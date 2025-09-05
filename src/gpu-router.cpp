#include <array>
#include <cerrno>  // For errno
#include <cstdio>  // For printf, perror
#include <cstring> // For std::memcpy, std::strncpy
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>

// SYCL/DPC++ headers
#include "dpc_common.hpp"
#include <sycl/sycl.hpp>

// TBB headers
#include <tbb/blocked_range.h>
#include <tbb/flow_graph.h>
#include <tbb/global_control.h>
#include <tbb/parallel_for.h>
#include <tbb/parallel_reduce.h>

// libpcap for packet capture
#include <pcap.h>

// Networking headers
#include <arpa/inet.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// Socket and device-level headers
#include <linux/if_packet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

// File control
#include <fcntl.h>
#include <unistd.h>

/* Ethernet frame header */
struct ether_hdr {
	uint8_t ethr_dhost[6]; // adresa MAC destinatie
	uint8_t ethr_shost[6]; // adresa MAC sursa
	uint16_t ethr_type;	   // identificator protocol encapsulat
};

/* IP Header */
struct ip_hdr {
	uint8_t ihl : 4, ver : 4;
	uint8_t tos;
	uint16_t tot_len;
	uint16_t id;
	uint16_t frag;
	uint8_t ttl;
	uint8_t proto;
	uint16_t checksum;
	uint32_t source_addr;
	uint32_t dest_addr;
};

const size_t burst_size = 32;
#define PACKET_SIZE 64

// Packet with vector data (not device copyable)
struct Packet {
	std::vector<uint8_t> data;
};

// A device-copyable struct for classification
static constexpr size_t MAX_BYTES = 128;
struct GPU_Packet {
	uint16_t length;
	std::array<uint8_t, MAX_BYTES> data;
};

// A simple device-friendly equivalent of ntohs():
static inline uint16_t dev_ntohs(uint16_t x) {
	// Byte-swap 16 bits
	return static_cast<uint16_t>(((x & 0xff00) >> 8) | ((x & 0x00ff) << 8));
}

using PacketBurst = std::vector<Packet>;

int get_sock(const char *if_name) {
	int s = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (s == -1) {
		perror("socket");
		return -1;
	}

	struct ifreq intf;
	std::memset(&intf, 0, sizeof(intf));
	std::strncpy(intf.ifr_name, if_name, IFNAMSIZ);
	if (ioctl(s, SIOCGIFINDEX, &intf) < 0) {
		perror("ioctl(SIOCGIFINDEX)");
		close(s);
		return -1;
	}

	struct sockaddr_ll addr{};
	addr.sll_family = AF_PACKET;
	addr.sll_protocol = htons(ETH_P_ALL);
	addr.sll_ifindex = intf.ifr_ifindex;

	if (bind(s, reinterpret_cast<struct sockaddr *>(&addr), sizeof(addr)) < 0) {
		perror("bind");
		close(s);
		return -1;
	}

	return s;
}

int main() {
	// Create a SYCL queue
	sycl::queue q;
	std::cout << "Using device: " << q.get_device().get_info<sycl::info::device::name>() << std::endl;

	// Limit TBB concurrency
	int nth = 10;
	auto mp = tbb::global_control::max_allowed_parallelism;
	tbb::global_control gc(mp, nth);

	tbb::flow::graph g;

	static bool reading_done = false;
	static pcap_t *pcap_handle = nullptr;

	// Prepare for .pcap reading
	{
		char errbuf[PCAP_ERRBUF_SIZE] = {0};
		pcap_handle = pcap_open_offline("/keyseight/src/capture1.pcap", errbuf);
		if (!pcap_handle) {
			std::cerr << "Error opening pcap: " << errbuf << "\n";
			reading_done = true;
		}
	}

	// --------------------------
	// 1) Input node: reads bursts from .pcap
	// --------------------------
	tbb::flow::input_node<PacketBurst> in_node{g, [&](tbb::flow_control &fc) -> PacketBurst {
												   std::cout << "[In Node] Running\n";

												   if (reading_done || !pcap_handle) {
													   fc.stop();
													   return {};
												   }

												   PacketBurst burst;
												   burst.reserve(burst_size);

												   for (size_t i = 0; i < burst_size; ++i) {
													   pcap_pkthdr *header;
													   const u_char *data = nullptr;
													   int ret = pcap_next_ex(pcap_handle, &header, &data);
													   if (ret <= 0) {
														   reading_done = true;
														   break;
													   }
													   Packet pkt;
													   pkt.data.resize(header->len);
													   std::memcpy(pkt.data.data(), data, header->len);
													   burst.push_back(pkt);
												   }

												   if (burst.empty()) {
													   reading_done = true;
													   fc.stop();
													   return {};
												   }

												   std::cout << "[In Node] Read " << burst.size() << " packets\n";
												   return burst;
											   }};

	// --------------------------
	// 2) Multifunction node: classify packets (IPv4 vs. ARP/IPv6) on GPU
	// --------------------------
	tbb::flow::multifunction_node<PacketBurst, std::tuple<PacketBurst, PacketBurst>> inspect_packet_node(
		g, tbb::flow::unlimited,
		[&](const PacketBurst &input_burst, auto &op) // output ports
		{
			std::cout << "[Inspect Packet Node] running \n";

			// Convert input_burst -> device-copyable array
			std::vector<GPU_Packet> gpuPackets(input_burst.size());
			for (size_t i = 0; i < input_burst.size(); ++i) {
				size_t copyLen = std::min<size_t>(MAX_BYTES, input_burst[i].data.size());
				gpuPackets[i].length = static_cast<uint16_t>(copyLen);
				std::memcpy(gpuPackets[i].data.data(), input_burst[i].data.data(), copyLen);
			}

			// 2) Prepare classification
			std::vector<int> classification(input_burst.size(), 0);

			// 3) Create buffers for GPU classification
			sycl::buffer<GPU_Packet> bufPackets(gpuPackets.data(), sycl::range<1>(gpuPackets.size()));
			sycl::buffer<int> bufClass(classification.data(), sycl::range<1>(classification.size()));

			// Submit kernel
			q.submit([&](sycl::handler &h) {
				 auto accPkts = bufPackets.get_access<sycl::access::mode::read>(h);
				 auto accClass = bufClass.get_access<sycl::access::mode::write>(h);

				 h.parallel_for(sycl::range<1>(gpuPackets.size()), [=](sycl::id<1> idx) {
					 size_t i = idx[0];
					 const auto &g = accPkts[i];
					 // If not enough bytes for an eth header
					 if (g.length < sizeof(struct ether_hdr)) {
						 accClass[i] = 0;
						 return;
					 }
					 const auto *eth_hdr = reinterpret_cast<const ether_hdr *>(g.data.data());
					 // Use device-friendly swap
					 uint16_t eth_type = dev_ntohs(eth_hdr->ethr_type);

					 // Classify
					 if (eth_type == ETHERTYPE_IP) {
						 accClass[i] = 1;
					 } else if (eth_type == ETHERTYPE_ARP || eth_type == ETHERTYPE_IPV6) {
						 accClass[i] = 2;
					 } else {
						 accClass[i] = 0;
					 }
				 });
			 }).wait();

			auto accClassHost = bufClass.get_access<sycl::access::mode::read>();

			// Build two bursts on the host
			PacketBurst ipv4_burst;
			PacketBurst arp_burst;
			ipv4_burst.reserve(input_burst.size());
			arp_burst.reserve(input_burst.size());

			for (size_t i = 0; i < input_burst.size(); ++i) {
				if (classification[i] == 1) {
					ipv4_burst.push_back(input_burst[i]);
				} else if (classification[i] == 2) {
					arp_burst.push_back(input_burst[i]);
				}
			}

			// 6) Output them
			if (!ipv4_burst.empty()) {
				std::get<0>(op).try_put(std::move(ipv4_burst));
			}
			if (!arp_burst.empty()) {
				std::get<1>(op).try_put(std::move(arp_burst));
			}
		});

	// --------------------------
	// 3) Count Stats node: prints ARP & IPv4 counts, forwards the PacketBurst
	// --------------------------
	tbb::flow::function_node<PacketBurst, PacketBurst> count_stats{
		g, tbb::flow::unlimited, [&](PacketBurst burst) -> PacketBurst {
			std::cout << "[Count Stats] node running\n";

			struct EtherCounts {
				int arp_count = 0;
				int ipv4_count = 0;
			};

			EtherCounts result = tbb::parallel_reduce(
				tbb::blocked_range<size_t>(0, burst.size()), EtherCounts{},
				// parallel_reduce subrange:
				[&](const tbb::blocked_range<size_t> &r, EtherCounts local) {
					for (size_t i = r.begin(); i < r.end(); i++) {
						const Packet &pkt = burst[i];
						if (pkt.data.size() < sizeof(struct ether_hdr))
							continue;
						auto eth_hdr = reinterpret_cast<const struct ether_hdr *>(pkt.data.data());
						// Use dev_ntohs here as well
						uint16_t eth_type = dev_ntohs(eth_hdr->ethr_type);
						if (eth_type == ETHERTYPE_IP) {
							local.ipv4_count++;
						} else if (eth_type == ETHERTYPE_ARP) {
							local.arp_count++;
						}
					}
					return local;
				},
				// join operation
				[](const EtherCounts &a, const EtherCounts &b) {
					EtherCounts sum;
					sum.arp_count = a.arp_count + b.arp_count;
					sum.ipv4_count = a.ipv4_count + b.ipv4_count;
					return sum;
				});

			std::cout << "[Count Stats] ARP packets:   " << result.arp_count << "\n";
			std::cout << "[Count Stats] IPv4 packets: " << result.ipv4_count << "\n";

			// Forward the burst
			return burst;
		}};

	tbb::flow::function_node<PacketBurst, PacketBurst> routing_node{
		g, tbb::flow::unlimited, [&](PacketBurst input_burst) -> PacketBurst {
			std::cout << "[Routing Node] running\n";

			// Convert input_burst into a device–copyable array of GPU_Packet objects.
			std::vector<GPU_Packet> gpuPackets(input_burst.size());
			for (size_t i = 0; i < input_burst.size(); ++i) {
				size_t copyLen = std::min<size_t>(MAX_BYTES, input_burst[i].data.size());
				gpuPackets[i].length = static_cast<uint16_t>(copyLen);
				std::memcpy(gpuPackets[i].data.data(), input_burst[i].data.data(), copyLen);
			}

			// Create a SYCL buffer over the GPU_Packet array.
			sycl::buffer<GPU_Packet> bufPackets(gpuPackets.data(), sycl::range<1>(gpuPackets.size()));

			// Submit a SYCL kernel that modifies the IP header: verify checksum, decrement TTL,
			//    recalc the checksum, and update the destination address (+1 on each byte).
			q.submit([&](sycl::handler &h) {
				 // Get read/write access for the GPU packets.
				 auto accPackets = bufPackets.get_access<sycl::access::mode::read_write>(h);

				 // A lambda to compute the IP header checksum.
				 auto compute_checksum = [=](const ip_hdr *ip_ptr) -> uint16_t {
					 // The IP header length (in 32-bit words) is given by ip->ihl.
					 int wordCount = ip_ptr->ihl * 2; // each 32-bit word is 2 x 16-bit.
					 uint32_t sum = 0;
					 const uint16_t *data = reinterpret_cast<const uint16_t *>(ip_ptr);
					 for (int k = 0; k < wordCount; ++k) {
						 sum += data[k];
					 }
					 // Fold 32-bit sum to 16 bits.
					 while (sum >> 16)
						 sum = (sum & 0xFFFF) + (sum >> 16);
					 return static_cast<uint16_t>(~sum);
				 };

				 h.parallel_for(sycl::range<1>(gpuPackets.size()), [=](sycl::id<1> idx) {
					 size_t i = idx[0];
					 GPU_Packet &pkt = accPackets[i];

					 // Ensure the packet contains enough data for both headers.
					 if (pkt.length < (sizeof(ether_hdr) + sizeof(ip_hdr))) {
						 return;
					 }

					 // Extract the IP header, assuming it immediately follows the Ethernet header.
					 ip_hdr *ip = reinterpret_cast<ip_hdr *>(pkt.data.data() + sizeof(ether_hdr));

					 // Verify the original IP checksum.
					 uint16_t original_checksum = ip->checksum;
					 ip->checksum = 0;
					 uint16_t computed = compute_checksum(ip);
					 if (computed != original_checksum) {
						 // If checksum verification fails, skip processing this packet.
						 return;
					 }

					 // Verify the TTL is high enough.
					 if (ip->ttl < 2) {
						 return;
					 }

					 // Decrement the TTL.
					 ip->ttl -= 1;

					 // Update the destination address: add +1 to each of the four bytes.
					 uint8_t *dst_bytes = reinterpret_cast<uint8_t *>(&ip->dest_addr);
					 for (int j = 0; j < 4; ++j) {
						 dst_bytes[j] += 1;
					 }

					 // Recalculate the checksum after modifying the destination address.
					 ip->checksum = 0;
					 ip->checksum = compute_checksum(ip);
				 });
			 }).wait();

			// 4) Copy the modified GPU_Packet data back to the original packets.
			for (size_t i = 0; i < input_burst.size(); ++i) {
				size_t copyLen =
					std::min<size_t>(input_burst[i].data.size(), static_cast<size_t>(gpuPackets[i].length));
				std::memcpy(input_burst[i].data.data(), gpuPackets[i].data.data(), copyLen);
			}

			return input_burst;
		}};

	// --------------------------
	// 5) Send node: sends the packets via raw socket,
	//    returns a continue_msg (no data output).
	// --------------------------
	tbb::flow::function_node<PacketBurst, tbb::flow::continue_msg> send_node{
		g, 1, [&](PacketBurst burst) -> tbb::flow::continue_msg {
			std::cout << "[Send Node] Running\n";

			int sockfd = get_sock("eth0");

			// Send each packet
			for (size_t i = 0; i < burst.size(); i++) {
				const Packet &pkt = burst[i];

				// Now we can use send(), since the kernel knows the destination
				ssize_t bytes_sent = write(sockfd, pkt.data.data(), pkt.data.size());
				if (bytes_sent < 0) {
					int err = errno;
					std::cerr << "Error sending packet. errno=" << err << " (" << std::strerror(err) << ")\n";
				}
			}

			close(sockfd);
			return {};
		}};

	// --------------------------
	// 6) Build the graph edges
	// --------------------------
	tbb::flow::broadcast_node<PacketBurst> broadcast_ipv4(g);

	tbb::flow::make_edge(in_node, inspect_packet_node);

	// We only run count_stats + routing + send on the IPv4 path
	tbb::flow::make_edge(tbb::flow::output_port<0>(inspect_packet_node), broadcast_ipv4);
	tbb::flow::make_edge(tbb::flow::output_port<1>(inspect_packet_node), count_stats);

	tbb::flow::make_edge(broadcast_ipv4, routing_node);
	tbb::flow::make_edge(broadcast_ipv4, count_stats);

	tbb::flow::make_edge(routing_node, send_node);

	// Activate input node
	in_node.activate();
	g.wait_for_all();

	std::cout << "Done waiting\n";
	return 0;
}
