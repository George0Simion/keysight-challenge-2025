<p align="center">
  <a href="" rel="noopener">
 <img src="https://i.imgur.com/AZ2iWek.png" alt="Project logo"></a>
</p>
<h3 align="center">GPU ROUTER</h3>

<div align="center">
Proiect realizat de: Iacobai Cosmin si Simion George
</div>

---

## 💡 HOW to run

Pentru rularea proiectului trebuie modificata linia 137 cu calea absoluta a fisierului .pcap de pe statia dumneavoastra. Dupa aceea, pasii normali, mkdir build, cd build, cmake .., make, make run

Asigură ieșirea pachetelor procesate către rețea (pe interfața specificată, de exemplu "eth0", se afla la linia 400).

# Procesare și Trimitere Pachete cu SYCL/DPC++ și TBB

Acest proiect este o aplicație C++ care combină mai multe tehnologii pentru a procesa pachetele de rețea. Codul folosește:
- **SYCL/DPC++** pentru accelerarea pe GPU a anumitor operații (ex. clasificarea și modificarea pachetelor).
- **Intel TBB (Threading Building Blocks)** pentru paralelizarea fluxului de lucru (flow graph și operații paralele).
- **libpcap** pentru citirea pachetelor dintr-un fișier de tip `.pcap`.
- **Socket-uri Raw** pentru trimiterea pachetelor modificate pe o interfață de rețea.
- Biblioteci standard C++ și funcții pentru manipularea rețelei (ex. operații pe Ethernet, IP, etc.).

## Rezumatul Fluxului de Lucru

Aplicația utilizează un **flux grafic (flow graph)** TBB compus din mai multe noduri:
1. **Input Node** – Citirea unui burst de pachete din fișierul `.pcap`.
2. **Multifunction Node (inspect_packet_node)** – Clasificarea pachetelor folosind kernel-uri SYCL pentru a determina tipul de pachet (IPv4 versus ARP/IPv6).
3. **Count Stats Node** – Numără și afișează statistici privind pachetele IPv4 și ARP.
4. **Routing Node** – Modifică pachetele IPv4 folosind SYCL pentru a decrementa TTL-ul, recalcula checksum-ul și actualiza adresa de destinație.
5. **Send Node** – Trimiterea pachetelor modificate folosind un raw socket.

## Detalii despre Componentele Cheie

### Structuri de Date

- **`struct ether_hdr`**  
  Reprezintă antetul unui cadru Ethernet. Conține adresele MAC sursă și destinație și tipul de protocol.

- **`struct ip_hdr`**  
  Definește antetul unui pachet IPv4, incluzând câmpuri precum lungimea totală, TTL, protocolul, checksum-ul, adresele sursă și destinație.

- **`struct Packet`**  
  Înveliș pentru datele unui pachet, stocate ca vector de octeți (`std::vector<uint8_t>`).

- **`struct GPU_Packet`**  
  O versiune compatibilă cu dispozitivele de calcul (GPU), de lungime fixă (MAX_BYTES) pentru a facilita copierea pe dispozitiv.

### Funcții și Module

#### 1. Funcția `get_sock`
- **Ce face:**  
  Creează un socket raw pentru captura/trimiterea pachetelor.  
  - Deschide un socket cu protocolul `ETH_P_ALL` pentru a putea lucra cu toate tipurile de pachete Ethernet.  
  - Folosește `ioctl()` pentru a obține indexul interfeței de rețea (ex. "eth0").  
  - Leagă socket-ul de interfața specificată.
- **Utilizare:**  
  Este apelată în nodul de trimitere pentru a obține un socket prin care se vor trimite pachetele modificate.

#### 2. Funcția `checksum`
- **Ce face:**  
  Calculează checksum-ul pentru un bloc de date (folosit pentru validarea antetului IP).
- **Algoritm:**  
  - Adună cuvinte de 16 de biți din date.
  - Execută o operație de “folding” pentru a reduce suma la 16 biți.
  - Returnează complementul sumei.
- **Utilizare:**  
  Folosit în nodul de routing pentru a verifica și recalcala checksum-ul antetului IP după modificări.

#### 3. Funcția `dev_ntohs`
- **Ce face:**  
  O variantă “device-friendly” a funcției standard `ntohs()`, implementată inline pentru a asigura o operație de byte-swap eficientă în interiorul kernel-ului SYCL.

#### 4. Nodul **Input Node**
- **Ce face:**  
  Citește un "burst" de pachete dintr-un fișier `.pcap` folosind funcția `pcap_next_ex()`.
- **Detalii:**  
  - Stochează pachetele citite într-un `std::vector` de tip `Packet`.
  - Dacă nu mai sunt pachete de citit sau apare o eroare, oprește fluxul (folosind `flow_control.stop()`).
- **Utilizare:**  
  Este punctul de intrare în graful de procesare TBB.

#### 5. Nodul **Multifunction Node (inspect_packet_node)**
- **Ce face:**  
  Clasifică pachetele în funcție de tipul de protocol Ethernet:
  - Dacă este IPv4, setează clasificarea la `1`.
  - Dacă este ARP sau IPv6, setează clasificarea la `2`.
  - Altfel, clasificarea rămâne `0`.
- **Implementare:**  
  - Convertește fiecare `Packet` într-un `GPU_Packet` (copie parțială până la MAX_BYTES) pentru a putea fi transferate pe GPU.
  - Creează buffere SYCL pentru pachete și rezultate de clasificare.
  - Rulează un kernel SYCL care face acces rapid la câmpul `ethr_type` al antetului Ethernet.
  - După rularea kernel-ului, se construiesc două burst-uri: unul pentru IPv4 și unul pentru ARP/IPv6.
- **Utilizare:**  
  Extinde fluxul de lucru segregând pachetele pentru procesări ulterioare specifice fiecărui tip.

#### 6. Nodul **Count Stats Node**
- **Ce face:**  
  Numără pachetele IPv4 și ARP din burst-ul primit.
- **Implementare:**  
  - Folosește `tbb::parallel_reduce` pentru a parcurge vectorul de pachete și a contoriza aparițiile de tip ARP și IPv4.
  - Afișează numărul de pachete de fiecare tip.
- **Utilizare:**  
  Oferă feedback statistic despre pachetele procesate și redirecționează pachetele pentru etapa de routing.

#### 7. Nodul **Routing Node**
- **Ce face:**  
  Prelucrează pachetele IPv4 pentru a efectua modificări de routing:
  - Verifică checksum-ul antetului IP și, dacă este valid, procedează la modificări.
  - Verifică dacă TTL-ul este suficient de mare; dacă da, îl decrementează cu 1.
  - Actualizează adresa de destinație incrementând fiecare octet cu `+1`.
  - Recalculează checksum-ul antetului IP după modificări.
- **Implementare:**  
  - Convertește pachetele într-o structură GPU-compatible (`GPU_Packet`).
  - Rulează un kernel SYCL care realizează verificările și modificările.
  - După terminarea kernel-ului, copiază datele modificate înapoi în structurile originale de `Packet`.
- **Utilizare:**  
  Modifică pachetele IPv4 astfel încât să simuleze modificări de rutare, în vederea experimentării cu verificarea și recalcularea checksum-ului.

#### 8. Nodul **Send Node**
- **Ce face:**  
  Trimite pachetele modificate folosind un raw socket.
- **Implementare:**  
  - Creează un raw socket apelând funcția `get_sock("eth0")`.
  - Iterează prin burst-ul de pachete și folosește `write()` pentru a trimite datele.
  - În cazul erorilor, afișează un mesaj descriptiv.
  - Închide socket-ul după trimitere.
- **Utilizare:**  
  Asigură ieșirea pachetelor procesate către rețea (pe interfața specificată, de exemplu "eth0", se afla la linia 400).