# 🌐 IP-B103 Lab 07: DNS Introduction and Traffic Analysis

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue?style=for-the-badge&logo=linkedin)](https://www.linkedin.com/in/muzammil-sethar/)
[![Email](https://img.shields.io/badge/Email-Contact_Me-red?style=for-the-badge&logo=gmail)](mailto:muzammilsethar@gmail.com)
[![Status](https://img.shields.io/badge/Status-Open_for_DFIR_&_SOC_Roles-success?style=for-the-badge)]()

**Author:** Mohammad Muzamil  
**Registration No:** C11/26/DFIT/17289  
**Role:** Digital Forensics Internship Trainee (DFIT) | ICDFA  
**Platform:** Kali Linux (Rolling Release) | tshark | Wireshark  

---

## 📌 Executive Summary
This lab establishes a forensic network baseline by examining Domain Name System (DNS) traffic resolution behavior at the packet level. The investigation encompasses local resolver configuration audits, resource record queries (`A`, `AAAA`, `MX`, `NS`) using `dig`, live packet capture via `tshark`, 16-bit Transaction ID matching (`0xbdec`), multi-domain browser query inventory aggregation, and historical mail protocol (`mail.patriots.in`) DNS correlation. Cryptographic SHA-256 hashes were calculated to ensure chain of custody.

---

## 📂 Laboratory File & Directory Structure

* `~/CIP-B103-Lab7/evidence/`
  * `dig_dns.pcap`
  * `fresh_dig_dns.pcapng`
  * `browser_dns.pcapng`
* `~/CIP-B103-Lab7/working/`
  * `dig_dns_working.pcap`
* `~/CIP-B103-Lab7/reports/`
  * `resolv_conf.txt`
  * `dns_capture_hashes.txt`
  * `dns_queries.tsv`
  * `dns_responses.tsv`
  * `browser_dns_inventory.txt`
  * `dns_A_answers.tsv`
  * `smtp_dns_correlation.tsv`

---

## 🛠️ Step-by-Step Execution, Commands & Visual Proofs

### 1. Workspace Setup & Environment Verification
**Objective:** Prepare workspace directories, install required network utilities (`bind9-dnsutils`, `tshark`), and inspect the local resolver configurations.

* **Commands Executed:**
  `mkdir -p ~/CIP-B103-Lab7/{evidence,working,exported,reports,screenshots,scripts}`
  `cd ~/CIP-B103-Lab7`
  `sudo apt update && sudo apt install -y dnsutils tshark wireshark`
  `cat /etc/resolv.conf | tee reports/resolv_conf.txt`
  `resolvectl status 2>/dev/null | tee reports/resolvectl_status.txt || true`

![Environment Setup](B103%20lab7.1.png)  
*Figure 1.1: Directory initialization, package verification, and local resolver identification.*

---

### 2. Evidence Acquisition & Cryptographic Hashing
**Objective:** Download baseline PCAP files, establish a forensically isolated working copy with preserved timestamps, and generate SHA-256 integrity hashes.

* **Commands Executed:**
  `wget -O evidence/dig_dns.pcap 'https://raw.githubusercontent.com/frankwxu/digital-forensics-lab/main/Networking_Forensics/lab_files/dns/dig_dns.pcap'`
  `cp --preserve=timestamps evidence/dig_dns.pcap working/dig_dns_working.pcap`
  `sha256sum evidence/dig_dns.pcap working/dig_dns_working.pcap | tee reports/dns_capture_hashes.txt`

![Evidence Integrity Verification](B103%20lab7.2.png)  
*Figure 1.2: Cryptographic SHA-256 hashing confirming zero-byte alteration.*

---

### 3. Part A — Active DNS Record Querying with `dig`
**Objective:** Conduct controlled DNS queries for `A`, `AAAA`, `MX`, and `NS` records against `example.com`.

* **Commands Executed:**
  `dig example.com A | tee reports/dig_example_A.txt`
  `dig example.com AAAA | tee reports/dig_example_AAAA.txt`
  `dig example.com MX | tee reports/dig_example_MX.txt`
  `dig example.com NS | tee reports/dig_example_NS.txt`
  `dig +short example.com A | tee reports/dig_example_short.txt`

| Query Type | Target Domain | Local Resolver Server | Status / RCODE | Transaction ID | Answer Count |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **A** | `example.com` | `127.0.0.53#53` | `REFUSED` (RCODE 5) | `1124` | 0 |
| **AAAA** | `example.com` | `127.0.0.53#53` | `REFUSED` (RCODE 5) | `22496` | 0 |
| **MX** | `example.com` | `127.0.0.53#53` | `REFUSED` (RCODE 5) | `49490` | 0 |
| **NS** | `example.com` | `127.0.0.53#53` | `REFUSED` (RCODE 5) | `60856` | 0 |

![Dig Terminal Outputs](B103%20lab7.3.png)  
![Dig Terminal Continuation](B103%20lab7.4.png)  
*Figure 1.3 & 1.4: Query execution showing systemd-resolved loopback listener.*

---

### 4. Part B — Live DNS Traffic Capture
**Objective:** Capture live DNS network resolution packets on interface `eth0`.

* **Commands Executed:**
  `IFACE=eth0`
  `sudo chmod -R 777 evidence reports`
  `sudo tshark -i "$IFACE" -f 'port 53' -a duration:25 -w evidence/fresh_dig_dns.pcapng &`
  `sleep 3`
  `dig +noedns example.com A >/dev/null`
  `wait`
  `sudo chmod 777 evidence/fresh_dig_dns.pcapng`
  `sha256sum evidence/fresh_dig_dns.pcapng | tee reports/fresh_dns_sha256.txt`

![Live Capture Execution](B103%20lab7.5.png)  
*Figure 1.5: TShark execution output and generated evidence SHA-256 hash.*

---

### 5. Part C & D — Packet Extraction & Transaction ID Correlation
**Objective:** Parse `fresh_dig_dns.pcapng` for DNS fields using 16-bit Transaction ID (`0xbdec`).

* **Commands Executed:**
  `PCAP=evidence/fresh_dig_dns.pcapng`
  `tshark -r "$PCAP" -Y 'dns.flags.response==0' -T fields -e frame.number -e frame.time -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e dns.id -e dns.qry.name -e dns.qry.type | tee reports/dns_queries.tsv`
  `tshark -r "$PCAP" -Y 'dns.flags.response==1' -T fields -e frame.number -e frame.time -e ip.src -e udp.srcport -e ip.dst -e udp.dstport -e dns.id -e dns.flags.rcode -e dns.count.answers -e dns.a -e dns.aaaa -e dns.resp.ttl | tee reports/dns_responses.tsv`

![Packet Extraction Output](B103%20lab7.6.png)  
*Figure 1.6: Packet extractions verifying response tuple correlation.*

---

### 6. Part E — Browser DNS Inventory Aggregation
**Objective:** Aggregate domain lookups by frequency.

* **Commands Executed:**
  `IFACE=eth0`
  `sudo tshark -i "$IFACE" -f 'port 53' -a duration:40 -w evidence/browser_dns.pcapng &`
  `sleep 3`
  `curl -s https://example.com >/dev/null &`
  `dig @8.8.8.8 google.com A >/dev/null &`
  `dig @8.8.8.8 wikipedia.org A >/dev/null &`
  `wait`
  `sudo chmod 777 evidence/browser_dns.pcapng`
  `tshark -r evidence/browser_dns.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name -e dns.qry.type | sort | uniq -c | sort -nr | tee reports/browser_dns_inventory.txt`

![Browser DNS Inventory Output](B103%20lab7.7.png)  
*Figure 1.7: Extracted inventory showing lookup occurrences.*

---

### 7. Part F — Subsequent Transport Correlation Analysis
**Objective:** Extract A records and TCP SYN sessions.

* **Commands Executed:**
  `tshark -r evidence/browser_dns.pcapng -Y 'dns.a' -T fields -e frame.time_epoch -e dns.qry.name -e dns.a | tee reports/dns_A_answers.tsv`
  `tshark -r evidence/browser_dns.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e frame.time_epoch -e ip.dst -e tcp.dstport | tee reports/subsequent_tcp_destinations.tsv`

![Transport Correlation Output](B103%20lab7.8.png)  
*Figure 1.8: DNS resolution timestamp extraction.*

---

### 8. Part G — SMTP Historical DNS Evidence Extraction
**Objective:** Extract legacy mail server resolution.

* **Commands Executed:**
  `if [ -f ../CIP-B103-Lab4/working/smtp_working.pcap ]; then tshark -r ../CIP-B103-Lab4/working/smtp_working.pcap -Y 'dns' -T fields -e frame.number -e frame.time -e dns.qry.name -e dns.qry.type -e dns.a -e dns.resp.name -e dns.resp.ttl | tee reports/smtp_dns_correlation.tsv; fi`

![SMTP DNS Extraction](B103%20lab7.9.png)  
*Figure 1.9: Historical DNS trace for mail.patriots.in.*

---

## 📋 Forensic Summary Findings Worksheet

| Parameter / Metric | Extracted Artifact | Analysis / Forensic Notes |
| :--- | :--- | :--- |
| **Capture File Name** | `fresh_dig_dns.pcapng` | Generated during live TShark capture on `eth0` |
| **SHA-256 Hash** | `42546609ec6a8ce...` | Unbroken chain of custody verification hash |
| **Target Query Domain** | `example.com` | Live DNS resolution test target |
| **Transaction ID** | `0xbdec` | 16-bit header field correlating query and response frames |
| **Client Socket** | `192.168.238.137:47140` | Source IP and ephemeral UDP client port |
| **Resolver Socket** | `192.168.238.2:53` | Standard recursive DNS resolver endpoint |
| **Resolved IPv4 Answer(s)** | `172.66.147.243`, `104.20.23.154` | Cloudflare CDN load-balancing A records |
| **Response Code / Status** | `0 (NOERROR)` | Successful domain lookup status |
| **Response TTL** | `5 seconds` | Time-To-Live value returned in answer payload |
| **Browser Domain Inventory** | `example.com`, `google.com`, `wikipedia.org` | Extracted domain query list from 40s capture |
| **SMTP Forensic Artifact** | `mail.patriots.in` ➔ `74.53.140.153` | Historical mail server lookup extracted from Lab 4 |

---

## 💡 Key Takeaways
1. **Command-Line Analysis Power:** Utilizing tools like `tshark` enables rapid extraction of network artifacts without relying on memory-intensive graphical utilities.
2. **Transaction Pair Correlation:** Matching request and response streams via 16-bit Transaction IDs (`0xbdec`) and host-resolver socket tuples is crucial for detecting DNS spoofing or cache poisoning.
3. **Capture Filter Awareness:** Using restrictive filters (e.g., `port 53`) successfully isolates targeted protocols but hides subsequent application-layer sessions.
