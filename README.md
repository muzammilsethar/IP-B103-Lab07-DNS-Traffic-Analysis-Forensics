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
```text
~/CIP-B103-Lab7/
├── evidence/
│   ├── dig_dns.pcap
│   ├── fresh_dig_dns.pcapng
│   └── browser_dns.pcapng
├── working/
│   └── dig_dns_working.pcap
├── reports/
│   ├── resolv_conf.txt
│   ├── dns_capture_hashes.txt
│   ├── dns_queries.tsv
│   ├── dns_responses.tsv
│   ├── browser_dns_inventory.txt
│   ├── dns_A_answers.tsv
│   └── smtp_dns_correlation.tsv
└── screenshots/
🛠️ Step-by-Step Execution, Commands & Visual Proofs1. Workspace Setup & Environment VerificationObjective: Prepare workspace directories, install required network utilities (bind9-dnsutils, tshark), and inspect the local resolver configurations.Bashmkdir -p ~/CIP-B103-Lab7/{evidence,working,exported,reports,screenshots,scripts}
cd ~/CIP-B103-Lab7
sudo apt update && sudo apt install -y dnsutils tshark wireshark
cat /etc/resolv.conf | tee reports/resolv_conf.txt
resolvectl status 2>/dev/null | tee reports/resolvectl_status.txt || true
Figure 1.1: Directory initialization, package verification, and local resolver identification.2. Evidence Acquisition & Cryptographic HashingObjective: Download baseline PCAP files, establish a forensically isolated working copy with preserved timestamps, and generate SHA-256 integrity hashes.Bashwget -O evidence/dig_dns.pcap 'https://raw.githubusercontent.com/frankwxu/digital-forensics-lab/main/Networking_Forensics/lab_files/dns/dig_dns.pcap'
cp --preserve=timestamps evidence/dig_dns.pcap working/dig_dns_working.pcap
sha256sum evidence/dig_dns.pcap working/dig_dns_working.pcap | tee reports/dns_capture_hashes.txt
Figure 1.2: Cryptographic SHA-256 hashing confirming zero-byte alteration.3. Part A — Active DNS Record Querying with digObjective: Conduct controlled DNS queries for A, AAAA, MX, and NS records against example.com.Bashdig example.com A | tee reports/dig_example_A.txt
dig example.com AAAA | tee reports/dig_example_AAAA.txt
dig example.com MX | tee reports/dig_example_MX.txt
dig example.com NS | tee reports/dig_example_NS.txt
dig +short example.com A | tee reports/dig_example_short.txt
Query TypeTarget DomainLocal Resolver ServerStatus / RCODETransaction IDAnswer CountAexample.com127.0.0.53#53REFUSED (RCODE 5)11240AAAAexample.com127.0.0.53#53REFUSED (RCODE 5)224960MXexample.com127.0.0.53#53REFUSED (RCODE 5)494900NSexample.com127.0.0.53#53REFUSED (RCODE 5)608560Figure 1.3 & 1.4: Query execution showing systemd-resolved loopback listener.4. Part B — Live DNS Traffic CaptureObjective: Capture live DNS network resolution packets on interface eth0.BashIFACE=eth0
sudo chmod -R 777 evidence reports
sudo tshark -i "$IFACE" -f 'port 53' -a duration:25 -w evidence/fresh_dig_dns.pcapng &
sleep 3
dig +noedns example.com A >/dev/null
wait

sudo chmod 777 evidence/fresh_dig_dns.pcapng
sha256sum evidence/fresh_dig_dns.pcapng | tee reports/fresh_dns_sha256.txt
Figure 1.5: TShark execution output and generated evidence SHA-256 hash.5. Part C & D — Packet Extraction & Transaction ID CorrelationObjective: Parse fresh_dig_dns.pcapng for DNS fields using 16-bit Transaction ID (0xbdec).BashPCAP=evidence/fresh_dig_dns.pcapng

# Query Field Extraction
tshark -r "$PCAP" -Y 'dns.flags.response==0' -T fields \
  -e frame.number -e frame.time -e ip.src -e udp.srcport -e ip.dst -e udp.dstport \
  -e dns.id -e dns.qry.name -e dns.qry.type \
  | tee reports/dns_queries.tsv

# Response Field Extraction
tshark -r "$PCAP" -Y 'dns.flags.response==1' -T fields \
  -e frame.number -e frame.time -e ip.src -e udp.srcport -e ip.dst -e udp.dstport \
  -e dns.id -e dns.flags.rcode -e dns.count.answers -e dns.a -e dns.aaaa -e dns.resp.ttl \
  | tee reports/dns_responses.tsv
Figure 1.6: Packet extractions verifying response tuple correlation.6. Part E — Browser DNS Inventory AggregationObjective: Aggregate domain lookups by frequency.BashIFACE=eth0
sudo tshark -i "$IFACE" -f 'port 53' -a duration:40 -w evidence/browser_dns.pcapng &
sleep 3
curl -s https://example.com >/dev/null &
dig @8.8.8.8 google.com A >/dev/null &
dig @8.8.8.8 wikipedia.org A >/dev/null &
wait

sudo chmod 777 evidence/browser_dns.pcapng
tshark -r evidence/browser_dns.pcapng -Y 'dns.flags.response==0' -T fields -e dns.qry.name -e dns.qry.type \
  | sort | uniq -c | sort -nr | tee reports/browser_dns_inventory.txt
Figure 1.7: Extracted inventory showing lookup occurrences.7. Part F — Subsequent Transport Correlation AnalysisBash# Extract DNS A Answers
tshark -r evidence/browser_dns.pcapng -Y 'dns.a' -T fields -e frame.time_epoch -e dns.qry.name -e dns.a \
  | tee reports/dns_A_answers.tsv

# Extract Outbound TCP SYN Sessions
tshark -r evidence/browser_dns.pcapng -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e frame.time_epoch -e ip.dst -e tcp.dstport \
  | tee reports/subsequent_tcp_destinations.tsv
Figure 1.8: DNS resolution timestamp extraction.8. Part G — SMTP Historical DNS Evidence ExtractionBashif [ -f ../CIP-B103-Lab4/working/smtp_working.pcap ]; then
  tshark -r ../CIP-B103-Lab4/working/smtp_working.pcap -Y 'dns' -T fields \
    -e frame.number -e frame.time -e dns.qry.name -e dns.qry.type -e dns.a -e dns.resp.name -e dns.resp.ttl \
    | tee reports/smtp_dns_correlation.tsv
fi
Figure 1.9: Historical DNS trace for mail.patriots.in.📋 Forensic Summary Findings WorksheetParameter / MetricExtracted ArtifactAnalysis / Forensic NotesCapture File Namefresh_dig_dns.pcapngGenerated during live TShark capture on eth0SHA-256 Hash42546609ec6a8ce...Unbroken chain of custody verification hashTarget Query Domainexample.comLive DNS resolution test targetTransaction ID0xbdec16-bit header field correlating query and response framesClient Socket192.168.238.137:47140Source IP and ephemeral UDP client portResolver Socket192.168.238.2:53Standard recursive DNS resolver endpointResolved IPv4 Answer(s)172.66.147.243, 104.20.23.154Cloudflare CDN load-balancing A recordsResponse Code / Status0 (NOERROR)Successful domain lookup statusResponse TTL5 secondsTime-To-Live value returned in answer payloadBrowser Domain Inventoryexample.com, google.com, wikipedia.orgExtracted domain query list from 40s captureSMTP Forensic Artifactmail.patriots.in ➔ 74.53.140.153Historical mail server lookup extracted from Lab 4
