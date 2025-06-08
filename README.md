# SuspiciousPacketDetector For-EDU
# NetDetect

A simple network traffic analyzer that detects suspicious activities such as ICMP Flood, ARP Spoofing, DNS Spoofing, and DHCP Spoofing from `.pcap` files. The tool visualizes packet data and logs detection results automatically.

## 🔍 Features

- Detects common network attacks:
  - ARP Spoofing
  - DNS Spoofing
  - DHCP Spoofing
  - ICMP Flood
- Generates simple detection graphs
- Saves detection logs and results
- Includes a test `.pcap` file generator

## 🗂️ Project Structure
📁 Network_Suspicious_edit2/
├── Network_Suspicious.py # Main detection script
├── sample_gen.py # PCAP sample generator
├── requirements.txt # Required Python libraries
├── How to use.txt # Local usage instructions (Thai)
├── sample/
│ └── attack_test.pcap # Sample test PCAP file
└── result/
├── detection_result.txt # Text log output
└── icmp_flood_chart.png # Visualization graph

## ⚙️ Installation

> Requires **Python 3.12**. It’s recommended to use a virtual environment.

```bash
pip install -r requirements.txt
