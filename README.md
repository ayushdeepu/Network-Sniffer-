# Basic Network Sniffer

A simple Python-based network sniffer built for learning how data flows through a network and how protocols (IP, TCP, UDP, ICMP) are structured.

## 📌 Features
- Captures live network packets in real time
- Identifies protocol type (TCP / UDP / ICMP)
- Displays source & destination IP addresses
- Displays source & destination ports (for TCP/UDP)
- Shows packet size and a safe preview of the payload
- Clean, readable console output for each captured packet

## 🛠️ Technology Used
- Python 3
- [Scapy](https://scapy.net/) — for packet capturing and parsing

## 📂 Project Structure
```
network_sniffer.py   # Main sniffer script
README.md            # Project documentation
```

## ⚙️ Installation
```bash
pip install scapy
```

## ▶️ Usage
Packet sniffing requires raw socket access, so run with elevated privileges:

**Linux / macOS**
```bash
sudo python3 network_sniffer.py
```

**Windows** (run your terminal/IDE as Administrator)
```bash
python network_sniffer.py
```

Press `Ctrl + C` to stop the capture. A summary of the total packets captured will be shown.

## 🖥️ Sample Output
```
[Packet #1] Captured at 14:32:10
------------------------------------------------------------
  Source IP      : 192.168.1.10
  Destination IP : 142.250.182.106
  Protocol       : TCP
  Source Port    : 51322
  Destination Port: 443
  Packet Size    : 74 bytes
  Payload Preview: (no payload)
------------------------------------------------------------
```

## 📚 What I Learned
- How packets are structured at different network layers (Ethernet, IP, Transport)
- The difference between TCP, UDP, and ICMP traffic
- How to use Scapy to capture and parse live traffic
- The basics of how data flows across a network from source to destination

## ⚠️ Disclaimer
This project is for **educational purposes only**. Only run this sniffer on networks you own or have explicit permission to monitor. Unauthorized packet capturing on networks you don't control may be illegal.
