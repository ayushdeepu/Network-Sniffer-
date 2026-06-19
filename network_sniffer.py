"""
Basic Network Sniffer
----------------------
A simple educational tool to capture and analyze live network traffic.

Goals covered:
  - Capture network traffic packets
  - Analyze packet structure (Ethernet / IP / TCP / UDP / ICMP layers)
  - Display source/destination IPs, ports, protocol, and payload
  - Learn how data flows through the network and basic protocol structure

Library used: scapy (https://scapy.net/)

IMPORTANT:
  - Run with administrator/root privileges (packet sniffing needs raw socket access).
      Linux/Mac : sudo python3 network_sniffer.py
      Windows   : run terminal/IDE "as Administrator"
  - Install scapy first:
      pip install scapy
  - This script is for educational/learning purposes only.
    Only capture traffic on networks you own or have explicit permission to monitor.
"""

from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw

# Keep a simple counter so the output is easy to read
packet_count = 0


def get_protocol_name(packet):
    """Return a human-readable protocol name for the packet."""
    if packet.haslayer(TCP):
        return "TCP"
    elif packet.haslayer(UDP):
        return "UDP"
    elif packet.haslayer(ICMP):
        return "ICMP"
    else:
        return "OTHER"


def get_ports(packet):
    """Return (src_port, dst_port) if available, else (None, None)."""
    if packet.haslayer(TCP):
        return packet[TCP].sport, packet[TCP].dport
    elif packet.haslayer(UDP):
        return packet[UDP].sport, packet[UDP].dport
    return None, None


def get_payload(packet, max_len=60):
    """
    Return a short, safe preview of the payload.
    Tries to decode as text; falls back to raw bytes/hex if it isn't printable.
    """
    if packet.haslayer(Raw):
        raw_bytes = bytes(packet[Raw].load)
        try:
            text = raw_bytes.decode("utf-8", errors="replace")
            text = text.replace("\n", " ").replace("\r", " ")
            return text[:max_len] + ("..." if len(text) > max_len else "")
        except Exception:
            return raw_bytes[:max_len].hex()
    return "(no payload)"


def process_packet(packet):
    """
    Callback function executed for every packet that scapy captures.
    Extracts and prints the key fields: timestamp, IPs, protocol, ports, payload.
    """
    global packet_count

    if packet.haslayer(IP):
        packet_count += 1

        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = get_protocol_name(packet)
        src_port, dst_port = get_ports(packet)
        payload_preview = get_payload(packet)
        timestamp = datetime.now().strftime("%H:%M:%S")
        size = len(packet)

        print(f"\n[Packet #{packet_count}] Captured at {timestamp}")
        print("-" * 60)
        print(f"  Source IP      : {src_ip}")
        print(f"  Destination IP : {dst_ip}")
        print(f"  Protocol       : {protocol}")
        if src_port and dst_port:
            print(f"  Source Port    : {src_port}")
            print(f"  Destination Port: {dst_port}")
        print(f"  Packet Size    : {size} bytes")
        print(f"  Payload Preview: {payload_preview}")
        print("-" * 60)


def main():
    print("=" * 60)
    print(" Basic Network Sniffer - Educational Tool")
    print(" Press Ctrl+C to stop capturing")
    print("=" * 60)

    try:
        # count=0 -> capture indefinitely until interrupted
        # store=False -> don't keep packets in memory (efficient for long runs)
        sniff(prn=process_packet, store=False, count=0)
    except KeyboardInterrupt:
        print(f"\n\nCapture stopped by user. Total packets captured: {packet_count}")
    except PermissionError:
        print("\n[ERROR] Permission denied. Try running this script as root/administrator.")
    except Exception as e:
        print(f"\n[ERROR] {e}")


if __name__ == "__main__":
    main()
