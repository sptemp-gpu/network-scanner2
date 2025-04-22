# sniffer.py
import argparse
from scapy.all import sniff, IP, TCP, UDP, ICMP
from datetime import datetime

LOG_FILE = "logs/packet_log.txt"
port_scan_tracker = {}

def log_packet(info, save_to_file):
    print(info)
    if save_to_file:
        with open(LOG_FILE, "a") as log:
            log.write(info + "\n")

def detect_port_scan(packet):
    src_ip = packet[IP].src
    dst_port = packet[TCP].dport

    if src_ip not in port_scan_tracker:
        port_scan_tracker[src_ip] = set()
    port_scan_tracker[src_ip].add(dst_port)

    if len(port_scan_tracker[src_ip]) > 10:  # 10+ ports = suspicious
        alert = f"⚠️ [ALERT] Possible Port Scan from {src_ip}"
        log_packet(alert, True)

def packet_callback(packet, live, save, filter_proto):
    if IP in packet:
        proto = "UNKNOWN"
        if packet.haslayer(TCP): proto = "TCP"
        elif packet.haslayer(UDP): proto = "UDP"
        elif packet.haslayer(ICMP): proto = "ICMP"
        
        if filter_proto and proto != filter_proto.upper():
            return  # Skip if protocol doesn't match filter

        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        log_entry = f"[{timestamp}] {proto} Packet: {src_ip} -> {dst_ip}"

        log_packet(log_entry, save)

        if proto == "TCP":
            detect_port_scan(packet)

def start_sniffer(live, save, filter_proto):
    print("🔍 Sniffing started... Press CTRL+C to stop.\n")
    sniff(
        prn=lambda pkt: packet_callback(pkt, live, save, filter_proto),
        store=0
    )

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="🔐 Network Packet Sniffer & Analyzer")
    parser.add_argument("--live", action="store_true", help="Display packets live")
    parser.add_argument("--save", action="store_true", help="Save packets to log file")
    parser.add_argument("--filter", type=str, help="Filter protocol (tcp, udp, icmp)")

    args = parser.parse_args()
    start_sniffer(args.live, args.save, args.filter)
