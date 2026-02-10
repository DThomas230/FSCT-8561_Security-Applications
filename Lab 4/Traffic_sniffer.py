from scapy.all import sniff, IP, TCP, UDP, DNS, Raw
from collections import Counter

captured_packets = []
protocol_counter = Counter()
traffic_log = []

# Keywords to flag in payloads (Part 3)
SENSITIVE_KEYWORDS = [
    b"password", b"passwd", b"login", b"user",
    b"cookie", b"session", b"token", b"auth",
    b"credit", b"ssn", b"secret"
]

def packet_callback(pkt):
    """Process each captured packet."""
    captured_packets.append(pkt)

    if not pkt.haslayer(IP):
        return

    ip = pkt[IP]
    src_ip = ip.src
    dst_ip = ip.dst
    proto = ip.proto  # 6=TCP, 17=UDP

    src_port = dst_port = "-"
    flags = "-"
    proto_name = "Other"

    # Identify protocol and extract ports
    if pkt.haslayer(TCP):
        proto_name = "TCP"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = str(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        proto_name = "UDP"
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    elif proto == 1:
        proto_name = "ICMP"

    protocol_counter[proto_name] += 1

    # Log entry (Part 4)
    entry = {
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": proto_name,
        "flags": flags,
        "length": len(pkt),
    }
    traffic_log.append(entry)

    # Print packet summary (Part 1 & 2)
    print(f"[{proto_name}] {src_ip}:{src_port} -> {dst_ip}:{dst_port}  "
          f"Flags={flags}  Len={len(pkt)}")

    # ── Part 3 – Sensitive Data Detection ──
    if pkt.haslayer(Raw):
        payload = pkt[Raw].load
        for keyword in SENSITIVE_KEYWORDS:
            if keyword in payload.lower():
                print(f"  *** SENSITIVE DATA DETECTED: '{keyword.decode()}' "
                      f"found in packet payload ***")
                break

        # Check for HTTP metadata exposure
        if payload.startswith(b"GET") or payload.startswith(b"POST") or \
           payload.startswith(b"HTTP"):
            print(f"  [HTTP Metadata] {payload[:200]}")


def print_summary():
    print("\n" + "=" * 60)
    print(" TRAFFIC ANALYSIS SUMMARY")
    print("=" * 60)
    print(f"Total packets captured: {len(captured_packets)}")
    print("\nPackets per protocol:")
    for proto, count in protocol_counter.most_common():
        print(f"  {proto:8s} : {count}")

    # Show unique IPs
    src_ips = set(e["src_ip"] for e in traffic_log)
    dst_ips = set(e["dst_ip"] for e in traffic_log)
    print(f"\nUnique source IPs      : {len(src_ips)}")
    print(f"Unique destination IPs : {len(dst_ips)}")

    print("\nTop 5 source IPs:")
    src_counter = Counter(e["src_ip"] for e in traffic_log)
    for ip, count in src_counter.most_common(5):
        print(f"  {ip:20s} : {count} packets")

    print("\nTop 5 destination IPs:")
    dst_counter = Counter(e["dst_ip"] for e in traffic_log)
    for ip, count in dst_counter.most_common(5):
        print(f"  {ip:20s} : {count} packets")
    print("=" * 60)

if __name__ == "__main__":
    PACKET_COUNT = 50

    print("=" * 60)
    print("Live Traffic Sniffer")
    print("=" * 60)

    # ── Part 1a: TCP-only capture ──
    print(f"\n[1] Capturing {PACKET_COUNT} TCP packets...")
    sniff(filter="tcp", count=PACKET_COUNT, prn=packet_callback)

    # ── Part 1b: HTTP (port 80) capture ──
    print(f"\n[2] Capturing {PACKET_COUNT} HTTP (port 80) packets...")
    sniff(filter="tcp port 80", count=PACKET_COUNT, prn=packet_callback)

    # ── Part 1c: DNS (port 53) capture ──
    print(f"\n[3] Capturing {PACKET_COUNT} DNS (port 53) packets...")
    sniff(filter="udp port 53", count=PACKET_COUNT, prn=packet_callback)

    # ── Part 4: Print summary ──
    print_summary()
