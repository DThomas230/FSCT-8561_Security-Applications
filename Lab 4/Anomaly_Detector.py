from scapy.all import rdpcap, IP, TCP, UDP
from collections import defaultdict

PCAP_FILE = "botnet-capture-20110812-rbot.pcap"
WINDOW_SECONDS = 5       # sliding window size
THRESHOLD = 20           # packets in window to trigger alert

print("=" * 60)
print("Anomaly Detector (PCAP Analysis)")
print("=" * 60)
print(f"\nLoading {PCAP_FILE} ...")
packets = rdpcap(PCAP_FILE)
print(f"Total packets loaded: {len(packets)}\n")

tcp_count = 0
udp_count = 0
other_count = 0

# src_ip -> list of timestamps
ip_timestamps = defaultdict(list)

# Track which IPs already triggered an alert (print once)
alerted_ips = set()
suspicious_ips = set()

for pkt in packets:
    if not pkt.haslayer(IP):
        continue

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    ts = float(pkt.time)

    # Count by protocol
    if pkt.haslayer(TCP):
        tcp_count += 1
    elif pkt.haslayer(UDP):
        udp_count += 1
    else:
        other_count += 1

    # Record timestamp for this source IP
    ip_timestamps[src_ip].append(ts)

    # ── Sliding-window anomaly detection ──
    # Keep only timestamps within the last WINDOW_SECONDS
    timestamps = ip_timestamps[src_ip]
    window_start = ts - WINDOW_SECONDS
    # Remove old timestamps outside the window
    ip_timestamps[src_ip] = [t for t in timestamps if t >= window_start]

    # Check threshold
    if len(ip_timestamps[src_ip]) > THRESHOLD:
        suspicious_ips.add(src_ip)
        if src_ip not in alerted_ips:
            print(f"[ALERT] Potential flood detected from {src_ip} "
                  f"– {len(ip_timestamps[src_ip])} packets in "
                  f"{WINDOW_SECONDS}s window")
            alerted_ips.add(src_ip)

print("\n" + "=" * 60)
print("ANALYSIS SUMMARY")
print("=" * 60)
print(f"Total TCP Packets      : {tcp_count}")
print(f"Total UDP Packets      : {udp_count}")
print(f"Total Other Packets    : {other_count}")
print(f"Suspicious IPs Detected: {len(suspicious_ips)}")

if suspicious_ips:
    print("\nSuspicious source IPs:")
    for ip in sorted(suspicious_ips):
        print(f"  - {ip}")

print("=" * 60)
