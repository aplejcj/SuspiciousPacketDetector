from scapy.all import *
import pandas as pd
import matplotlib.pyplot as plt
from collections import defaultdict, Counter
from datetime import datetime
import os

def detect_and_plot(pcap_file):
    packets = rdpcap(pcap_file)

    ip_mac_map = defaultdict(set)
    mac_ip_map = defaultdict(set)
    dns_responses = defaultdict(lambda: defaultdict(set))
    dhcp_servers = defaultdict(list)
    icmp_counter = Counter()

    syn_counter = Counter()
    syn_ack_tracker = set()
    scan_flags_counter = Counter()

    log_lines = []

    for pkt in packets:
        pkt_time = datetime.fromtimestamp(float(pkt.time)).strftime("%Y-%m-%d %H:%M:%S")

        # === ARP Spoofing ===
        if pkt.haslayer(ARP) and pkt[ARP].op == 2:
            ip = pkt[ARP].psrc
            mac = pkt[ARP].hwsrc
            ip_mac_map[ip].add((mac, pkt_time))
            mac_ip_map[mac].add((ip, pkt_time))

        # === DNS Spoofing ===
        if pkt.haslayer(DNS) and pkt[DNS].qr == 1:
            if pkt.haslayer(DNSQR):
                qname = pkt[DNSQR].qname.decode()
                answer = pkt[DNS].an.rdata
                dns_responses[qname][answer].add(pkt_time)

        # === DHCP Spoofing ===
        if pkt.haslayer(DHCP):
            for opt in pkt[DHCP].options:
                if opt[0] == 'server_id':
                    dhcp_servers[opt[1]].append(pkt_time)

        # === ICMP Flood ===
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt.haslayer(IP):
            src = pkt[IP].src
            icmp_counter[src] += 1

        # === SYN Flood / TCP Scan ===
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flags = pkt[TCP].flags
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst
            dst_port = pkt[TCP].dport

            if flags == 'S':  # SYN only
                syn_counter[src_ip] += 1
                syn_ack_tracker.add((dst_ip, dst_port))
            elif flags == 'SA':  # SYN-ACK
                # ลด count ของ IP ที่มี handshake กลับ
                if (src_ip, pkt[TCP].sport) in syn_ack_tracker:
                    if syn_counter[src_ip] > 0:
                        syn_counter[src_ip] -= 1
                    syn_ack_tracker.discard((src_ip, pkt[TCP].sport))

            # ตรวจ TCP scan: NULL, XMAS, FIN
            if flags == 0:
                scan_flags_counter["NULL"] += 1
            elif flags == 0x29:  # FIN+PSH+URG
                scan_flags_counter["XMAS"] += 1
            elif flags == 0x01:  # FIN
                scan_flags_counter["FIN"] += 1

    # === ARP Spoofing Report ===
    log_lines.append("\n=== ARP Spoofing ===")
    log_lines.append("ระดับความอันตราย: สูง")
    log_lines.append("แนวทางป้องกันเบื้องต้น: ตรวจสอบและ alert MAC-IP mapping ที่เปลี่ยนแปลงผิดปกติ")
    for ip, macs_with_time in ip_mac_map.items():
        macs = set([m for m, _ in macs_with_time])
        if len(macs) > 1:
            log_lines.append(f"[!] IP {ip} maps to multiple MACs:")
            for mac, t in macs_with_time:
                log_lines.append(f"    - MAC: {mac} at {t}")
    for mac, ips_with_time in mac_ip_map.items():
        ips = set([ip for ip, _ in ips_with_time])
        if len(ips) > 1:
            log_lines.append(f"[!] MAC {mac} maps to multiple IPs:")
            for ip, t in ips_with_time:
                log_lines.append(f"    - IP: {ip} at {t}")

    # === DNS Spoofing Report ===
    log_lines.append("\n=== DNS Spoofing ===")
    log_lines.append("ระดับความอันตราย: ปานกลาง")
    log_lines.append("แนวทางป้องกันเบื้องต้น: หลีกเลี่ยงการใช้ DNS ที่ไม่น่าเชื่อถือ หรือใช้ DNS resolver ที่ควบคุมได้")
    for qname, rdata_time_map in dns_responses.items():
        if len(rdata_time_map) > 1:
            log_lines.append(f"[!] DNS mismatch for {qname}:")
            for rdata, times in rdata_time_map.items():
                for t in times:
                    log_lines.append(f"    - Response: {rdata} at {t}")

    # === DHCP Spoofing Report ===
    log_lines.append("\n=== DHCP Spoofing ===")
    log_lines.append("ระดับความอันตราย: สูง")
    log_lines.append("แนวทางป้องกันเบื้องต้น: จำกัด DHCP responses จาก MAC ที่ไม่รู้จัก")
    if len(dhcp_servers) > 1:
        log_lines.append(f"[!] Multiple DHCP servers detected:")
        for server, times in dhcp_servers.items():
            for t in times:
                log_lines.append(f"    - Server: {server} at {t}")
    else:
        for server, times in dhcp_servers.items():
            log_lines.append(f"[*] Single DHCP server: {server} at {times[0]}")

    # === ICMP Flood Report ===
    log_lines.append("\n=== ICMP Flood ===")
    log_lines.append("ระดับความอันตราย: ปานกลาง")
    log_lines.append("แนวทางป้องกันเบื้องต้น: ใช้ rate limiting บน firewall หรือ router")
    icmp_data = {"IP": [], "Packet Count": []}
    for src, count in icmp_counter.items():
        icmp_data["IP"].append(src)
        icmp_data["Packet Count"].append(count)
        if count > 100:
            log_lines.append(f"[!] High ICMP volume from {src}: {count} packets")

    # === SYN Flood Report ===
    log_lines.append("\n=== SYN Flood ===")
    log_lines.append("ระดับความอันตราย: สูง")
    log_lines.append("แนวทางป้องกันเบื้องต้น: ใช้ SYN cookies, จำกัด connection rate")
    for ip, count in syn_counter.items():
        if count > 100:
            log_lines.append(f"[!] Possible SYN flood from {ip}: {count} SYN packets without ACK")

    # === TCP Scan Report ===
    log_lines.append("\n=== TCP Scan Detection ===")
    log_lines.append("ระดับความอันตราย: ปานกลางถึงสูง (ขึ้นกับลักษณะ scan)")
    log_lines.append("แนวทางป้องกันเบื้องต้น: บล็อก IP ที่ scan พอร์ต, ใช้ IDS เช่น Snort/Suricata")
    for scan_type, count in scan_flags_counter.items():
        if count > 0:
            log_lines.append(f"[!] Detected {scan_type} scan: {count} packets")

    # === Console Output ===
    for line in log_lines:
        print(line)

    # === บันทึก log ลงไฟล์ ===
    log_file = os.path.join(current_dir, 'result/detection_result.txt')
    # log_file = "detection_result.txt"
    with open(log_file, "w", encoding="utf-8") as f:
        for line in log_lines:
            f.write(line + "\n")
    print(f"\n✅ ผลการวิเคราะห์ถูกบันทึกลงในไฟล์: {log_file}")

    # === ICMP Chart ===
    df = pd.DataFrame(icmp_data)
    if not df.empty:
        plt.figure(figsize=(10, 5))
        bars = plt.bar(df["IP"], df["Packet Count"], color='skyblue')
        plt.xlabel("Source IP")
        plt.ylabel("Number of ICMP Echo Requests")
        plt.title("ICMP Packet Count per Source IP")
        plt.xticks(rotation=45)
        for bar in bars:
            height = bar.get_height()
            plt.text(bar.get_x() + bar.get_width()/2, height + 1, str(height), ha='center', va='bottom')
        plt.tight_layout()
        icmp_flood_chart_path = os.path.join(current_dir, 'result/icmp_flood_chart.png')
        plt.savefig(icmp_flood_chart_path)
        print(f"📊 ICMP flood chart saved to {icmp_flood_chart_path}")
        plt.show()
    else:
        print("No ICMP Echo Request packets found.")

if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pcap_path = os.path.join(current_dir, 'sample/attack_test.pcap')
    detect_and_plot(pcap_path)
