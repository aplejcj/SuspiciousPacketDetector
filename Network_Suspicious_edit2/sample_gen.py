from scapy.all import *
import random
import time
import os

packets = []

base_time = time.time()

# === 1. ARP Spoofing ===
for i in range(6): 
    mac1 = f"aa:bb:cc:dd:ee:{i:02x}"
    mac2 = f"11:22:33:44:55:{i:02x}"
    arp1 = Ether()/ARP(op=2, psrc="192.168.1.1", hwsrc=mac1, pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
    arp1.time = base_time + i
    arp2 = Ether()/ARP(op=2, psrc="192.168.1.1", hwsrc=mac2, pdst="192.168.1.100", hwdst="ff:ff:ff:ff:ff:ff")
    arp2.time = base_time + i + 0.5
    packets += [arp1, arp2]

# === 2. DNS Spoofing ===
for i in range(6): 
    ip1 = f"1.2.3.{i+1}"
    ip2 = f"6.6.6.{i+1}"
    dns1 = Ether()/IP(src="8.8.8.8", dst="192.168.1.100")/UDP(sport=53, dport=33333)/DNS(
        id=i*2+1, qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata=ip1)
    )
    dns1.time = base_time + 10 + i
    dns2 = Ether()/IP(src="8.8.8.8", dst="192.168.1.100")/UDP(sport=53, dport=33333)/DNS(
        id=i*2+2, qr=1, qd=DNSQR(qname="example.com"), an=DNSRR(rrname="example.com", rdata=ip2)
    )
    dns2.time = base_time + 10 + i + 0.5
    packets += [dns1, dns2]

# === 3. DHCP Spoofing ===
for i in range(3):  
    eth1 = Ether(src=f"00:11:22:33:44:{i:02x}", dst="ff:ff:ff:ff:ff:ff")
    ip1 = IP(src="0.0.0.0", dst="255.255.255.255")
    udp1 = UDP(sport=67, dport=68)
    bootp1 = BOOTP(op=2, yiaddr=f"192.168.1.{101+i}", siaddr="192.168.1.1", chaddr=bytes.fromhex("aabbccddeeff"))
    dhcp1 = DHCP(options=[('message-type', 'offer'), ('server_id', '192.168.1.1'), 'end'])
    pkt_dhcp1 = eth1/ip1/udp1/bootp1/dhcp1
    pkt_dhcp1.time = base_time + 20 + i

    eth2 = Ether(src=f"66:77:88:99:aa:{i:02x}", dst="ff:ff:ff:ff:ff:ff")
    ip2 = IP(src="0.0.0.0", dst="255.255.255.255")
    udp2 = UDP(sport=67, dport=68)
    bootp2 = BOOTP(op=2, yiaddr=f"192.168.1.{102+i}", siaddr="192.168.1.200", chaddr=bytes.fromhex("aabbccddeeee"))
    dhcp2 = DHCP(options=[('message-type', 'offer'), ('server_id', '192.168.1.200'), 'end'])
    pkt_dhcp2 = eth2/ip2/udp2/bootp2/dhcp2
    pkt_dhcp2.time = base_time + 20 + i + 0.5

    packets += [pkt_dhcp1, pkt_dhcp2]

# === 4. ICMP Flood ===
for i in range(600):  
    src_ip = f"192.168.1.{random.randint(10, 20)}"
    pkt = Ether()/IP(src=src_ip, dst="192.168.1.100")/ICMP()
    pkt.time = base_time + 30 + i * 0.01
    packets.append(pkt)

# === 5. SYN Flood ===
for i in range(450): 
    pkt = Ether()/IP(src="10.0.0.99", dst="192.168.1.100")/TCP(sport=random.randint(1024, 65535), dport=80, flags="S")
    pkt.time = base_time + 40 + i * 0.01
    packets.append(pkt)

# === 6. TCP Port Scan ===
scan_ip = "10.0.0.77"
dst_ip = "192.168.1.100"
for port in range(20, 50):  
    # NULL scan
    null_pkt = Ether()/IP(src=scan_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=port, flags=0)
    null_pkt.time = base_time + 50 + port * 0.01
    packets.append(null_pkt)

    # FIN scan
    fin_pkt = Ether()/IP(src=scan_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=port, flags="F")
    fin_pkt.time = base_time + 50 + port * 0.01 + 0.005
    packets.append(fin_pkt)

    # XMAS scan (FIN + PSH + URG)
    xmas_pkt = Ether()/IP(src=scan_ip, dst=dst_ip)/TCP(sport=random.randint(1024, 65535), dport=port, flags="FPU")
    xmas_pkt.time = base_time + 50 + port * 0.01 + 0.010
    packets.append(xmas_pkt)

# 💾 บันทึกเป็น .pcap
current_dir = os.path.dirname(os.path.abspath(__file__))
pcap_path = os.path.join(current_dir, 'sample/attack_test.pcap')
os.makedirs(os.path.dirname(pcap_path), exist_ok=True)
wrpcap(pcap_path, packets)

print("✅ attack_test.pcap (3 เท่าของทุกการโจมตี) สร้างเรียบร้อยแล้ว")
