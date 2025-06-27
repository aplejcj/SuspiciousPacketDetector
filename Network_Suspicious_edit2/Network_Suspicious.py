# Network_Suspicious.py (Final Professional Version)
import os
import time
import json
import configparser
import argparse
from collections import defaultdict, Counter
import numpy as np
from scapy.all import *

class SuspiciousPacketDetector:
    """
    คลาสสำหรับวิเคราะห์และตรวจจับกิจกรรมที่น่าสงสัยในเครือข่าย
    โดยใช้การเรียนรู้ค่าพื้นฐาน (Baseline) และการวิเคราะห์เชิงสถิติ
    """
    def __init__(self, config_path='config.ini'):
        self.config = configparser.ConfigParser()
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"ไม่พบไฟล์ config: '{config_path}'")
        self.config.read(config_path)
        
        self.baseline_file = self.config.get('Paths', 'baseline_file', fallback='result/network_baseline.json')
        self.sensitivity = self.config.getfloat('DetectionParameters', 'sensitivity', fallback=3.0)

    def _analyze_packets_for_stats(self, packets):
        """(Private) วิเคราะห์ packet เพื่อสรุปสถิติพื้นฐานต่อช่วงเวลา"""
        if not packets:
            return {}
        
        events_per_interval = defaultdict(Counter)
        first_ts = packets[0].time
        interval_seconds = 10

        for pkt in packets:
            interval_index = int((pkt.time - first_ts) / interval_seconds)
            
            if pkt.haslayer(ARP) and pkt[ARP].op == 2:
                events_per_interval[interval_index]['arp_reply_count'] += 1
            if pkt.haslayer(TCP) and pkt[TCP].flags == 'S':
                events_per_interval[interval_index]['syn_count'] += 1
            if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
                events_per_interval[interval_index]['icmp_echo_count'] += 1
        
        return events_per_interval

    def learn(self, pcap_path):
        """
        โหมดเรียนรู้: สร้างไฟล์ Baseline จากทราฟฟิกปกติ
        """
        print(f"--- Running in LEARN mode from '{pcap_path}' ---")
        try:
            packets = rdpcap(pcap_path)
        except Scapy_Exception as e:
            print(f"[Error] ไม่สามารถอ่านไฟล์ pcap ได้: {e}")
            return

        events_per_interval = self._analyze_packets_for_stats(packets)
        
        # รวบรวมค่าเพื่อคำนวณสถิติ
        stats = defaultdict(list)
        for interval in events_per_interval.values():
            stats['arp_reply_count'].append(interval['arp_reply_count'])
            stats['syn_count'].append(interval['syn_count'])
            stats['icmp_echo_count'].append(interval['icmp_echo_count'])

        baseline = {}
        for key, values in stats.items():
            baseline[f"{key}_mean"] = np.mean(values) if values else 0
            baseline[f"{key}_std"] = np.std(values) if values else 0

        # สร้างโฟลเดอร์ result หากยังไม่มี
        os.makedirs(os.path.dirname(self.baseline_file), exist_ok=True)
        with open(self.baseline_file, 'w') as f:
            json.dump(baseline, f, indent=4)
            
        print(f"✅ Baseline created successfully: '{self.baseline_file}'")
        print(json.dumps(baseline, indent=2))

    def detect(self, pcap_path):
        """
        โหมดตรวจจับ: วิเคราะห์ไฟล์ pcap และหาความผิดปกติเทียบกับ Baseline
        """
        print(f"--- Running in DETECT mode on '{pcap_path}' ---")
        if not os.path.exists(self.baseline_file):
            raise FileNotFoundError(f"ไม่พบไฟล์ Baseline '{self.baseline_file}'. กรุณารันโหมด learn ก่อน")
            
        with open(self.baseline_file, 'r') as f:
            baseline = json.load(f)

        try:
            packets = rdpcap(pcap_path)
        except Scapy_Exception as e:
            print(f"[Error] ไม่สามารถอ่านไฟล์ pcap ได้: {e}")
            return

        events_per_interval = self._analyze_packets_for_stats(packets)
        detections = []

        for interval_idx, events in events_per_interval.items():
            # ตรวจจับ ICMP Flood
            icmp_threshold = baseline.get('icmp_echo_count_mean', 0) + (baseline.get('icmp_echo_count_std', 0) * self.sensitivity)
            if events['icmp_echo_count'] > icmp_threshold and icmp_threshold > 0:
                detections.append(f"High ICMP Echo activity detected (Count: {events['icmp_echo_count']}), normal is ~{baseline.get('icmp_echo_count_mean', 0):.1f}")

            # ตรวจจับ SYN Flood
            syn_threshold = baseline.get('syn_count_mean', 0) + (baseline.get('syn_count_std', 0) * self.sensitivity)
            if events['syn_count'] > syn_threshold and syn_threshold > 0:
                detections.append(f"High SYN Packet activity detected (Count: {events['syn_count']}), normal is ~{baseline.get('syn_count_mean', 0):.1f}")
        
        self._generate_report(detections)

    def _generate_report(self, detections):
        """(Private) สร้างรายงานสรุปผลการตรวจจับ"""
        output_dir = 'result'
        os.makedirs(output_dir, exist_ok=True)
        report_path = os.path.join(output_dir, 'detection_report.txt')

        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("Network Anomaly Detection Report\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*40 + "\n\n")

            if not detections:
                f.write("No significant anomalies detected based on the current baseline and sensitivity settings.\n")
                print("\n✅ Analysis complete. No significant anomalies detected.")
                return

            f.write("The following anomalies were detected:\n")
            for i, desc in enumerate(detections, 1):
                f.write(f"  {i}. {desc}\n")
        
        print(f"\n✅ Analysis complete. Report saved to '{report_path}'")


def main():
    """
    ฟังก์ชันหลักสำหรับจัดการ Command-line arguments
    """
    parser = argparse.ArgumentParser(
        description="Suspicious Packet Detector: A tool for network traffic analysis.",
        formatter_class=argparse.RawTextHelpFormatter
    )
    
    parser.add_argument(
        'mode', 
        choices=['learn', 'detect'], 
        help="The operational mode:\n"
             "learn  - Analyze a normal pcap file to create a traffic baseline.\n"
             "detect - Analyze a pcap file to detect anomalies against the baseline."
    )
    
    parser.add_argument(
        '--pcap', 
        required=True, 
        help="Path to the .pcap file to be analyzed."
    )
    
    parser.add_argument(
        '--config', 
        default='config.ini', 
        help="Path to the configuration file (default: config.ini)."
    )

    args = parser.parse_args()

    try:
        detector = SuspiciousPacketDetector(config_path=args.config)
        if args.mode == 'learn':
            detector.learn(pcap_path=args.pcap)
        elif args.mode == 'detect':
            detector.detect(pcap_path=args.pcap)
    except Exception as e:
        print(f"[FATAL ERROR] An unexpected error occurred: {e}")


if __name__ == "__main__":
    main()