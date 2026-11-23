"""
KOPO / ThreatNet IDS - Comprehensive Multi-Class Traffic Generator & Streaming Simulator
Supports 35 distinct attack types + Benign traffic across 7 cyber categories:
1. DDoS / Floods (SYN, UDP, ICMP, HTTP, DNS Amp, NTP Amp, Smurf)
2. DoS (Slowloris, Slowhttptest, Teardrop, Ping of Death, Land Attack)
3. Scans (Port Scan, SYN Scan, Null Scan, FIN Scan, Xmas Scan)
4. Brute Force (SSH, FTP, Web, SSH Patator, FTP Patator)
5. Web Attacks (SQL Injection, XSS, Generic Web Attack, Heartbleed, Phishing)
6. Malware & Botnets (Botnet, Ransomware, C2 Beacon, Cryptomining)
7. Infiltration & Exploits (Infiltration, Data Exfiltration, Zero-Day Exploit, Email Spam)

Outputs: flows_77_full.jsonl / flows_77_full.csv
"""
import argparse
import csv
import json
import random
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
import pandas as pd


# Mapping from 35 specific attack types to 8 high-level IDS macro classes
LABEL_TO_MACRO = {
    "BENIGN": "BENIGN",
    # DDoS
    "SYN_FLOOD": "DDoS",
    "UDP_FLOOD": "DDoS",
    "ICMP_FLOOD": "DDoS",
    "DNS_AMPLIFICATION": "DDoS",
    "NTP_AMPLIFICATION": "DDoS",
    "SMURF": "DDoS",
    # DoS
    "HTTP_FLOOD": "DoS",
    "SLOWLORIS": "DoS",
    "SLOWHTTPTEST": "DoS",
    "PING_OF_DEATH": "DoS",
    "TEARDROP": "DoS",
    "LAND_ATTACK": "DoS",
    # Port Scans
    "PORT_SCAN": "PortScan",
    "SYN_SCAN": "PortScan",
    "NULL_SCAN": "PortScan",
    "FIN_SCAN": "PortScan",
    "XMAS_SCAN": "PortScan",
    # Brute Force
    "BRUTE_FORCE_SSH": "BruteForce",
    "BRUTE_FORCE_FTP": "BruteForce",
    "BRUTE_FORCE_WEB": "BruteForce",
    "SSH_PATATOR": "BruteForce",
    "FTP_PATATOR": "BruteForce",
    # Web Attacks
    "SQL_INJECTION": "WebAttack",
    "XSS": "WebAttack",
    "WEB_ATTACK": "WebAttack",
    "HEARTBLEED": "WebAttack",
    "PHISHING": "WebAttack",
    # Botnet & C2
    "BOTNET": "Bot",
    "C2_BEACON": "Bot",
    "CRYPTOMINING": "Bot",
    "EMAIL_SPAM": "Bot",
    # Infiltration / Malware / Exploits
    "INFILTRATION": "Infiltration",
    "RANSOMWARE": "Infiltration",
    "DATA_EXFILTRATION": "Infiltration",
    "ZERO_DAY_EXPLOIT": "Infiltration",
}

ALL_LABELS = list(LABEL_TO_MACRO.keys())


def base_values(label: str) -> dict:
    """Generate accurate, distinct network telemetry parameters for every attack & benign class."""
    # ---------- طبيعي ----------
    if label == "BENIGN":
        f = random.randint(3, 20)
        b = random.randint(2, 20)
        return dict(dur=random.randint(200_000, 3_000_000), fwd=f, bwd=b,
                    size=random.choice([60, 512, 1460]), syn=1, ack=b,
                    fin=0, rst=0, psh=random.randint(1, 4), urg=0,
                    proto=6, port=random.choice([80, 443, 22]))

    # ---------- DDoS / DoS ----------
    if label == "SYN_FLOOD":
        f = random.randint(2000, 10000)
        return dict(dur=random.randint(50_000, 200_000), fwd=f, bwd=0, size=60,
                    syn=f, ack=0, fin=0, rst=0, psh=0, urg=0, proto=6, port=80)
    if label == "UDP_FLOOD":
        return dict(dur=random.randint(20_000, 100_000), fwd=random.randint(5000, 20000),
                    bwd=0, size=random.choice([512, 1024]), syn=0, ack=0,
                    fin=0, rst=0, psh=0, urg=0, proto=17, port=53)
    if label == "ICMP_FLOOD":
        return dict(dur=random.randint(20_000, 100_000), fwd=random.randint(3000, 15000),
                    bwd=0, size=random.choice([64, 128]), syn=0, ack=0,
                    fin=0, rst=0, psh=0, urg=0, proto=1, port=0)
    if label == "HTTP_FLOOD":
        return dict(dur=random.randint(300_000, 800_000), fwd=random.randint(5000, 15000),
                    bwd=random.randint(20, 100), size=1460, syn=1, ack=random.randint(20, 100),
                    fin=0, rst=0, psh=0, urg=0, proto=6, port=80)
    if label == "SLOWLORIS":
        return dict(dur=random.randint(30_000_000, 120_000_000), fwd=random.randint(50, 200),
                    bwd=random.randint(20, 100), size=random.choice([1, 2, 5]), syn=1,
                    ack=random.randint(20, 100), fin=0, rst=0, psh=0, urg=0, proto=6, port=80)
    if label == "SLOWHTTPTEST":
        return dict(dur=random.randint(20_000_000, 90_000_000), fwd=random.randint(100, 400),
                    bwd=random.randint(50, 200), size=random.choice([10, 20, 50]), syn=1,
                    ack=random.randint(50, 200), fin=0, rst=0, psh=0, urg=0, proto=6, port=80)

    # ---------- Scans (أعلام دقيقة) ----------
    if label == "PORT_SCAN":
        f = random.randint(100, 500)
        return dict(dur=random.randint(500_000, 5_000_000), fwd=f, bwd=random.randint(0, f),
                    size=0, syn=f, ack=0, fin=0, rst=0, psh=0, urg=0, proto=6, port=random.randint(1, 1024))
    if label == "SYN_SCAN":
        f = random.randint(100, 400)
        return dict(dur=random.randint(500_000, 3_000_000), fwd=f, bwd=0, size=0,
                    syn=f, ack=0, fin=0, rst=0, psh=0, urg=0, proto=6, port=random.randint(1, 1024))
    if label == "NULL_SCAN":
        return dict(dur=random.randint(500_000, 3_000_000), fwd=random.randint(50, 200),
                    bwd=0, size=0, syn=0, ack=0, fin=0, rst=0, psh=0, urg=0,
                    proto=6, port=random.randint(1, 1024))
    if label == "FIN_SCAN":
        f = random.randint(50, 200)
        return dict(dur=random.randint(500_000, 3_000_000), fwd=f, bwd=0, size=0,
                    syn=0, ack=0, fin=f, rst=0, psh=0, urg=0, proto=6, port=random.randint(1, 1024))
    if label == "XMAS_SCAN":
        f = random.randint(50, 200)
        return dict(dur=random.randint(500_000, 3_000_000), fwd=f, bwd=0, size=0,
                    syn=0, ack=0, fin=f, rst=0, psh=f, urg=f, proto=6, port=random.randint(1, 1024))

    # ---------- Brute Force ----------
    if label == "BRUTE_FORCE_SSH":
        return dict(dur=random.randint(10_000_000, 60_000_000), fwd=random.randint(500, 2000),
                    bwd=random.randint(500, 2000), size=random.choice([200, 300, 400]), syn=1,
                    ack=random.randint(500, 4000), fin=0, rst=0, psh=0, urg=0, proto=6, port=22)
    if label == "BRUTE_FORCE_FTP":
        return dict(dur=random.randint(10_000_000, 60_000_000), fwd=random.randint(500, 2000),
                    bwd=random.randint(500, 2000), size=random.choice([200, 300, 400]), syn=1,
                    ack=random.randint(500, 4000), fin=0, rst=0, psh=0, urg=0, proto=6, port=21)
    if label == "BRUTE_FORCE_WEB":
        return dict(dur=random.randint(10_000_000, 60_000_000), fwd=random.randint(500, 2000),
                    bwd=random.randint(500, 2000), size=random.choice([300, 500, 700]), syn=1,
                    ack=random.randint(500, 4000), fin=0, rst=0, psh=0, urg=0, proto=6, port=random.choice([80, 443]))
    if label == "SSH_PATATOR":
        return dict(dur=random.randint(20_000_000, 90_000_000), fwd=random.randint(1000, 3000),
                    bwd=random.randint(1000, 3000), size=random.choice([100, 200, 300]), syn=1,
                    ack=random.randint(1000, 6000), fin=0, rst=0, psh=0, urg=0, proto=6, port=22)
    if label == "FTP_PATATOR":
        return dict(dur=random.randint(20_000_000, 90_000_000), fwd=random.randint(1000, 3000),
                    bwd=random.randint(1000, 3000), size=random.choice([100, 200, 300]), syn=1,
                    ack=random.randint(1000, 6000), fin=0, rst=0, psh=0, urg=0, proto=6, port=21)

    # ---------- Web Attacks ----------
    if label == "SQL_INJECTION":
        return dict(dur=random.randint(1_000_000, 10_000_000), fwd=random.randint(30, 150),
                    bwd=random.randint(20, 100), size=random.choice([800, 1200, 1460]), syn=1,
                    ack=random.randint(20, 100), fin=0, rst=0, psh=random.randint(30, 150), urg=0,
                    proto=6, port=80)
    if label == "XSS":
        return dict(dur=random.randint(1_000_000, 8_000_000), fwd=random.randint(15, 80),
                    bwd=random.randint(15, 80), size=random.choice([500, 700, 900]), syn=1,
                    ack=random.randint(15, 80), fin=0, rst=0, psh=random.randint(15, 80), urg=0,
                    proto=6, port=80)
    if label == "WEB_ATTACK":
        return dict(dur=random.randint(5_000_000, 30_000_000), fwd=random.randint(100, 500),
                    bwd=random.randint(100, 500), size=random.choice([600, 900, 1200]), syn=1,
                    ack=random.randint(100, 500), fin=0, rst=0, psh=random.randint(50, 200), urg=0,
                    proto=6, port=80)
    if label == "HEARTBLEED":
        return dict(dur=random.randint(500_000, 5_000_000), fwd=random.randint(10, 50),
                    bwd=random.randint(10, 50), size=random.choice([1400, 1460]), syn=1,
                    ack=random.randint(10, 50), fin=0, rst=0, psh=random.randint(10, 50), urg=0,
                    proto=6, port=443)
    if label == "PHISHING":
        return dict(dur=random.randint(500_000, 5_000_000), fwd=random.randint(10, 60),
                    bwd=random.randint(10, 60), size=random.choice([400, 600, 800]), syn=1,
                    ack=random.randint(10, 60), fin=0, rst=0, psh=random.randint(5, 30), urg=0,
                    proto=6, port=random.choice([80, 443]))

    # ---------- Malware / Infiltration ----------
    if label == "BOTNET":
        return dict(dur=random.randint(5_000_000, 30_000_000), fwd=random.randint(50, 300),
                    bwd=random.randint(50, 300), size=random.choice([100, 300, 600]), syn=1,
                    ack=random.randint(50, 300), fin=0, rst=0, psh=0, urg=0,
                    proto=6, port=random.randint(1024, 65535))
    if label == "INFILTRATION":
        return dict(dur=random.randint(30_000_000, 180_000_000), fwd=random.randint(200, 1000),
                    bwd=random.randint(1000, 5000), size=1460, syn=1, ack=random.randint(1000, 5000),
                    fin=0, rst=0, psh=0, urg=0, proto=6, port=random.choice([80, 443]))
    if label == "RANSOMWARE":
        return dict(dur=random.randint(60_000_000, 300_000_000), fwd=random.randint(1000, 5000),
                    bwd=random.randint(2000, 10000), size=random.choice([1000, 1200, 1400]), syn=1,
                    ack=random.randint(2000, 10000), fin=0, rst=0,
                    psh=random.randint(1000, 5000), urg=0, proto=6, port=random.choice([445, 139, 443]))
    if label == "C2_BEACON":
        return dict(dur=random.randint(10_000_000, 60_000_000), fwd=random.randint(20, 100),
                    bwd=random.randint(20, 100), size=random.choice([100, 200, 300]), syn=1,
                    ack=random.randint(20, 100), fin=0, rst=0, psh=0, urg=0,
                    proto=6, port=random.choice([8080, 8443, 4444]))
    if label == "CRYPTOMINING":
        return dict(dur=random.randint(120_000_000, 600_000_000), fwd=random.randint(200, 800),
                    bwd=random.randint(200, 800), size=random.choice([300, 600, 900]), syn=1,
                    ack=random.randint(200, 800), fin=0, rst=0, psh=0, urg=0,
                    proto=6, port=random.choice([3333, 4444, 14444]))
    if label == "DATA_EXFILTRATION":
        return dict(dur=random.randint(30_000_000, 180_000_000), fwd=random.randint(100, 500),
                    bwd=random.randint(2000, 10000), size=1460, syn=1, ack=random.randint(2000, 10000),
                    fin=0, rst=0, psh=0, urg=0, proto=6, port=random.choice([443, 21]))
    if label == "ZERO_DAY_EXPLOIT":
        return dict(dur=random.randint(1_000_000, 10_000_000), fwd=random.randint(10, 50),
                    bwd=random.randint(10, 50), size=random.choice([1500, 1600, 2000]), syn=1,
                    ack=random.randint(10, 50), fin=0, rst=0,
                    psh=random.randint(10, 50), urg=random.randint(1, 10),
                    proto=6, port=random.choice([80, 443, 445]))

    # ---------- Amplification / Legacy ----------
    if label == "DNS_AMPLIFICATION":
        return dict(dur=random.randint(100_000, 1_000_000), fwd=random.randint(1000, 5000),
                    bwd=random.randint(5000, 20000), size=random.choice([512, 1024]), syn=0,
                    ack=0, fin=0, rst=0, psh=0, urg=0, proto=17, port=53)
    if label == "NTP_AMPLIFICATION":
        return dict(dur=random.randint(100_000, 1_000_000), fwd=random.randint(1000, 5000),
                    bwd=random.randint(5000, 20000), size=random.choice([512, 1024]), syn=0,
                    ack=0, fin=0, rst=0, psh=0, urg=0, proto=17, port=123)
    if label == "SMURF":
        return dict(dur=random.randint(100_000, 1_000_000), fwd=random.randint(1000, 5000),
                    bwd=random.randint(5000, 20000), size=random.choice([64, 128]), syn=0,
                    ack=0, fin=0, rst=0, psh=0, urg=0, proto=1, port=0)
    if label == "PING_OF_DEATH":
        return dict(dur=random.randint(100_000, 1_000_000), fwd=random.randint(10, 50),
                    bwd=random.randint(0, 10), size=random.choice([1473, 1600, 2000]), syn=0,
                    ack=0, fin=0, rst=0, psh=0, urg=0, proto=1, port=0)
    if label == "TEARDROP":
        return dict(dur=random.randint(100_000, 1_000_000), fwd=random.randint(100, 500),
                    bwd=random.randint(0, 50), size=random.choice([28, 40, 60]), syn=0,
                    ack=0, fin=0, rst=0, psh=0, urg=0, proto=17, port=0)
    if label == "LAND_ATTACK":
        f = random.randint(1000, 5000)
        return dict(dur=random.randint(100_000, 1_000_000), fwd=f, bwd=0, size=60,
                    syn=f, ack=0, fin=0, rst=0, psh=0, urg=0, proto=6, port=80)
    if label == "EMAIL_SPAM":
        return dict(dur=random.randint(5_000_000, 30_000_000), fwd=random.randint(100, 500),
                    bwd=random.randint(50, 300), size=random.choice([400, 800, 1200]), syn=1,
                    ack=random.randint(50, 300), fin=0, rst=0, psh=0, urg=0, proto=6, port=25)

    raise ValueError(f"صنف غير معروف: {label}")


def make_full_flow(label: str) -> dict:
    """Build a complete 77-feature enterprise flow payload."""
    v = base_values(label)
    dur, fwd, bwd, size = v["dur"], v["fwd"], v["bwd"], v["size"]
    syn, ack = v["syn"], v["ack"]
    fin, rst, psh, urg = v["fin"], v["rst"], v["psh"], v["urg"]
    proto, port = v["proto"], v["port"]

    total_fwd = fwd * size
    total_bwd = bwd * size
    dur_s = max(dur / 1e6, 1e-6)
    iat = dur / max(fwd, 1)
    bwd_iat = dur / max(bwd, 1) if bwd else 0.0

    return {
        "Destination Port": port,
        "Flow Duration": dur,
        "Total Fwd Packets": fwd,
        "Total Backward Packets": bwd,
        "Total Length of Fwd Packets": total_fwd,
        "Total Length of Bwd Packets": total_bwd,
        "Fwd Packet Length Max": size,
        "Fwd Packet Length Min": size if fwd > 0 else 0,
        "Fwd Packet Length Mean": float(size),
        "Fwd Packet Length Std": 0.0,
        "Bwd Packet Length Max": size if bwd > 0 else 0,
        "Bwd Packet Length Min": size if bwd > 0 else 0,
        "Bwd Packet Length Mean": float(size) if bwd > 0 else 0.0,
        "Bwd Packet Length Std": 0.0,
        "Flow Bytes/s": round((total_fwd + total_bwd) / dur_s, 2),
        "Flow Packets/s": round((fwd + bwd) / dur_s, 2),
        "Flow IAT Mean": round(iat, 2),
        "Flow IAT Std": 0.0,
        "Flow IAT Max": round(iat, 2),
        "Flow IAT Min": round(iat, 2),
        "Fwd IAT Total": dur,
        "Fwd IAT Mean": round(iat, 2),
        "Fwd IAT Std": 0.0,
        "Fwd IAT Max": round(iat, 2),
        "Fwd IAT Min": round(iat, 2),
        "Bwd IAT Total": dur if bwd else 0,
        "Bwd IAT Mean": round(bwd_iat, 2),
        "Bwd IAT Std": 0.0,
        "Bwd IAT Max": round(bwd_iat, 2),
        "Bwd IAT Min": round(bwd_iat, 2),
        "Fwd PSH Flags": 1 if psh > 0 else 0,
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": 1 if urg > 0 else 0,
        "Bwd URG Flags": 0,
        "Fwd Header Length": fwd * 20,
        "Bwd Header Length": bwd * 20,
        "Fwd Packets/s": round(fwd / dur_s, 2),
        "Bwd Packets/s": round(bwd / dur_s, 2),
        "Min Packet Length": min(size, 60) if size else 0,
        "Max Packet Length": max(size, 60),
        "Packet Length Mean": float(size),
        "Packet Length Std": 0.0,
        "Packet Length Variance": 0.0,
        "FIN Flag Count": fin,
        "SYN Flag Count": syn,
        "RST Flag Count": rst,
        "PSH Flag Count": psh,
        "ACK Flag Count": ack,
        "URG Flag Count": urg,
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,
        "Down/Up Ratio": round(bwd / max(fwd, 1), 5),
        "Average Packet Size": float(size),
        "Avg Fwd Segment Size": float(size),
        "Avg Bwd Segment Size": float(size) if bwd else 0.0,
        "Fwd Header Length.1": fwd * 20,
        "Fwd Avg Bytes/Bulk": 0,
        "Fwd Avg Packets/Bulk": 0,
        "Fwd Avg Bulk Rate": 0,
        "Bwd Avg Bytes/Bulk": 0,
        "Bwd Avg Packets/Bulk": 0,
        "Bwd Avg Bulk Rate": 0,
        "Subflow Fwd Packets": fwd,
        "Subflow Fwd Bytes": total_fwd,
        "Subflow Bwd Packets": bwd,
        "Subflow Bwd Bytes": total_bwd,
        "Init_Win_bytes_forward": 8192,
        "Init_Win_bytes_backward": 65535 if bwd else 0,
        "act_data_pkt_fwd": max(fwd - 1, 0),
        "min_seg_size_forward": 20,
        "Active Mean": 0.0 if label == "BENIGN" else dur / 2.0,
        "Active Std": 0.0,
        "Active Max": 0 if label == "BENIGN" else dur // 2,
        "Active Min": 0 if label == "BENIGN" else dur // 2,
        "Idle Mean": 0.0 if label == "BENIGN" else dur / 2.0,
        "Idle Std": 0.0,
        "Idle Max": 0 if label == "BENIGN" else dur // 2,
        "Idle Min": 0 if label == "BENIGN" else dur // 2,
        "Label": label,
    }


def make_flow(label: str) -> dict:
    """Build a simplified 10-feature flow payload."""
    v = base_values(label)
    dur, fwd, bwd, size = v["dur"], v["fwd"], v["bwd"], v["size"]
    syn, ack, proto = v["syn"], v["ack"], v["proto"]
    total_bytes = fwd * size
    dur_sec = max(dur / 1e6, 1e-6)

    return {
        "Protocol": proto,
        "Flow Duration": dur,
        "Total Fwd Packets": fwd,
        "Total Backward Packets": bwd,
        "Fwd Packet Length Max": size,
        "Flow Bytes/s": round(total_bytes / dur_sec, 2),
        "Flow Packets/s": round((fwd + bwd) / dur_sec, 2),
        "SYN Flag Count": syn,
        "ACK Flag Count": ack,
        "Avg Packet Size": round(total_bytes / fwd, 2) if fwd else 0,
        "label": label,
    }


def stream_traffic(api_url: str = "http://127.0.0.1:8000/api/detect", interval_sec: float = 2.0, feature_mode: int = 77):
    """
    Live streaming mode:
    Periodically generates a random flow from the 35 attack types, prints it, and submits it to the API.
    """
    print(f"\n🚀 [KOPO IDS] بدء بث الترافيك الحي الشامل إلى {api_url}")
    print(f"📊 عدد الأصناف المدعومة: {len(ALL_LABELS)} صنفاً (35 هجوماً + الطبيعي)")
    print(f"📊 نمط الميزات: {feature_mode} ميزة ({'77-Feature Enterprise' if feature_mode == 77 else '10-Feature Simplified'})")
    print(f"⏱ الفاصل الزمني: كل {interval_sec} ثانية (اضغط Ctrl+C للإيقاف)...")
    print("=" * 95)

    count = 0
    try:
        while True:
            count += 1
            lbl = random.choice(ALL_LABELS)
            flow = make_full_flow(lbl) if feature_mode == 77 else make_flow(lbl)
            payload_flow = {k: v for k, v in flow.items() if k not in ["Label", "label"]}

            try:
                req = urllib.request.Request(
                    api_url,
                    data=json.dumps({"features": payload_flow}).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                )
                with urllib.request.urlopen(req, timeout=3) as resp:
                    res = json.loads(resp.read().decode("utf-8"))
                    pred = res.get("attack_type", "UNKNOWN")
                    conf = res.get("confidence", 0) * 100
                    anom = res.get("is_anomaly", False)
                    anom_score = (res.get("anomaly_score") or 0) * 100

                    status_icon = "🚨 ATTACK" if res.get("is_attack") else "✅ BENIGN"
                    print(
                        f"[{count:04d}] مولّد: {lbl:20s} ➔ التوقع بالـ ML: {pred:14s} ({conf:5.1f}%) | "
                        f"شذوذ: {anom_score:5.1f}% ({'ANOMALY' if anom else 'NORMAL'}) | {status_icon}"
                    )
            except Exception as e:
                print(f"[{count:04d}] مولّد: {lbl:20s} | Pkts: {flow.get('Total Fwd Packets')} | (API offline: {e})")

            time.sleep(interval_sec)
    except KeyboardInterrupt:
        print("\n🛑 تم إيقاف البث الحي.")


def main():
    parser = argparse.ArgumentParser(description="KOPO ThreatNet IDS - 35 Attack Classes Generator & Streamer")
    parser.add_argument("--features", type=int, choices=[10, 77], default=77, help="Feature schema mode: 10 or 77 (default: 77)")
    parser.add_argument("--count", type=int, default=300, help="Number of flows per class to generate (default: 300)")
    parser.add_argument("--stream", action="store_true", help="Run in continuous live streaming mode")
    parser.add_argument("--interval", type=float, default=2.0, help="Interval in seconds between flows in stream mode (default: 2.0)")
    parser.add_argument("--api", type=str, default="http://127.0.0.1:8000/api/detect", help="Detection API URL for stream mode")
    args = parser.parse_args()

    if args.stream:
        stream_traffic(api_url=args.api, interval_sec=args.interval, feature_mode=args.features)
        return

    print(f"▶ [KOPO IDS] توليد {args.count} سجل لكل صنف ({len(ALL_LABELS)} أصناف) بنمط {args.features} ميزة...")
    gen_func = make_full_flow if args.features == 77 else make_flow
    flows = [gen_func(l) for l in ALL_LABELS for _ in range(args.count)]

    # 1. Save JSONL
    jsonl_path = "flows_77_full.jsonl" if args.features == 77 else "flows_10_full.jsonl"
    with open(jsonl_path, "w", encoding="utf-8") as f:
        for fl in flows:
            f.write(json.dumps(fl) + "\n")

    # 2. Save CSV
    csv_path = "flows_77_full.csv" if args.features == 77 else "flows_10_full.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(flows[0].keys()))
        w.writeheader()
        w.writerows(flows)

    print(f"عدد الأصناف: {len(ALL_LABELS)}")
    print(f"عدد السجلات: {len(flows):,}")
    print(f"عدد الأعمدة: {len(flows[0])}  ({args.features} ميزة + Label)")
    print(f"✅ تم حفظ الملفات بنجاح ➔ {jsonl_path} / {csv_path}\n")

    label_key = "Label" if "Label" in flows[0] else "label"
    print("التوزيع الإحصائي:")
    for k, v in sorted(Counter(fl[label_key] for fl in flows).items()):
        print(f"  {k:22s} : {v}")


if __name__ == "__main__":
    main()
