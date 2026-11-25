import sys
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine
import math

engine = DetectionEngine()
engine.load()

# Python replica of Detect.jsx generateAttackParams and makeDynamicFlow
def generate_attack_flow(label):
    dur, fwd, bwd, size, syn, ack, fin, rst, psh, urg, proto, port = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 80

    if label in ['BENIGN', 'Normal HTTP', 'Normal']:
        dur = 350000; fwd = 10; bwd = 8; size = 220; syn = 1; ack = 8; psh = 2; port = 443; proto = 6
    elif label in ['HTTP_FLOOD', 'DoS Attack', 'DOS', 'DoS']:
        dur = 400000; fwd = 8000; bwd = 40; size = 1460; syn = 1; ack = 40; port = 80; proto = 6
    elif label == 'SLOWLORIS':
        dur = 60000000; fwd = 100; bwd = 40; size = 2; syn = 1; ack = 40; port = 80; proto = 6
    elif label == 'SLOWHTTPTEST':
        dur = 50000000; fwd = 200; bwd = 80; size = 20; syn = 1; ack = 80; port = 80; proto = 6
    elif label == 'PING_OF_DEATH':
        dur = 400000; fwd = 25; bwd = 0; size = 1600; syn = 0; ack = 0; proto = 1; port = 0
    elif label == 'TEARDROP':
        dur = 400000; fwd = 200; bwd = 0; size = 40; syn = 0; ack = 0; proto = 17; port = 0
    elif label == 'LAND_ATTACK':
        dur = 400000; fwd = 20; bwd = 0; size = 40; syn = 20; ack = 0; port = 80; proto = 6
    elif label in ['SYN_FLOOD', 'DDoS Attack', 'DDOS']:
        dur = 100000; fwd = 5000; bwd = 0; size = 60; syn = 5000; ack = 0; port = 80; proto = 6
    elif label == 'UDP_FLOOD':
        dur = 50000; fwd = 10000; bwd = 0; size = 512; syn = 0; ack = 0; proto = 17; port = 53
    elif label == 'ICMP_FLOOD':
        dur = 50000; fwd = 8000; bwd = 0; size = 64; syn = 0; ack = 0; proto = 1; port = 0
    elif label == 'DNS_AMPLIFICATION':
        dur = 80000; fwd = 6000; bwd = 0; size = 1024; syn = 0; ack = 0; proto = 17; port = 53
    elif label == 'NTP_AMPLIFICATION':
        dur = 60000; fwd = 5000; bwd = 0; size = 468; syn = 0; ack = 0; proto = 17; port = 123
    elif label == 'SMURF':
        dur = 70000; fwd = 7000; bwd = 0; size = 128; syn = 0; ack = 0; proto = 1; port = 0
    elif label in ['PORT_SCAN', 'Port Scan']:
        dur = 50000; fwd = 2; bwd = 0; size = 0; syn = 1; ack = 0; port = 445; proto = 6
    elif label == 'SYN_SCAN':
        dur = 200000; fwd = 50; bwd = 0; size = 0; syn = 50; ack = 0; port = 80; proto = 6
    elif label == 'FIN_SCAN':
        dur = 150000; fwd = 30; bwd = 0; size = 0; syn = 0; fin = 30; ack = 0; port = 80; proto = 6
    elif label == 'NULL_SCAN':
        dur = 150000; fwd = 25; bwd = 0; size = 0; syn = 0; ack = 0; port = 80; proto = 6
    elif label == 'XMAS_SCAN':
        dur = 150000; fwd = 25; bwd = 0; size = 0; syn = 0; fin = 25; psh = 25; urg = 25; ack = 0; port = 80; proto = 6
    elif label in ['BRUTE_FORCE_SSH', 'Brute Force']:
        dur = 12000000; fwd = 1000; bwd = 600; size = 250; syn = 1; ack = 600; psh = 80; port = 22; proto = 6
    elif label == 'BRUTE_FORCE_FTP':
        dur = 10000000; fwd = 800; bwd = 500; size = 150; syn = 1; ack = 500; psh = 50; port = 21; proto = 6
    elif label == 'BRUTE_FORCE_WEB':
        dur = 8000000; fwd = 600; bwd = 400; size = 350; syn = 1; ack = 400; psh = 60; port = 80; proto = 6
    elif label == 'PASSWORD_SPRAYING':
        dur = 15000000; fwd = 400; bwd = 300; size = 280; syn = 1; ack = 300; psh = 40; port = 443; proto = 6
    elif label == 'CREDENTIAL_STUFFING':
        dur = 20000000; fwd = 800; bwd = 600; size = 320; syn = 1; ack = 600; psh = 70; port = 443; proto = 6
    elif label in ['SQL_INJECTION', 'Web Attack']:
        dur = 400000; fwd = 8; bwd = 6; size = 1200; syn = 1; ack = 6; psh = 25; port = 80; proto = 6
    elif label == 'XSS':
        dur = 350000; fwd = 6; bwd = 5; size = 950; syn = 1; ack = 5; psh = 18; port = 80; proto = 6
    elif label == 'COMMAND_INJECTION':
        dur = 450000; fwd = 7; bwd = 5; size = 1100; syn = 1; ack = 5; psh = 22; port = 80; proto = 6
    elif label == 'PATH_TRAVERSAL':
        dur = 300000; fwd = 5; bwd = 4; size = 800; syn = 1; ack = 4; psh = 15; port = 80; proto = 6
    elif label == 'DIRECTORY_BRUTEFORCE':
        dur = 5000000; fwd = 500; bwd = 300; size = 400; syn = 1; ack = 300; psh = 45; port = 80; proto = 6
    elif label == 'C2_BEACON':
        dur = 30000000; fwd = 30; bwd = 30; size = 180; syn = 1; ack = 30; port = 4444; proto = 6
    elif label == 'BOTNET':
        dur = 45000000; fwd = 60; bwd = 50; size = 220; syn = 1; ack = 50; port = 6667; proto = 6
    elif label == 'RANSOMWARE':
        dur = 60000000; fwd = 1500; bwd = 1000; size = 1400; syn = 1; ack = 1000; port = 445; proto = 6
    elif label == 'CRYPTOMINING':
        dur = 250000000; fwd = 300; bwd = 300; size = 600; syn = 1; ack = 300; port = 3333; proto = 6
    elif label == 'DATA_EXFILTRATION':
        dur = 60000000; fwd = 150; bwd = 3500; size = 1460; syn = 1; ack = 3500; port = 443; proto = 6
    elif label == 'ZERO_DAY_EXPLOIT':
        dur = 300000; fwd = 1; bwd = 1; size = 1460; syn = 0; ack = 1; urg = 4; port = 8088; proto = 6
    elif label == 'EMAIL_SPAM':
        dur = 15000000; fwd = 150; bwd = 100; size = 800; syn = 1; ack = 100; port = 25; proto = 6

    total_fwd = fwd * size
    total_bwd = bwd * size
    dur_sec = max(dur / 1e6, 1e-6)
    iat = dur / max(fwd, 1)
    bwd_iat = dur / bwd if bwd else 0

    return {
        "Destination Port": port,
        "Protocol": proto,
        "Flow Duration": dur,
        "Total Fwd Packets": fwd,
        "Total Backward Packets": bwd,
        "Total Length of Fwd Packets": total_fwd,
        "Total Length of Bwd Packets": total_bwd,
        "Fwd Packet Length Max": size,
        "Fwd Packet Length Min": max(0, int(size * 0.2)),
        "Fwd Packet Length Mean": round(size * (0.85 if size > 0 else 0), 1),
        "Fwd Packet Length Std": round(size * 0.25, 1),
        "Bwd Packet Length Max": size if bwd else 0,
        "Bwd Packet Length Min": max(0, int(size * 0.2)) if bwd else 0,
        "Bwd Packet Length Mean": round(size * 0.85, 1) if bwd else 0.0,
        "Bwd Packet Length Std": round(size * 0.25, 1) if bwd else 0.0,
        "Flow Bytes/s": round(((total_fwd + total_bwd) / dur_sec), 2),
        "Flow Packets/s": round(((fwd + bwd) / dur_sec), 2),
        "Flow IAT Mean": round(iat, 2),
        "Flow IAT Std": round(iat * 0.45, 2),
        "Flow IAT Max": round(iat * 2.2, 2),
        "Flow IAT Min": max(1, int(iat * 0.05)),
        "Fwd IAT Total": dur,
        "Fwd IAT Mean": round(iat, 2),
        "Fwd IAT Std": round(iat * 0.45, 2),
        "Fwd IAT Max": round(iat * 2.2, 2),
        "Fwd IAT Min": max(1, int(iat * 0.05)),
        "Bwd IAT Total": dur if bwd else 0,
        "Bwd IAT Mean": round(bwd_iat, 2),
        "Bwd IAT Std": round(bwd_iat * 0.45, 2),
        "Bwd IAT Max": round(bwd_iat * 2.2, 2),
        "Bwd IAT Min": max(1, int(bwd_iat * 0.05)) if bwd else 0,
        "Fwd PSH Flags": 1 if psh > 0 or size > 300 else 0,
        "Bwd PSH Flags": 0,
        "Fwd URG Flags": 1 if urg > 0 else 0,
        "Bwd URG Flags": 0,
        "Fwd Header Length": fwd * 20,
        "Bwd Header Length": bwd * 20,
        "Fwd Packets/s": round((fwd / dur_sec), 2),
        "Bwd Packets/s": round((bwd / dur_sec), 2),
        "Min Packet Length": max(0, int(size * 0.2)),
        "Max Packet Length": max(size, 60),
        "Packet Length Mean": round(size * (0.85 if size > 0 else 0), 1),
        "Packet Length Std": round(size * 0.28, 1),
        "Packet Length Variance": round(size * size * 0.08, 1),
        "FIN Flag Count": fin,
        "SYN Flag Count": syn,
        "RST Flag Count": rst,
        "PSH Flag Count": psh,
        "ACK Flag Count": ack,
        "URG Flag Count": urg,
        "CWE Flag Count": 0,
        "ECE Flag Count": 0,
        "Down/Up Ratio": round((bwd / max(fwd, 1)), 2),
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
        "act_data_pkt_fwd": max(1, int(fwd * 0.7)),
        "min_seg_size_forward": 20,
        "Active Mean": 0,
        "Active Std": 0,
        "Active Max": 0,
        "Active Min": 0,
        "Idle Mean": 0,
        "Idle Std": 0,
        "Idle Max": 0,
        "Idle Min": 0
    }

subtypes = [
    'BENIGN',
    'HTTP_FLOOD', 'SLOWLORIS', 'SLOWHTTPTEST', 'PING_OF_DEATH', 'TEARDROP', 'LAND_ATTACK',
    'SYN_FLOOD', 'UDP_FLOOD', 'ICMP_FLOOD', 'DNS_AMPLIFICATION', 'NTP_AMPLIFICATION', 'SMURF',
    'PORT_SCAN', 'SYN_SCAN', 'FIN_SCAN', 'NULL_SCAN', 'XMAS_SCAN',
    'BRUTE_FORCE_SSH', 'BRUTE_FORCE_FTP', 'BRUTE_FORCE_WEB', 'PASSWORD_SPRAYING', 'CREDENTIAL_STUFFING',
    'SQL_INJECTION', 'XSS', 'COMMAND_INJECTION', 'PATH_TRAVERSAL', 'DIRECTORY_BRUTEFORCE',
    'C2_BEACON', 'BOTNET', 'RANSOMWARE', 'CRYPTOMINING',
    'DATA_EXFILTRATION', 'ZERO_DAY_EXPLOIT', 'EMAIL_SPAM'
]

print(f"{'Subtype':<24} | {'Verdict':<18} | {'Category':<16} | {'XGB':<12} | {'RF':<12} | {'LSTM':<10} | {'Votes'}")
print("-" * 115)

for s in subtypes:
    flow = generate_attack_flow(s)
    res = engine.predict(flow)
    xgb_lbl = res["model_results"].get("xgb", {}).get("label", "N/A")
    rf_lbl = res["model_results"].get("rf", {}).get("label", "N/A")
    lstm_lbl = res["model_results"].get("lstm", {}).get("label", "N/A")
    votes = f"{res['ensemble_votes']['attack']}/{res['ensemble_votes']['total']}"
    print(f"{s:<24} | {res['attack_type']:<18} | {res['attack_category']:<16} | {xgb_lbl:<12} | {rf_lbl:<12} | {lstm_lbl:<10} | {votes}")
