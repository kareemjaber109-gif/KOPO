import sys
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine
import json

e = DetectionEngine()
e.load()

def generate_improved_flow(label):
    # Base defaults
    proto = 6
    port = 80
    dur = 2000000
    fwd = 5
    bwd = 5
    size = 200
    syn = 0
    ack = 0
    fin = 0
    urg = 0
    psh = 1
    win_fwd = 29200
    win_bwd = 235

    l = label.upper()
    if l in ['BENIGN', 'NORMAL HTTP', 'NORMAL']:
        port = 443; dur = 348000; fwd = 11; bwd = 6; size = 220; syn = 1; ack = 6; psh = 2
        win_fwd = 29200; win_bwd = 65535
    elif 'PORT_SCAN' in l or 'SCAN' in l:
        # CICIDS2017 PortScan profile
        port = 445; dur = 341670; fwd = 3; bwd = 6; size = 18; syn = 0; ack = 0; psh = 1
        win_fwd = 29200; win_bwd = 227
    elif l == 'TEARDROP':
        proto = 17; port = 0; dur = 400000; fwd = 200; bwd = 0; size = 40; psh = 0
        win_fwd = -1; win_bwd = -1
    elif l == 'PING_OF_DEATH':
        proto = 1; port = 0; dur = 400000; fwd = 25; bwd = 0; size = 1600; psh = 0
        win_fwd = -1; win_bwd = -1
    elif 'DOS' in l or 'SLOW' in l or 'HTTP_FLOOD' in l or 'LAND_ATTACK' in l:
        # CICIDS2017 DoS profile
        port = 80; dur = 13994; fwd = 3; bwd = 1; size = 6; syn = 0; ack = 0; psh = 0
        win_fwd = 0; win_bwd = 235
    elif 'DDOS' in l or 'SYN_FLOOD' in l or 'UDP_FLOOD' in l or 'ICMP_FLOOD' in l or 'AMPLIFICATION' in l or 'SMURF' in l:
        # CICIDS2017 DDoS profile
        port = 80; dur = 8927790; fwd = 5; bwd = 0; size = 6; syn = 0; ack = 1; psh = 0
        win_fwd = 256; win_bwd = -1
    elif 'BRUTE' in l or 'PASSWORD' in l or 'CREDENTIAL' in l:
        # CICIDS2017 BruteForce profile
        port = 22; dur = 12043459; fwd = 21; bwd = 32; size = 640; syn = 0; ack = 0; psh = 1
        win_fwd = 29200; win_bwd = 247
    elif 'SQL' in l or 'XSS' in l or 'WEB' in l or 'INJECTION' in l or 'TRAVERSAL' in l:
        # CICIDS2017 WebAttack profile
        port = 80; dur = 5659068; fwd = 3; bwd = 1; size = 0; syn = 0; ack = 0; psh = 1
        win_fwd = 29200; win_bwd = 28960
    elif 'BOT' in l or 'C2' in l or 'RANSOMWARE' in l or 'CRYPTOMINING' in l:
        # CICIDS2017 Bot profile
        port = 6667; dur = 1013034; fwd = 3; bwd = 3; size = 0; syn = 0; ack = 0; psh = 1
        win_fwd = 8192; win_bwd = 0
    elif 'ZERO_DAY' in l or 'EXPLOIT' in l or 'DATA_EXFILTRATION' in l:
        port = 8088; dur = 501734; fwd = 1; bwd = 1; size = 1460; syn = 0; ack = 1; urg = 4; psh = 1
        win_fwd = 8192; win_bwd = 0

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
        "Fwd PSH Flags": psh,
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
        "RST Flag Count": 0,
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
        "Subflow Fwd Packets": fwd,
        "Subflow Fwd Bytes": total_fwd,
        "Subflow Bwd Packets": bwd,
        "Subflow Bwd Bytes": total_bwd,
        "Init_Win_bytes_forward": win_fwd,
        "Init_Win_bytes_backward": win_bwd,
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

subtypes_to_test = [
    'BENIGN',
    'HTTP_FLOOD',
    'SYN_FLOOD',
    'PORT_SCAN',
    'SYN_SCAN',
    'BRUTE_FORCE_SSH',
    'SQL_INJECTION',
    'BOTNET',
    'TEARDROP',
    'ZERO_DAY_EXPLOIT'
]

print(f"{'Attack':<18} | {'Engine Verdict':<18} | {'XGBoost Label':<15} | {'XGB Conf':<9} | {'RF Label':<12} | {'RF Conf'}")
print("-" * 95)

for s in subtypes_to_test:
    flow = generate_improved_flow(s)
    res = e.predict(flow)
    xgb_l = res["model_results"]["xgb"]["label"]
    xgb_c = res["model_results"]["xgb"]["confidence"]
    rf_l = res["model_results"]["rf"]["label"]
    rf_c = res["model_results"]["rf"]["confidence"]
    print(f"{s:<18} | {res['attack_type']:<18} | {xgb_l:<15} | {xgb_c:<9.2f} | {rf_l:<12} | {rf_c:.2f}")
