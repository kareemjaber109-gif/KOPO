import sys
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine
import json

e = DetectionEngine()
e.load()

# Test how makeDynamicFlow with realistic parameters performs on XGBoost and RF
def make_realistic_flow(label):
    proto = 6
    port = 80
    dur = 1000000
    fwd = 5
    bwd = 5
    size = 200
    syn = 0
    ack = 0
    psh = 1
    urg = 0
    fin = 0
    win_fwd = 29200
    win_bwd = 235

    if label in ['BENIGN', 'Normal HTTP', 'Normal']:
        port = 443; dur = 348000; fwd = 11; bwd = 6; size = 220; syn = 1; ack = 6; psh = 2
        win_fwd = 29200; win_bwd = 65535
    elif 'DOS' in label.upper() or 'FLOOD' in label.upper() or label in ['SLOWLORIS', 'SLOWHTTPTEST', 'HTTP_FLOOD', 'TEARDROP', 'PING_OF_DEATH', 'LAND_ATTACK']:
        if label == 'TEARDROP':
            proto = 17; port = 0; dur = 400000; fwd = 200; bwd = 0; size = 40; psh = 0; win_fwd = -1; win_bwd = -1
        elif label == 'PING_OF_DEATH':
            proto = 1; port = 0; dur = 400000; fwd = 25; bwd = 0; size = 1600; psh = 0; win_fwd = -1; win_bwd = -1
        elif 'DDOS' in label.upper() or 'SYN_FLOOD' in label or 'UDP_FLOOD' in label or 'ICMP_FLOOD' in label or 'AMPLIFICATION' in label or 'SMURF' in label:
            port = 80; dur = 1293792; fwd = 3; bwd = 7; size = 20; psh = 1; win_fwd = 8192; win_bwd = 229
        else:
            # DoS Attack (matches realistic CICIDS2017 DoS)
            port = 80; dur = 1878; fwd = 3; bwd = 6; size = 382; psh = 1; win_fwd = 29200; win_bwd = 235
    elif 'SCAN' in label.upper():
        # PortScan (matches realistic CICIDS2017 PortScan)
        port = 445; dur = 5021059; fwd = 6; bwd = 5; size = 356; psh = 1; win_fwd = 29200; win_bwd = 243
    elif 'BRUTE' in label.upper() or 'PASSWORD' in label.upper() or 'CREDENTIAL' in label.upper():
        # Brute Force (matches realistic CICIDS2017 Brute Force)
        port = 22; dur = 5808851; fwd = 15; bwd = 18; size = 640; psh = 1; win_fwd = 29200; win_bwd = 257
    elif 'SQL' in label.upper() or 'XSS' in label.upper() or 'WEB' in label.upper() or 'INJECTION' in label.upper() or 'TRAVERSAL' in label.upper():
        # Web Attack (matches realistic CICIDS2017 Web Attack)
        port = 80; dur = 5088371; fwd = 4; bwd = 4; size = 358; psh = 1; win_fwd = 29200; win_bwd = 235
    elif 'BOT' in label.upper():
        port = 6667; dur = 1013034; fwd = 3; bwd = 3; size = 0; psh = 1; win_fwd = 8192; win_bwd = 0
    elif 'ZERO_DAY' in label.upper():
        port = 8088; dur = 501734; fwd = 1; bwd = 1; size = 1460; syn = 0; ack = 1; urg = 4; win_fwd = 8192; win_bwd = 0
    else:
        port = 80; dur = 500000; fwd = 5; bwd = 5; size = 300; psh = 1; win_fwd = 29200; win_bwd = 235

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

test_types = [
    'BENIGN',
    'HTTP_FLOOD',
    'SYN_FLOOD',
    'PORT_SCAN',
    'BRUTE_FORCE_SSH',
    'SQL_INJECTION',
    'BOTNET',
    'TEARDROP',
    'ZERO_DAY_EXPLOIT'
]

print(f"{'Attack':<18} | {'Engine Verdict':<16} | {'XGBoost':<14} | {'RF':<14} | {'ISO':<10} | {'Votes'}")
print("-" * 88)

for t in test_types:
    f = make_realistic_flow(t)
    res = e.predict(f)
    xgb = res["model_results"].get("xgb", {}).get("label", "N/A")
    rf = res["model_results"].get("rf", {}).get("label", "N/A")
    iso = res["model_results"].get("iso", {}).get("label", "N/A")
    votes = f"{res['ensemble_votes']['attack']}/{res['ensemble_votes']['total']}"
    print(f"{t:<18} | {res['attack_type']:<16} | {xgb:<14} | {rf:<14} | {iso:<10} | {votes}")
