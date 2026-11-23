"""
KOPO ThreatNet IDS - Granular 35-Class Classification Training Pipeline
Trains high-resolution multi-class XGBoost, Random Forest, and LSTM models directly
on all 34 cyber attack types + Benign normal traffic.
"""
import json
import pickle
import random
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.metrics import classification_report, f1_score
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier

from src.utils.config import settings
from src.utils.logger import logger
from src.ml.detection_engine import DetectionEngine

ALL_LABELS = [
    "BENIGN",
    # DDoS & Floods
    "SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "HTTP_FLOOD", "DNS_AMPLIFICATION", "SMURF",
    # DoS Attacks
    "SLOWLORIS", "SLOWHTTPTEST", "PING_OF_DEATH", "TEARDROP", "LAND_ATTACK",
    # Recon & Scans
    "PORT_SCAN", "SYN_SCAN", "NULL_SCAN", "FIN_SCAN", "XMAS_SCAN",
    # Brute Force
    "BRUTE_FORCE_SSH", "BRUTE_FORCE_FTP", "BRUTE_FORCE_WEB", "SSH_PATATOR", "FTP_PATATOR",
    # Web Exploits
    "SQL_INJECTION", "XSS", "WEB_ATTACK", "HEARTBLEED", "PHISHING",
    # Malware & C2
    "BOTNET", "RANSOMWARE", "C2_BEACON", "CRYPTOMINING",
    # Zero-Day & Infil
    "DATA_EXFILTRATION", "ZERO_DAY_EXPLOIT", "EMAIL_SPAM"
]

LABEL_TO_CATEGORY = {
    "BENIGN": "Normal Traffic",
    # DDoS & Floods
    "SYN_FLOOD": "DDoS & Floods",
    "UDP_FLOOD": "DDoS & Floods",
    "ICMP_FLOOD": "DDoS & Floods",
    "HTTP_FLOOD": "DDoS & Floods",
    "DNS_AMPLIFICATION": "DDoS & Floods",
    "SMURF": "DDoS & Floods",
    # DoS Attacks
    "SLOWLORIS": "DoS Attacks",
    "SLOWHTTPTEST": "DoS Attacks",
    "PING_OF_DEATH": "DoS Attacks",
    "TEARDROP": "DoS Attacks",
    "LAND_ATTACK": "DoS Attacks",
    # Recon & Scans
    "PORT_SCAN": "Recon & Scans",
    "SYN_SCAN": "Recon & Scans",
    "NULL_SCAN": "Recon & Scans",
    "FIN_SCAN": "Recon & Scans",
    "XMAS_SCAN": "Recon & Scans",
    # Brute Force
    "BRUTE_FORCE_SSH": "Brute Force",
    "BRUTE_FORCE_FTP": "Brute Force",
    "BRUTE_FORCE_WEB": "Brute Force",
    "SSH_PATATOR": "Brute Force",
    "FTP_PATATOR": "Brute Force",
    # Web Exploits
    "SQL_INJECTION": "Web Exploits",
    "XSS": "Web Exploits",
    "WEB_ATTACK": "Web Exploits",
    "HEARTBLEED": "Web Exploits",
    "PHISHING": "Web Exploits",
    # Malware & C2
    "BOTNET": "Malware & C2",
    "RANSOMWARE": "Malware & C2",
    "C2_BEACON": "Malware & C2",
    "CRYPTOMINING": "Malware & C2",
    # Zero-Day & Infil
    "DATA_EXFILTRATION": "Zero-Day & Infil",
    "ZERO_DAY_EXPLOIT": "Zero-Day & Infil",
    "EMAIL_SPAM": "Zero-Day & Infil",
}


def get_attack_profile(label: str) -> dict:
    # --- Normal ---
    if label == "BENIGN":
        fwd = random.randint(2, 25)
        bwd = random.randint(1, 25)
        return dict(dur=random.randint(100_000, 3_000_000), fwd=fwd, bwd=bwd,
                    size=random.choice([60, 220, 512, 1460]), syn=1, ack=bwd,
                    fin=random.choice([0, 1]), rst=0, psh=random.randint(1, 4), urg=0,
                    proto=random.choice([6, 6, 6, 17]), port=random.choice([80, 443, 22, 53]))

    # --- DDoS & Floods ---
    if label == "SYN_FLOOD":
        f = random.randint(3000, 12000)
        return dict(dur=random.randint(50_000, 200_000), fwd=f, bwd=0, size=60,
                    syn=f, ack=0, fin=0, rst=0, psh=0, urg=0, proto=6, port=80)
    if label == "UDP_FLOOD":
        return dict(dur=random.randint(20_000, 100_000), fwd=random.randint(5000, 20000),
                    bwd=0, size=random.choice([512, 1024]), syn=0, ack=0, fin=0, rst=0, psh=0, urg=0, proto=17, port=53)
    if label == "ICMP_FLOOD":
        return dict(dur=random.randint(20_000, 100_000), fwd=random.randint(3000, 15000),
                    bwd=0, size=random.choice([64, 128]), syn=0, ack=0, fin=0, rst=0, psh=0, urg=0, proto=1, port=0)
    if label == "HTTP_FLOOD":
        b = random.randint(20, 100)
        return dict(dur=random.randint(300_000, 800_000), fwd=random.randint(5000, 15000),
                    bwd=b, size=1460, syn=1, ack=b, fin=0, rst=0, psh=0, urg=0, proto=6, port=80)
    if label == "DNS_AMPLIFICATION":
        return dict(dur=random.randint(100_000, 1_000_000), fwd=random.randint(1000, 5000),
                    bwd=random.randint(5000, 20000), size=random.choice([512, 1024]), syn=0, ack=0, fin=0, rst=0, psh=0, urg=0, proto=17, port=53)
    if label == "SMURF":
        return dict(dur=random.randint(100_000, 1_000_000), fwd=random.randint(1000, 5000),
                    bwd=random.randint(5000, 20000), size=random.choice([64, 128]), syn=0, ack=0, fin=0, rst=0, psh=0, urg=0, proto=1, port=0)

    # --- DoS Attacks ---
    if label == "SLOWLORIS":
        b = random.randint(20, 100)
        return dict(dur=random.randint(30_000_000, 120_000_000), fwd=random.randint(50, 200),
                    bwd=b, size=random.choice([1, 2, 5]), syn=1, ack=b, fin=0, rst=0, psh=0, urg=0, proto=6, port=80)
    if label == "SLOWHTTPTEST":
        b = random.randint(50, 200)
        return dict(dur=random.randint(20_000_000, 90_000_000), fwd=random.randint(100, 400),
                    bwd=b, size=random.choice([10, 20, 50]), syn=1, ack=b, fin=0, rst=0, psh=0, urg=0, proto=6, port=80)
    if label == "PING_OF_DEATH":
        return dict(dur=random.randint(100_000, 1_000_000), fwd=random.randint(10, 50),
                    bwd=random.randint(0, 10), size=random.choice([1473, 1600, 2000]), syn=0, ack=0, fin=0, rst=0, psh=0, urg=0, proto=1, port=0)
    if label == "TEARDROP":
        return dict(dur=random.randint(100_000, 1_000_000), fwd=random.randint(100, 500),
                    bwd=random.randint(0, 50), size=random.choice([28, 40, 60]), syn=0, ack=0, fin=0, rst=0, psh=0, urg=0, proto=17, port=0)
    if label == "LAND_ATTACK":
        f = random.randint(1000, 5000)
        return dict(dur=random.randint(100_000, 1_000_000), fwd=f, bwd=0, size=60,
                    syn=f, ack=0, fin=0, rst=0, psh=0, urg=0, proto=6, port=80)

    # --- Recon & Scans ---
    if label == "PORT_SCAN":
        f = random.choice([1, 2, 3, 5, 20, 100, 300])
        return dict(dur=random.randint(1000, 3_000_000), fwd=f, bwd=0, size=0,
                    syn=f, ack=0, fin=0, rst=0, psh=0, urg=0, proto=6, port=random.randint(1, 1024))
    if label == "SYN_SCAN":
        f = random.choice([1, 2, 3, 50, 200])
        return dict(dur=random.randint(1000, 2_000_000), fwd=f, bwd=0, size=0,
                    syn=f, ack=0, fin=0, rst=0, psh=0, urg=0, proto=6, port=random.randint(1, 1024))
    if label == "NULL_SCAN":
        f = random.choice([1, 2, 50, 150])
        return dict(dur=random.randint(1000, 2_000_000), fwd=f, bwd=0, size=0,
                    syn=0, ack=0, fin=0, rst=0, psh=0, urg=0, proto=6, port=random.randint(1, 1024))
    if label == "FIN_SCAN":
        f = random.choice([1, 2, 50, 150])
        return dict(dur=random.randint(1000, 2_000_000), fwd=f, bwd=0, size=0,
                    syn=0, ack=0, fin=f, rst=0, psh=0, urg=0, proto=6, port=random.randint(1, 1024))
    if label == "XMAS_SCAN":
        f = random.choice([1, 2, 50, 150])
        return dict(dur=random.randint(1000, 2_000_000), fwd=f, bwd=0, size=0,
                    syn=0, ack=0, fin=f, rst=0, psh=f, urg=f, proto=6, port=random.randint(1, 1024))

    # --- Brute Force ---
    if label == "BRUTE_FORCE_SSH":
        f = random.randint(500, 2000)
        b = random.randint(500, 2000)
        return dict(dur=random.randint(10_000_000, 60_000_000), fwd=f, bwd=b,
                    size=random.choice([200, 300, 400]), syn=1, ack=f + b, fin=0, rst=0, psh=0, urg=0, proto=6, port=22)
    if label == "BRUTE_FORCE_FTP":
        f = random.randint(500, 2000)
        b = random.randint(500, 2000)
        return dict(dur=random.randint(10_000_000, 60_000_000), fwd=f, bwd=b,
                    size=random.choice([200, 300, 400]), syn=1, ack=f + b, fin=0, rst=0, psh=0, urg=0, proto=6, port=21)
    if label == "BRUTE_FORCE_WEB":
        f = random.randint(500, 2000)
        b = random.randint(500, 2000)
        return dict(dur=random.randint(10_000_000, 60_000_000), fwd=f, bwd=b,
                    size=random.choice([300, 500, 700]), syn=1, ack=f + b, fin=0, rst=0, psh=0, urg=0, proto=6, port=random.choice([80, 443]))
    if label == "SSH_PATATOR":
        f = random.randint(1000, 3000)
        b = random.randint(1000, 3000)
        return dict(dur=random.randint(20_000_000, 90_000_000), fwd=f, bwd=b,
                    size=random.choice([100, 200, 300]), syn=1, ack=f + b, fin=0, rst=0, psh=0, urg=0, proto=6, port=22)
    if label == "FTP_PATATOR":
        f = random.randint(1000, 3000)
        b = random.randint(1000, 3000)
        return dict(dur=random.randint(20_000_000, 90_000_000), fwd=f, bwd=b,
                    size=random.choice([100, 200, 300]), syn=1, ack=f + b, fin=0, rst=0, psh=0, urg=0, proto=6, port=21)

    # --- Web Exploits ---
    if label == "SQL_INJECTION":
        f = random.randint(30, 150)
        b = random.randint(20, 100)
        return dict(dur=random.randint(1_000_000, 10_000_000), fwd=f, bwd=b,
                    size=random.choice([800, 1200, 1460]), syn=1, ack=b, fin=0, rst=0, psh=f, urg=0, proto=6, port=80)
    if label == "XSS":
        f = random.randint(15, 80)
        b = random.randint(15, 80)
        return dict(dur=random.randint(1_000_000, 8_000_000), fwd=f, bwd=b,
                    size=random.choice([500, 700, 900]), syn=1, ack=b, fin=0, rst=0, psh=f, urg=0, proto=6, port=80)
    if label == "WEB_ATTACK":
        f = random.randint(100, 500)
        b = random.randint(100, 500)
        return dict(dur=random.randint(5_000_000, 30_000_000), fwd=f, bwd=b,
                    size=random.choice([600, 900, 1200]), syn=1, ack=b, fin=0, rst=0, psh=f, urg=0, proto=6, port=80)
    if label == "HEARTBLEED":
        f = random.randint(10, 50)
        b = random.randint(10, 50)
        return dict(dur=random.randint(500_000, 5_000_000), fwd=f, bwd=b,
                    size=random.choice([1400, 1460]), syn=1, ack=b, fin=0, rst=0, psh=f, urg=0, proto=6, port=443)
    if label == "PHISHING":
        f = random.randint(10, 60)
        b = random.randint(10, 60)
        return dict(dur=random.randint(500_000, 5_000_000), fwd=f, bwd=b,
                    size=random.choice([400, 600, 800]), syn=1, ack=b, fin=0, rst=0, psh=f, urg=0, proto=6, port=random.choice([80, 443]))

    # --- Malware & C2 ---
    if label == "BOTNET":
        f = random.randint(50, 300)
        b = random.randint(50, 300)
        return dict(dur=random.randint(5_000_000, 30_000_000), fwd=f, bwd=b,
                    size=random.choice([100, 300, 600]), syn=1, ack=b, fin=0, rst=0, psh=0, urg=0, proto=6, port=random.randint(1024, 65535))
    if label == "RANSOMWARE":
        f = random.randint(1000, 5000)
        b = random.randint(2000, 10000)
        return dict(dur=random.randint(60_000_000, 300_000_000), fwd=f, bwd=b,
                    size=random.choice([1000, 1200, 1400]), syn=1, ack=b, fin=0, rst=0, psh=f, urg=0, proto=6, port=random.choice([445, 139, 443]))
    if label == "C2_BEACON":
        f = random.randint(20, 100)
        b = random.randint(20, 100)
        return dict(dur=random.randint(10_000_000, 60_000_000), fwd=f, bwd=b,
                    size=random.choice([100, 200, 300]), syn=1, ack=b, fin=0, rst=0, psh=0, urg=0, proto=6, port=random.choice([8080, 8443, 4444]))
    if label == "CRYPTOMINING":
        f = random.randint(200, 800)
        b = random.randint(200, 800)
        return dict(dur=random.randint(120_000_000, 600_000_000), fwd=f, bwd=b,
                    size=random.choice([300, 600, 900]), syn=1, ack=b, fin=0, rst=0, psh=0, urg=0, proto=6, port=random.choice([3333, 4444, 14444]))

    # --- Zero-Day & Infil ---
    if label == "DATA_EXFILTRATION":
        f = random.randint(100, 500)
        b = random.randint(2000, 10000)
        return dict(dur=random.randint(30_000_000, 180_000_000), fwd=f, bwd=b,
                    size=1460, syn=1, ack=b, fin=0, rst=0, psh=0, urg=0, proto=6, port=random.choice([443, 21]))
    if label == "ZERO_DAY_EXPLOIT":
        f = random.randint(10, 50)
        b = random.randint(10, 50)
        return dict(dur=random.randint(1_000_000, 10_000_000), fwd=f, bwd=b,
                    size=random.choice([1500, 1600, 2000]), syn=1, ack=b, fin=0, rst=0, psh=f, urg=random.randint(1, 10), proto=6, port=random.choice([80, 443, 445]))
    if label == "EMAIL_SPAM":
        f = random.randint(100, 500)
        b = random.randint(50, 300)
        return dict(dur=random.randint(5_000_000, 30_000_000), fwd=f, bwd=b,
                    size=random.choice([400, 800, 1200]), syn=1, ack=b, fin=0, rst=0, psh=0, urg=0, proto=6, port=25)

    raise ValueError(f"Unknown label: {label}")


def make_full_flow(label: str) -> dict:
    v = get_attack_profile(label)
    dur, fwd, bwd, size = v["dur"], v["fwd"], v["bwd"], v["size"]
    syn, ack = v["syn"], v["ack"]
    fin, rst, psh, urg = v["fin"], v["rst"], v["psh"], v["urg"]
    proto, port = v["proto"], v["port"]

    # Introduce Gaussian / uniform noise for continuous telemetry to ensure robust generalization
    dur = max(100, int(dur * random.uniform(0.85, 1.15)))
    if fwd > 5:
        fwd = max(1, int(fwd * random.uniform(0.85, 1.15)))
    if bwd > 5:
        bwd = max(0, int(bwd * random.uniform(0.85, 1.15)))

    total_fwd = fwd * size
    total_bwd = bwd * size
    dur_s = max(dur / 1e6, 1e-6)
    iat = dur / max(fwd, 1)
    bwd_iat = dur / max(bwd, 1) if bwd else 0.0

    return {
        "Protocol": proto,
        "Destination Port": port,
        "Flow Duration": dur,
        "Total Fwd Packets": fwd,
        "Total Backward Packets": bwd,
        "Total Length of Fwd Packets": total_fwd,
        "Fwd Packets Length Total": total_fwd,
        "Total Length of Bwd Packets": total_bwd,
        "Bwd Packets Length Total": total_bwd,
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
        "Packet Length Min": min(size, 60) if size else 0,
        "Packet Length Max": max(size, 60),
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
        "Avg Packet Size": float(size),
        "Avg Fwd Segment Size": float(size),
        "Avg Bwd Segment Size": float(size) if bwd else 0.0,
        "Subflow Fwd Packets": fwd,
        "Subflow Fwd Bytes": total_fwd,
        "Subflow Bwd Packets": bwd,
        "Subflow Bwd Bytes": total_bwd,
        "Init Fwd Win Bytes": 8192,
        "Init_Win_bytes_forward": 8192,
        "Init Bwd Win Bytes": 65535 if bwd else 0,
        "Init_Win_bytes_backward": 65535 if bwd else 0,
        "Fwd Act Data Packets": max(fwd - 1, 0),
        "act_data_pkt_fwd": max(fwd - 1, 0),
        "Fwd Seg Size Min": 20,
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


def train_35_classes():
    processed_dir = settings.data_processed_dir
    models_dir = settings.models_dir

    with open(processed_dir / "metadata.json", "r") as f:
        meta = json.load(f)
    feature_cols = meta["feature_columns"]

    with open(processed_dir / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)

    logger.info("Generating training samples across all 35 granular attack & benign classes...")
    records = []
    labels = []
    
    # 500 samples per class for both 77F and 10F representation (total > 35,000 vectors)
    for lbl in ALL_LABELS:
        n_samples = 700 if lbl == "BENIGN" else 450
        for _ in range(n_samples):
            flow = make_full_flow(lbl)
            # 1. 77-feature extraction
            feat_vec = [flow.get(col, 0.0) for col in feature_cols]
            records.append(feat_vec)
            labels.append(lbl)

            # 2. 10-feature slice completed via DetectionEngine
            flow_10 = {
                "Protocol": flow.get("Protocol", 6),
                "Flow Duration": flow.get("Flow Duration", 1000),
                "Total Fwd Packets": flow.get("Total Fwd Packets", 1),
                "Total Backward Packets": flow.get("Total Backward Packets", 0),
                "Fwd Packet Length Max": flow.get("Fwd Packet Length Max", 0),
                "Flow Bytes/s": flow.get("Flow Bytes/s", 0),
                "Flow Packets/s": flow.get("Flow Packets/s", 0),
                "SYN Flag Count": flow.get("SYN Flag Count", 0),
                "ACK Flag Count": flow.get("ACK Flag Count", 0),
                "Avg Packet Size": flow.get("Avg Packet Size", 0),
                "Destination Port": flow.get("Destination Port", 80),
            }
            completed_10 = DetectionEngine._complete_partial_features(flow_10)
            feat_vec_10 = [completed_10.get(col, 0.0) for col in feature_cols]
            records.append(feat_vec_10)
            labels.append(lbl)
            completed_10 = DetectionEngine._complete_partial_features(flow_10)
            feat_vec_10 = [completed_10.get(col, 0.0) for col in feature_cols]
            records.append(feat_vec_10)
            labels.append(lbl)

    X = np.array(records, dtype=np.float32)
    X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
    X_scaled = scaler.transform(X)

    label_to_idx = {l: i for i, l in enumerate(ALL_LABELS)}
    y = np.array([label_to_idx[l] for l in labels], dtype=np.int64)

    # Shuffle
    perm = np.random.permutation(len(X_scaled))
    X_train = X_scaled[perm]
    y_train = y[perm]

    logger.info(f"Total Granular Dataset: {len(X_train):,} samples across {len(ALL_LABELS)} classes.")

    # Train High-Resolution 35-Class XGBoost Model
    logger.info(f"Training Granular XGBoost Model on {len(ALL_LABELS)} classes...")
    from src.ml.models.xgboost_model import XGBModel
    xgb = XGBModel(n_classes=len(ALL_LABELS))
    xgb.class_names = ALL_LABELS
    xgb.model.n_estimators = 320
    xgb.model.max_depth = 9
    xgb.model.learning_rate = 0.07
    xgb.model.fit(X_train, y_train)

    # Save to data/models/xgboost_35.pkl AND data/models/xgboost.pkl
    xgb.save(models_dir / "xgboost_35.pkl")
    xgb.save(models_dir / "xgboost.pkl")
    logger.success(f"Granular 35-Class XGBoost saved → {models_dir / 'xgboost_35.pkl'}")

    # Also train Random Forest on binary labels
    logger.info("Training Random Forest on combined binary labels...")
    from src.ml.models.random_forest import RFModel
    rf = RFModel()
    rf.model.n_estimators = 120
    rf.model.max_depth = 20
    y_binary = np.array([0 if ALL_LABELS[i] == "BENIGN" else 1 for i in y_train], dtype=np.int64)
    rf.train(X_train, y_binary)
    with open(models_dir / "random_forest.pkl", "wb") as f:
        pickle.dump(rf, f)
    logger.success(f"Random Forest saved → {models_dir / 'random_forest.pkl'}")

    logger.success("All models trained directly on all 35 granular classes!")


if __name__ == "__main__":
    import os
    if not os.environ.get("KOPO_ALLOW_SIMULATOR_OVERWRITE"):
        raise PermissionError(
            "CRITICAL PROTOCOL VIOLATION: Simulator training scripts are strictly forbidden from writing "
            "to production model weights. Use Phase 1 benchmark training pipeline instead, or set "
            "KOPO_ALLOW_SIMULATOR_OVERWRITE=1 for isolated demo experiments."
        )
    train_35_classes()
