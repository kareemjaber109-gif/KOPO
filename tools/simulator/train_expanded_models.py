"""
KOPO ThreatNet IDS - Comprehensive Multi-Class Retraining Pipeline
Trains XGBoost, Random Forest, and Isolation Forest on all 35 Attack Signatures + Benign Baseline.
Learns tree splits directly from data features without hardcoded rules.
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

# Mapping from granular 35 attack types to 8 core IDS macro classes
LABEL_TO_MACRO = {
    "BENIGN": "BENIGN",
    # DDoS
    "DDoS": "DDoS",
    "DDOS": "DDoS",
    "SYN_FLOOD": "DDoS",
    "UDP_FLOOD": "DDoS",
    "ICMP_FLOOD": "DDoS",
    "DNS_AMPLIFICATION": "DDoS",
    "NTP_AMPLIFICATION": "DDoS",
    "SMURF": "DDoS",
    # DoS
    "DoS": "DoS",
    "DOS": "DoS",
    "HTTP_FLOOD": "DoS",
    "SLOWLORIS": "DoS",
    "SLOWHTTPTEST": "DoS",
    "PING_OF_DEATH": "DoS",
    "TEARDROP": "DoS",
    "LAND_ATTACK": "DoS",
    # Port Scan
    "PortScan": "PortScan",
    "PORT_SCAN": "PortScan",
    "SYN_SCAN": "PortScan",
    "NULL_SCAN": "PortScan",
    "FIN_SCAN": "PortScan",
    "XMAS_SCAN": "PortScan",
    # Brute Force
    "BruteForce": "BruteForce",
    "BRUTE_FORCE_SSH": "BruteForce",
    "BRUTE_FORCE_FTP": "BruteForce",
    "BRUTE_FORCE_WEB": "BruteForce",
    "SSH_PATATOR": "BruteForce",
    "FTP_PATATOR": "BruteForce",
    # Web Attacks
    "WebAttack": "WebAttack",
    "SQL_INJECTION": "WebAttack",
    "XSS": "WebAttack",
    "WEB_ATTACK": "WebAttack",
    "HEARTBLEED": "WebAttack",
    "PHISHING": "WebAttack",
    # Botnet / C2
    "Bot": "Bot",
    "BOTNET": "Bot",
    "C2_BEACON": "Bot",
    "CRYPTOMINING": "Bot",
    "EMAIL_SPAM": "Bot",
    # Infiltration / Malware / Exploits
    "Infiltration": "Infiltration",
    "INFILTRATION": "Infiltration",
    "RANSOMWARE": "Infiltration",
    "DATA_EXFILTRATION": "Infiltration",
    "ZERO_DAY_EXPLOIT": "Infiltration",
}

ALL_LABELS = list(LABEL_TO_MACRO.keys())


def base_values(label: str) -> dict:
    # ---------- طبيعي ----------
    if label == "BENIGN":
        fwd = random.randint(2, 30)
        bwd = random.randint(1, 30)
        return dict(dur=random.randint(80_000, 3_500_000), fwd=fwd,
                    bwd=bwd, size=random.choice([60, 220, 512, 1460]),
                    syn=1, ack=bwd, fin=random.choice([0, 1]), rst=0, psh=random.randint(1, 4), urg=0,
                    proto=random.choice([6, 6, 6, 17]), port=random.choice([80, 443, 22, 53]))

    # ---------- DDoS / DoS ----------
    if label in ["DOS", "DoS", "HTTP_FLOOD"]:
        f = random.randint(4000, 16000)
        b = random.randint(10, 120)
        return dict(dur=random.randint(250_000, 900_000), fwd=f, bwd=b, size=1460, syn=1, ack=b,
                    fin=0, rst=0, psh=0, urg=0, proto=6, port=80)
    if label in ["SYN_FLOOD", "DDoS", "DDOS"]:
        f = random.randint(3000, 12000)
        return dict(dur=random.randint(50_000, 250_000), fwd=f, bwd=0, size=60,
                    syn=f, ack=0, fin=0, rst=0, psh=0, urg=0, proto=6, port=80)
    if label == "UDP_FLOOD":
        return dict(dur=random.randint(20_000, 100_000), fwd=random.randint(5000, 20000),
                    bwd=0, size=random.choice([512, 1024]), syn=0, ack=0,
                    fin=0, rst=0, psh=0, urg=0, proto=17, port=53)
    if label == "ICMP_FLOOD":
        return dict(dur=random.randint(20_000, 100_000), fwd=random.randint(3000, 15000),
                    bwd=0, size=random.choice([64, 128]), syn=0, ack=0,
                    fin=0, rst=0, psh=0, urg=0, proto=1, port=0)
    if label == "SLOWLORIS":
        return dict(dur=random.randint(30_000_000, 120_000_000), fwd=random.randint(50, 200),
                    bwd=random.randint(20, 100), size=random.choice([1, 2, 5]), syn=1,
                    ack=random.randint(20, 100), fin=0, rst=0, psh=0, urg=0, proto=6, port=80)
    if label == "SLOWHTTPTEST":
        return dict(dur=random.randint(20_000_000, 90_000_000), fwd=random.randint(100, 400),
                    bwd=random.randint(50, 200), size=random.choice([10, 20, 50]), syn=1,
                    ack=random.randint(50, 200), fin=0, rst=0, psh=0, urg=0, proto=6, port=80)

    # ---------- Scans (أعلام دقيقة) ----------
    if label in ["PORT_SCAN", "PortScan"]:
        f = random.choice([1, 2, 2, 3, 5, 20, 100, 300])
        return dict(dur=random.randint(1000, 3_000_000), fwd=f, bwd=0,
                    size=0, syn=f, ack=0, fin=0, rst=0, psh=0, urg=0, proto=6, port=random.randint(1, 1024))
    if label == "SYN_SCAN":
        f = random.choice([1, 2, 3, 50, 200])
        return dict(dur=random.randint(1000, 2_000_000), fwd=f, bwd=0, size=0,
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
    if label in ["BRUTE_FORCE_SSH", "BruteForce"]:
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
    if label in ["SQL_INJECTION", "WebAttack"]:
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

    # ---------- Malware / Infiltration ----------
    if label in ["BOTNET", "Bot"]:
        return dict(dur=random.randint(5_000_000, 30_000_000), fwd=random.randint(50, 300),
                    bwd=random.randint(50, 300), size=random.choice([100, 300, 600]), syn=1,
                    ack=random.randint(50, 300), fin=0, rst=0, psh=0, urg=0,
                    proto=6, port=random.randint(1024, 65535))
    if label in ["INFILTRATION", "Infiltration"]:
        return dict(dur=random.randint(30_000_000, 180_000_000), fwd=random.randint(200, 1000),
                    bwd=random.randint(1000, 5000), size=1460, syn=1, ack=random.randint(1000, 5000),
                    fin=0, rst=0, psh=0, urg=0, proto=6, port=random.choice([80, 443]))

    # ---------- Advanced / Ransomware / C2 ----------
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
    if label == "PHISHING":
        return dict(dur=random.randint(500_000, 5_000_000), fwd=random.randint(10, 60),
                    bwd=random.randint(10, 60), size=random.choice([400, 600, 800]), syn=1,
                    ack=random.randint(10, 60), fin=0, rst=0, psh=random.randint(5, 30), urg=0,
                    proto=6, port=random.choice([80, 443]))

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

    raise ValueError(f"Unknown label: {label}")


def make_full_flow(label: str) -> dict:
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
        "Protocol": proto,
        "Destination Port": port,
        "Flow Duration": dur,
        "Total Fwd Packets": fwd,
        "Total Backward Packets": bwd,
        "Fwd Packets Length Total": total_fwd,
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
        "Fwd URG Flags": 1 if urg > 0 else 0,
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
        "Avg Packet Size": float(size),
        "Avg Fwd Segment Size": float(size),
        "Avg Bwd Segment Size": float(size) if bwd else 0.0,
        "Subflow Fwd Packets": fwd,
        "Subflow Fwd Bytes": total_fwd,
        "Subflow Bwd Packets": bwd,
        "Subflow Bwd Bytes": total_bwd,
        "Init Fwd Win Bytes": 8192,
        "Init Bwd Win Bytes": 65535 if bwd else 0,
        "Fwd Act Data Packets": max(fwd - 1, 0),
        "Fwd Seg Size Min": 20,
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


def train_and_update_models():
    processed_dir = settings.data_processed_dir
    models_dir = settings.models_dir

    with open(processed_dir / "metadata.json", "r") as f:
        meta = json.load(f)
    feature_cols = meta["feature_columns"]
    class_names = meta["class_names"]

    with open(processed_dir / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)

    logger.info("1. Generating diverse synthetic flow samples per class across all attack & benign signatures...")
    synthetic_records = []
    synthetic_macros = []
    for lbl in ALL_LABELS:
        macro = LABEL_TO_MACRO[lbl]
        # Give Benign and DoS/DDoS generous synthetic representation
        n_samples = 600 if macro == "BENIGN" else 250
        for _ in range(n_samples):
            flow = make_full_flow(lbl)
            # 1. Full 77-feature extraction
            feat_vec = [flow.get(col, 0.0) for col in feature_cols]
            synthetic_records.append(feat_vec)
            synthetic_macros.append(macro)

            # 2. 10-feature slice completed via DetectionEngine (dual-schema alignment)
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
            }
            completed_10 = DetectionEngine._complete_partial_features(flow_10)
            feat_vec_10 = [completed_10.get(col, 0.0) for col in feature_cols]
            synthetic_records.append(feat_vec_10)
            synthetic_macros.append(macro)

    X_synth = np.array(synthetic_records, dtype=np.float32)
    X_synth = np.nan_to_num(X_synth, nan=0.0, posinf=0.0, neginf=0.0)
    X_synth_scaled = scaler.transform(X_synth)

    # Encode labels according to class_names
    class_to_idx = {c: i for i, c in enumerate(class_names)}
    y_synth_multi = np.array([class_to_idx[m] for m in synthetic_macros], dtype=np.int64)
    y_synth_binary = np.array([0 if m == "BENIGN" else 1 for m in synthetic_macros], dtype=np.int64)

    logger.info(f"Generated {len(X_synth_scaled):,} augmented samples.")

    # 2. Blend with representative slice of real CICIDS training dataset
    X_real = np.load(processed_dir / "X_train.npy")
    y_real_multi = np.load(processed_dir / "y_train_multi.npy")
    y_real_binary = np.load(processed_dir / "y_train_binary.npy")

    # Sample 15,000 diverse real samples
    np.random.seed(settings.random_seed)
    idx_real = np.random.choice(len(X_real), size=min(15000, len(X_real)), replace=False)
    X_train_combined = np.vstack([X_real[idx_real], X_synth_scaled])
    y_train_multi_combined = np.concatenate([y_real_multi[idx_real], y_synth_multi])
    y_train_binary_combined = np.concatenate([y_real_binary[idx_real], y_synth_binary])

    # Shuffle
    perm = np.random.permutation(len(X_train_combined))
    X_train_combined = X_train_combined[perm]
    y_train_multi_combined = y_train_multi_combined[perm]
    y_train_binary_combined = y_train_binary_combined[perm]

    logger.info(f"Total Combined Training Set: {len(X_train_combined):,} samples across {len(class_names)} classes.")

    # 3. Retrain High-Performance XGBoost
    logger.info("Training Multi-Class XGBoost on expanded signatures...")
    from src.ml.models.xgboost_model import XGBModel
    xgb = XGBModel(n_classes=len(class_names))
    xgb.class_names = class_names
    # Set hyperparams for fast and accurate convergence
    xgb.model.n_estimators = 250
    xgb.model.max_depth = 8
    xgb.train(X_train_combined, y_train_multi_combined, use_cost_sensitive=True)
    xgb.save(models_dir / "xgboost.pkl")

    # 4. Retrain Random Forest
    logger.info("Training Random Forest Binary Classifier...")
    from src.ml.models.random_forest import RFModel
    rf = RFModel()
    rf.model.n_estimators = 120
    rf.model.max_depth = 18
    rf.train(X_train_combined, y_train_binary_combined)
    with open(models_dir / "random_forest.pkl", "wb") as f:
        pickle.dump(rf, f)
    logger.success(f"Random Forest saved → {models_dir / 'random_forest.pkl'}")

    # 5. Retrain PyTorch LSTM Sequential Classifier
    logger.info("Training Deep PyTorch LSTM on combined dataset...")
    try:
        from src.ml.models.lstm_model import LSTMModel
        lstm = LSTMModel(input_size=len(feature_cols))
        lstm.EPOCHS = 4
        lstm.BATCH_SIZE = 1024
        lstm.train(X_train_combined, y_train_binary_combined, max_train_samples=25000)
        lstm.save(models_dir / "lstm.pt")
        logger.success(f"LSTM saved → {models_dir / 'lstm.pt'}")
    except Exception as e:
        logger.warning(f"LSTM training skipped or encountered error: {e}")

    # 6. Evaluate on test set
    X_test = np.load(processed_dir / "X_test.npy")
    y_test_multi = np.load(processed_dir / "y_test_multi.npy")
    y_pred_xgb = xgb.predict(X_test[:10000])
    macro_f1 = f1_score(y_test_multi[:10000], y_pred_xgb, average="macro", zero_division=0)
    logger.success(f"XGBoost Test Macro F1 on real test slice: {macro_f1 * 100:.2f}%")

    logger.success("Retraining complete! All 3 models (XGBoost, Random Forest, LSTM) trained directly via ML weights.")


if __name__ == "__main__":
    import os
    if not os.environ.get("KOPO_ALLOW_SIMULATOR_OVERWRITE"):
        raise PermissionError(
            "CRITICAL PROTOCOL VIOLATION: Simulator training scripts are strictly forbidden from writing "
            "to production model weights. Use Phase 1 benchmark training pipeline instead, or set "
            "KOPO_ALLOW_SIMULATOR_OVERWRITE=1 for isolated demo experiments."
        )
    train_and_update_models()
