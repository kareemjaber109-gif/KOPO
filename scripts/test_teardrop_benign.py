import sys
sys.path.insert(0, ".")
import json
from src.ml.detection_engine import DetectionEngine

engine = DetectionEngine()
engine.load()

# Test TEARDROP flow from user screenshot
teardrop = {
    'Destination Port': 0,
    'Protocol': 17,
    'Flow Duration': 611169,
    'Total Fwd Packets': 320,
    'Total Backward Packets': 0,
    'Total Length of Fwd Packets': 8960,
    'Total Length of Bwd Packets': 0,
    'Fwd Packet Length Max': 28,
    'Fwd Packet Length Min': 5,
    'Fwd Packet Length Mean': 23.8,
    'Fwd Packet Length Std': 7.0,
    'Flow Bytes/s': 14660.41,
    'Flow Packets/s': 523.59,
    'Flow IAT Mean': 1915.89,
    'Flow IAT Std': 862.15,
    'Flow IAT Max': 4214.96,
    'Flow IAT Min': 95,
    'Fwd IAT Total': 611169,
    'Fwd IAT Mean': 1915.89,
    'Fwd IAT Std': 862.15,
    'Fwd IAT Max': 4214.96,
    'Fwd IAT Min': 95,
    'SYN Flag Count': 0,
    'ACK Flag Count': 0,
    'PSH Flag Count': 0
}

res = engine.predict(teardrop)
print("=== TEARDROP RESULT ===")
print("is_attack:", res["is_attack"])
print("attack_type:", res["attack_type"])
print("attack_category:", res["attack_category"])
print("confidence:", res["confidence"])
print("action:", res["action"])
print("votes:", res["ensemble_votes"])
for k, v in res["model_results"].items():
    print(f"  {k}: {v.get('label')} ({v.get('confidence', 0)})")

print("\n=== BENIGN FLOW TEST ===")
# Test realistic Benign flow from Detect.jsx
benign = {
    "Destination Port": 443,
    "Protocol": 6,
    "Flow Duration": 350000,
    "Total Fwd Packets": 10,
    "Total Backward Packets": 8,
    "Total Length of Fwd Packets": 650,
    "Total Length of Bwd Packets": 3200,
    "Fwd Packet Length Max": 220,
    "Fwd Packet Length Min": 0,
    "Fwd Packet Length Mean": 65.0,
    "Fwd Packet Length Std": 82.5,
    "Bwd Packet Length Max": 1400,
    "Bwd Packet Length Min": 0,
    "Bwd Packet Length Mean": 400.0,
    "Bwd Packet Length Std": 520.0,
    "Flow Bytes/s": 11000.0,
    "Flow Packets/s": 51.4,
    "Flow IAT Mean": 20588.0,
    "Flow IAT Std": 35000.0,
    "Flow IAT Max": 119400.0,
    "Flow IAT Min": 1,
    "Fwd IAT Total": 350000,
    "Fwd IAT Mean": 38888.0,
    "Fwd IAT Std": 44700.0,
    "Fwd IAT Max": 124400.0,
    "Fwd IAT Min": 24,
    "Bwd IAT Total": 262500,
    "Bwd IAT Mean": 37500.0,
    "Bwd IAT Std": 56250.0,
    "Bwd IAT Max": 150000.0,
    "Bwd IAT Min": 1,
    "Fwd PSH Flags": 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Bwd URG Flags": 0,
    "Fwd Header Length": 200,
    "Bwd Header Length": 160,
    "Fwd Packets/s": 28.57,
    "Bwd Packets/s": 22.86,
    "Min Packet Length": 0,
    "Max Packet Length": 1400,
    "Packet Length Mean": 213.88,
    "Packet Length Std": 412.0,
    "Packet Length Variance": 169744.0,
    "FIN Flag Count": 0,
    "SYN Flag Count": 1,
    "RST Flag Count": 0,
    "PSH Flag Count": 2,
    "ACK Flag Count": 8,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 0.8,
    "Average Packet Size": 213.9,
    "Avg Fwd Segment Size": 65.0,
    "Avg Bwd Segment Size": 400.0,
    "Fwd Header Length.1": 200,
    "Fwd Avg Bytes/Bulk": 0,
    "Fwd Avg Packets/Bulk": 0,
    "Fwd Avg Bulk Rate": 0,
    "Bwd Avg Bytes/Bulk": 0,
    "Bwd Avg Packets/Bulk": 0,
    "Bwd Avg Bulk Rate": 0,
    "Subflow Fwd Packets": 10,
    "Subflow Fwd Bytes": 650,
    "Subflow Bwd Packets": 8,
    "Subflow Bwd Bytes": 3200,
    "Init_Win_bytes_forward": 29200,
    "Init_Win_bytes_backward": 65535,
    "act_data_pkt_fwd": 4,
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

res2 = engine.predict(benign)
print("is_attack:", res2["is_attack"])
print("attack_type:", res2["attack_type"])
print("attack_category:", res2["attack_category"])
print("confidence:", res2["confidence"])
print("action:", res2["action"])
print("is_anomaly:", res2.get("is_anomaly"))
print("anomaly_score:", res2.get("anomaly_score"))
print("votes:", res2["ensemble_votes"])
for k, v in res2["model_results"].items():
    print(f"  {k}: {v.get('label')} ({v.get('confidence', 0)})")

from src.ml.detection_engine import ATTACK_CATEGORY_MAP

cases = [
    ('TEARDROP', {'Destination Port': 0, 'Protocol': 17, 'Total Fwd Packets': 320, 'Total Backward Packets': 0, 'Fwd Packet Length Max': 28}),
    ('PING_OF_DEATH', {'Destination Port': 0, 'Protocol': 1, 'Total Fwd Packets': 25, 'Total Backward Packets': 0, 'Fwd Packet Length Max': 1500}),
    ('LAND_ATTACK', {'Destination Port': 80, 'Protocol': 6, 'Total Fwd Packets': 20, 'Total Backward Packets': 0, 'SYN Flag Count': 20, 'ACK Flag Count': 0, 'Fwd Packet Length Max': 40}),
    ('SYN_FLOOD', {'Destination Port': 80, 'Protocol': 6, 'Total Fwd Packets': 2500, 'Total Backward Packets': 0, 'SYN Flag Count': 2500, 'ACK Flag Count': 0}),
    ('UDP_FLOOD', {'Destination Port': 80, 'Protocol': 17, 'Total Fwd Packets': 5000, 'Total Backward Packets': 0}),
    ('DNS_AMPLIFICATION', {'Destination Port': 53, 'Protocol': 17, 'Total Fwd Packets': 5000, 'Total Backward Packets': 0}),
    ('ICMP_FLOOD', {'Destination Port': 0, 'Protocol': 1, 'Total Fwd Packets': 2000, 'Total Backward Packets': 0}),
    ('HTTP_FLOOD', {'Destination Port': 80, 'Protocol': 6, 'Total Fwd Packets': 4000, 'Fwd Packet Length Max': 1460}),
    ('SLOWLORIS', {'Destination Port': 80, 'Protocol': 6, 'Flow Duration': 50000000, 'Fwd Packet Length Max': 5}),
    ('PORT_SCAN', {'Destination Port': 445, 'Protocol': 6, 'Total Fwd Packets': 2, 'Total Backward Packets': 0, 'SYN Flag Count': 1, 'ACK Flag Count': 0, 'Fwd Packet Length Max': 0}),
    ('SYN_SCAN', {'Destination Port': 80, 'Protocol': 6, 'Total Fwd Packets': 50, 'Total Backward Packets': 0, 'SYN Flag Count': 50, 'ACK Flag Count': 0, 'Fwd Packet Length Max': 0}),
    ('NULL_SCAN', {'Destination Port': 80, 'Protocol': 6, 'Total Fwd Packets': 20, 'Total Backward Packets': 0, 'SYN Flag Count': 0, 'ACK Flag Count': 0, 'FIN Flag Count': 0, 'Fwd Packet Length Max': 0}),
]

print("\n=== ALL ATTACK HEURISTIC CHECKS ===")
for name, flow in cases:
    inferred = engine._infer_attack_from_flow(flow)
    cat = ATTACK_CATEGORY_MAP.get(inferred, 'Unknown')
    match = 'OK' if inferred == name or name in inferred else 'MISMATCH'
    print(f"{name:<20} -> {inferred:<20} ({cat}) [{match}]")
