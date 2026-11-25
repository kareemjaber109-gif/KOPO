import sys
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine

e = DetectionEngine()
e.load()

# User's exact Zero-Day Exploit flow from image 1
flow = {
    'Destination Port': 8088,
    'Protocol': 6,
    'Flow Duration': 501734,
    'Total Fwd Packets': 1,
    'Total Backward Packets': 1,
    'Total Length of Fwd Packets': 1460,
    'Total Length of Bwd Packets': 1460,
    'Fwd Packet Length Max': 1460,
    'Fwd Packet Length Min': 292,
    'Fwd Packet Length Mean': 1241.0,
    'Fwd Packet Length Std': 365.0,
    'Bwd Packet Length Max': 1460,
    'Bwd Packet Length Min': 292,
    'Bwd Packet Length Mean': 1241.0,
    'Bwd Packet Length Std': 365.0,
    'Flow Bytes/s': 5820.0,
    'Flow Packets/s': 3.99,
    'Flow IAT Mean': 501734.0,
    'Flow IAT Std': 225780.3,
    'Flow IAT Max': 1103814.8,
    'Flow IAT Min': 25086,
    'Fwd IAT Total': 501734,
    'Fwd IAT Mean': 501734.0,
    'Fwd IAT Std': 225780.3,
    'Fwd IAT Max': 1103814.8,
    'Fwd IAT Min': 25086,
    'Bwd IAT Total': 501734,
    'Bwd IAT Mean': 501734.0,
    'Bwd IAT Std': 225780.3,
    'Bwd IAT Max': 1103814.8,
    'Bwd IAT Min': 25086,
    'Fwd PSH Flags': 1,
    'Bwd PSH Flags': 0,
    'Fwd URG Flags': 1,
    'Bwd URG Flags': 0,
    'Fwd Header Length': 20,
    'Bwd Header Length': 20,
    'Fwd Packets/s': 1.99,
    'Bwd Packets/s': 1.99,
    'Min Packet Length': 292,
    'Max Packet Length': 1460,
    'Packet Length Mean': 1241.0,
    'Packet Length Std': 408.8,
    'Packet Length Variance': 170528.0,
    'FIN Flag Count': 0,
    'SYN Flag Count': 0,
    'RST Flag Count': 0,
    'PSH Flag Count': 0,
    'ACK Flag Count': 1,
    'URG Flag Count': 4,
    'CWE Flag Count': 0,
    'ECE Flag Count': 0,
    'Down/Up Ratio': 1.0,
    'Average Packet Size': 1460.0,
    'Avg Fwd Segment Size': 1460.0,
    'Avg Bwd Segment Size': 1460.0,
    'Fwd Header Length.1': 20,
    'Subflow Fwd Packets': 1,
    'Subflow Fwd Bytes': 1460,
    'Subflow Bwd Packets': 1,
    'Subflow Bwd Bytes': 1460,
    'Init_Win_bytes_forward': 8192,
    'Init_Win_bytes_backward': 65535,
    'act_data_pkt_fwd': 1,
    'min_seg_size_forward': 20
}

res = e.predict(flow)
print("=== ZERO-DAY EXPLOIT PREDICTION ===")
print("is_attack:", res["is_attack"])
print("attack_type:", res["attack_type"])
print("attack_category:", res["attack_category"])
print("confidence:", res["confidence"])
print("action:", res["action"])
print("is_anomaly:", res["is_anomaly"])
print("anomaly_score:", res["anomaly_score"])
print("votes:", res["ensemble_votes"])
for k, v in res["model_results"].items():
    print(f"  {k}: {v.get('label')} ({v.get('confidence', 0)})")
