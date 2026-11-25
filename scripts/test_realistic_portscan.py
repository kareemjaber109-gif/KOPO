import sys
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine
import numpy as np

e = DetectionEngine()
e.load()

# Test 1: PortScan with realistic features from CICIDS2017
# From inspect_portscan: Dur=656, FwdPkts=2, BwdPkts=1, FwdMax=6, SYN=0, ACK=0, WinFwd=1024, WinBwd=29200
portscan_flow = {
    "Protocol": 6,
    "Flow Duration": 656,
    "Total Fwd Packets": 2,
    "Total Backward Packets": 1,
    "Fwd Packets Length Total": 12,
    "Bwd Packets Length Total": 0,
    "Fwd Packet Length Max": 6,
    "Fwd Packet Length Min": 6,
    "Fwd Packet Length Mean": 6.0,
    "Fwd Packet Length Std": 0.0,
    "Bwd Packet Length Max": 0,
    "Bwd Packet Length Min": 0,
    "Bwd Packet Length Mean": 0.0,
    "Bwd Packet Length Std": 0.0,
    "Flow Bytes/s": 18292.68,
    "Flow Packets/s": 4573.17,
    "Flow IAT Mean": 328.0,
    "Flow IAT Std": 452.55,
    "Flow IAT Max": 648.0,
    "Flow IAT Min": 8.0,
    "Fwd IAT Total": 656,
    "Fwd IAT Mean": 656.0,
    "Fwd IAT Std": 0.0,
    "Fwd IAT Max": 656.0,
    "Fwd IAT Min": 656.0,
    "Bwd IAT Total": 0,
    "Bwd IAT Mean": 0.0,
    "Bwd IAT Std": 0.0,
    "Bwd IAT Max": 0.0,
    "Bwd IAT Min": 0.0,
    "Fwd PSH Flags": 0,
    "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0,
    "Bwd URG Flags": 0,
    "Fwd Header Length": 40,
    "Bwd Header Length": 20,
    "Fwd Packets/s": 3048.78,
    "Bwd Packets/s": 1524.39,
    "Packet Length Min": 0,
    "Packet Length Max": 6,
    "Packet Length Mean": 3.0,
    "Packet Length Std": 3.46,
    "Packet Length Variance": 12.0,
    "FIN Flag Count": 0,
    "SYN Flag Count": 0,
    "RST Flag Count": 0,
    "PSH Flag Count": 0,
    "ACK Flag Count": 0,
    "URG Flag Count": 0,
    "CWE Flag Count": 0,
    "ECE Flag Count": 0,
    "Down/Up Ratio": 0.5,
    "Avg Packet Size": 4.0,
    "Avg Fwd Segment Size": 6.0,
    "Avg Bwd Segment Size": 0.0,
    "Fwd Header Length.1": 40,
    "Subflow Fwd Packets": 2,
    "Subflow Fwd Bytes": 12,
    "Subflow Bwd Packets": 1,
    "Subflow Bwd Bytes": 0,
    "Init Fwd Win Bytes": 1024,
    "Init Bwd Win Bytes": 29200,
    "Fwd Act Data Packets": 1,
    "Fwd Seg Size Min": 20,
    "Active Mean": 0,
    "Active Std": 0,
    "Active Max": 0,
    "Active Min": 0,
    "Idle Mean": 0,
    "Idle Std": 0,
    "Idle Max": 0,
    "Idle Min": 0
}

res = e.predict(portscan_flow)
print("=== REALISTIC PORTSCAN PREDICTION ===")
print("attack_type:", res["attack_type"])
print("confidence:", res["confidence"])
print("votes:", res["ensemble_votes"])
for k, v in res["model_results"].items():
    print(f"  {k}: {v.get('label')} ({v.get('confidence', 0):.2f})")
