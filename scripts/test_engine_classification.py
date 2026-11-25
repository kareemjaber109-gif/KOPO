import sys
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import numpy as np
import pickle
import json
from src.utils.config import settings
from src.ml.detection_engine import DetectionEngine


def main():
    eng = DetectionEngine.get_instance()

    synthetic_tests = [
        ("SYN_FLOOD", {
            "Destination Port": 80, "Protocol": 6, "Flow Duration": 150000,
            "Total Fwd Packets": 3000, "Total Backward Packets": 0,
            "Fwd Packet Length Max": 0, "SYN Flag Count": 3000, "ACK Flag Count": 0,
            "Fwd Header Length": 60000, "Packet Length Mean": 0.0, "Flow Packets/s": 20000.0
        }),
        ("PORT_SCAN", {
            "Destination Port": 80, "Protocol": 6, "Flow Duration": 5000,
            "Total Fwd Packets": 1, "Total Backward Packets": 0,
            "Fwd Packet Length Max": 0, "SYN Flag Count": 1, "ACK Flag Count": 0,
            "Fwd Header Length": 20, "Packet Length Mean": 0.0, "Flow Packets/s": 200.0
        }),
        ("BRUTE_FORCE_SSH", {
            "Destination Port": 22, "Protocol": 6, "Flow Duration": 8000000,
            "Total Fwd Packets": 800, "Total Backward Packets": 400,
            "Fwd Packet Length Max": 320, "Fwd Packet Length Mean": 180,
            "SYN Flag Count": 1, "ACK Flag Count": 1200
        }),
        ("BENIGN", {
            "Destination Port": 443, "Protocol": 6, "Flow Duration": 250000,
            "Total Fwd Packets": 10, "Total Backward Packets": 8,
            "Fwd Packet Length Max": 250, "Fwd Packet Length Mean": 85.0, "Fwd Packet Length Std": 40.0,
            "Bwd Packet Length Max": 1400, "Bwd Packet Length Mean": 600.0, "Bwd Packet Length Std": 200.0,
            "SYN Flag Count": 1, "ACK Flag Count": 18
        }),
    ]

    print("=" * 80)
    print("TEST 2: SYNTHETIC ATTACK VECTORS")
    print("=" * 80)
    for name, flow in synthetic_tests:
        res = eng.predict(flow)
        rf_info = res["model_results"]["rf"]
        xgb_info = res["model_results"]["xgb"]
        print(f"[{name:<15}]")
        print(f"  RandomForest: {rf_info['label']:<12} (conf={rf_info['confidence']:.2f}, attack={rf_info['is_attack']})")
        print(f"  XGBoost     : {xgb_info['label']:<12} (conf={xgb_info['confidence']:.2f}, attack={xgb_info['is_attack']})")
        print(f"  Final Label : {res['attack_type']:<12} (Action={res['action']})")
        print("-" * 50)


if __name__ == "__main__":
    main()
