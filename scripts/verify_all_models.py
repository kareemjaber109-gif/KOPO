import json
from src.ml.detection_engine import DetectionEngine

engine = DetectionEngine.get_instance()

user_dos_10 = {
    'Protocol': 6,
    'Flow Duration': 500000,
    'Total Fwd Packets': 8000,
    'Total Backward Packets': 50,
    'Fwd Packet Length Max': 1460,
    'Flow Bytes/s': 23360000,
    'Flow Packets/s': 16100,
    'SYN Flag Count': 1,
    'ACK Flag Count': 50,
    'Avg Packet Size': 1460
}

res_u10 = engine.predict(user_dos_10)
print("=== USER DOS 10-FEATURE ===")
print("Verdict :", res_u10["attack_type"], f"({res_u10['confidence']*100:.1f}%)")
print("Severity:", res_u10["severity_label"], f"(Score: {res_u10['severity_score']}/5)")
print("Alert?  :", res_u10["should_alert"])
print("Breakdown:", {k: v.get("label") for k, v in res_u10["model_results"].items()})

print("\n=== ENTERPRISE PRESETS ===")
with open("frontend/src/pages/presets.json") as f:
    presets = json.load(f)

for p in ["Normal HTTP", "Port Scan", "DoS Attack", "DDoS Attack", "Brute Force", "Web Attack", "Abnormal (Zero-Day)"]:
    r = engine.predict(presets[p])
    at = r["attack_type"]
    cf = r["confidence"] * 100
    sev = r["severity_label"]
    anom = r.get("anomaly_score", 0) * 100
    print(f"{p:20s} -> Verdict: {at:12s} ({cf:5.1f}%) | Severity: {sev:8s} | Anomaly: {anom:5.1f}%")
