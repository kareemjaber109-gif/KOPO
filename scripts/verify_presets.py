import sys
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine
import json

e = DetectionEngine()
e.load()

with open("data/models/realistic_presets.json", "r") as f:
    presets = json.load(f)

print(f"{'Attack Name':<20} | {'Verdict':<15} | {'XGBoost Label':<18} | {'XGB Conf':<10} | {'RF Label':<15} | {'RF Conf'}")
print("-" * 95)

for name, flow in presets.items():
    res = e.predict(flow)
    xgb_res = res["model_results"].get("xgb", {})
    rf_res = res["model_results"].get("rf", {})
    print(f"{name:<20} | {res['attack_type']:<15} | {xgb_res.get('label'):<18} | {xgb_res.get('confidence', 0):<10.2f} | {rf_res.get('label'):<15} | {rf_res.get('confidence', 0):.2f}")
