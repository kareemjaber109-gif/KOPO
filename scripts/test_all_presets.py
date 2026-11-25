import sys
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine
import json

engine = DetectionEngine()
engine.load()

with open("data/models/realistic_presets.json", "r") as f:
    presets = json.load(f)

print(f"{'Attack':<20} | {'Verdict':<18} | {'Category':<16} | {'XGB':<12} | {'RF':<12} | {'Votes'}")
print("-" * 95)

for name, features in presets.items():
    res = engine.predict(features)
    xgb_res = res["model_results"].get("xgb", {})
    rf_res = res["model_results"].get("rf", {})
    xgb_lbl = f"{xgb_res.get('label', 'N/A')} ({xgb_res.get('confidence', 0):.2f})"
    rf_lbl = f"{rf_res.get('label', 'N/A')} ({rf_res.get('confidence', 0):.2f})"
    votes = f"{res['ensemble_votes']['attack']}/{res['ensemble_votes']['total']}"
    print(f"{name:<20} | {res['attack_type']:<18} | {res['attack_category']:<16} | {xgb_lbl:<12} | {rf_lbl:<12} | {votes}")
