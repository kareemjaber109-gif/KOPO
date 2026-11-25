import json
from src.ml.detection_engine import DetectionEngine

eng = DetectionEngine()
eng.load()

vflows = json.load(open('data/models/verified_attack_flows.json'))
for k, feats in vflows.items():
    r = eng.predict(feats)
    rf = r['model_results']['rf']
    xgb = r['model_results']['xgb']
    lstm = r['model_results']['lstm']
    print(f"[{k:12s}] -> Verdict: {r['attack_type']:15s} (Cat: {r['attack_category']:15s}) Action: {r['action']:5s}")
    print(f"   RF: {rf['label']:12s} ({rf['confidence']*100:5.1f}%) | XGB: {xgb['label']:12s} ({xgb['confidence']*100:5.1f}%) | LSTM: {lstm['label']} ({lstm['confidence']*100:5.1f}%)")
