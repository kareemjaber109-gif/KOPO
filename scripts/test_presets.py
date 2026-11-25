import json
from src.ml.detection_engine import DetectionEngine

eng = DetectionEngine()
eng.load()
p = json.load(open('frontend/src/pages/presets.json'))
print("=== TESTING frontend/src/pages/presets.json ===")
for k, v in p.items():
    feats = v if isinstance(v, dict) else v.get('features', {})
    res = eng.predict(feats)
    models = res.get('models', {})
    rf = models.get('random_forest', {})
    xgb = models.get('xgboost', {})
    iso = models.get('isolation_forest', {})
    ae = models.get('autoencoder', {})
    print(f"[{k}] -> Verdict: {res.get('attack_type')} ({res.get('attack_category')}) | Action: {res.get('action')} | Votes: {res.get('votes')}")
    print(f"   RF: {rf.get('predicted_label')} ({rf.get('confidence', 0):.2f}) | XGB: {xgb.get('predicted_label')} ({xgb.get('confidence', 0):.2f}) | ISO: {iso.get('is_attack')} | AE: {ae.get('is_anomaly')}")

print("\n=== TESTING data/models/verified_attack_flows.json ===")
vflows = json.load(open('data/models/verified_attack_flows.json'))
for k, feats in vflows.items():
    res = eng.predict(feats)
    models = res.get('models', {})
    rf = models.get('random_forest', {})
    xgb = models.get('xgboost', {})
    iso = models.get('isolation_forest', {})
    ae = models.get('autoencoder', {})
    print(f"[{k}] -> Verdict: {res.get('attack_type')} ({res.get('attack_category')}) | Action: {res.get('action')} | Votes: {res.get('votes')}")
    print(f"   RF: {rf.get('predicted_label')} ({rf.get('confidence', 0):.2f}) | XGB: {xgb.get('predicted_label')} ({xgb.get('confidence', 0):.2f}) | ISO: {iso.get('is_attack')} | AE: {ae.get('is_anomaly')}")
