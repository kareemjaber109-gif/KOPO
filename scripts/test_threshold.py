import json
from src.ml.detection_engine import DetectionEngine

eng = DetectionEngine()
eng.load()
tmpls = json.load(open('frontend/src/pages/attackTemplates.json'))

threshold = 0.85
print(f"{'Attack':15s} | {'Score':7s} | {'Status (t=0.85)':15s}")
print("-" * 45)
for k, v in tmpls.items():
    r = eng.predict(v)
    score = r.get('anomaly_score', 0)
    is_anom = score >= threshold
    status = "ANOMALY" if is_anom else "NORMAL"
    print(f"{k:15s} | {score*100:5.1f}% | {status:15s}")
