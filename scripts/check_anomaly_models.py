import json
from src.ml.detection_engine import DetectionEngine

eng = DetectionEngine()
eng.load()
tmpls = json.load(open('frontend/src/pages/attackTemplates.json'))

print(f"{'Attack':15s} | {'Score':7s} | {'is_anom':7s} | {'AE Label':10s} | {'ISO Label':10s} | {'RF Label':15s} | {'RF is_attack':12s}")
print("-" * 90)

for k, v in tmpls.items():
    r = eng.predict(v)
    models = r['model_results']
    ae = models.get('anomaly_ensemble', {})
    iso = models.get('iso', {})
    rf = models.get('rf', {})
    score = f"{r.get('anomaly_score', 0):.4f}"
    is_anom = str(r.get('is_anomaly', False))
    ae_label = str(ae.get('label', 'N/A'))
    iso_label = str(iso.get('label', 'N/A'))
    rf_label = str(rf.get('label', 'N/A'))
    rf_attack = str(rf.get('is_attack', False))
    print(f"{k:15s} | {score:7s} | {is_anom:7s} | {ae_label:10s} | {iso_label:10s} | {rf_label:15s} | {rf_attack:12s}")
