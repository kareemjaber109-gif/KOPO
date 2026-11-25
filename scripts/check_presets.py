import json
from src.ml.detection_engine import DetectionEngine

eng = DetectionEngine()
eng.load()
p = json.load(open('frontend/src/pages/presets.json'))
for k, v in p.items():
    res = eng.predict(v)
    xgb_l = res['model_results']['xgb']['label']
    xgb_c = res['model_results']['xgb']['confidence'] * 100
    rf_l = res['model_results']['rf']['label']
    rf_c = res['model_results']['rf']['confidence'] * 100
    lstm_l = res['model_results']['lstm']['label']
    print(f"{k:20s} | {res['attack_type']:15s} | XGB: {xgb_l} ({xgb_c:.1f}%) | RF: {rf_l} ({rf_c:.1f}%) | LSTM: {lstm_l}")
