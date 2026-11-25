import sys
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine
import numpy as np

eng = DetectionEngine()
eng.load()

# Test benign flows from clean test set
y_test = np.load('data/processed/clean/y_test_multi.npy')
X_test = np.load('data/processed/clean/X_test.npy')

benign_indices = np.where(y_test == 0)[0][:50]
attack_indices = np.where(y_test > 0)[0][:50]

import json
vflows = json.load(open('data/models/verified_attack_flows.json'))

print("=== VERIFIED ATTACK FLOWS ANOMALY SCORES ===")
for k, v in vflows.items():
    r = eng.predict(v)
    anom_score = r.get('anomaly_score', 0)
    ae_p = r['model_results'].get('anomaly_ensemble', {}).get('autoencoder_percentile', 0)
    if_p = r['model_results'].get('anomaly_ensemble', {}).get('isolation_forest_percentile', 0)
    print(f"{k:15s} | Score: {anom_score*100:5.1f}% | AE_P: {ae_p*100:5.1f}% | IF_P: {if_p*100:5.1f}% | AnomLabel: {r['model_results'].get('anomaly_ensemble', {}).get('label')}")
