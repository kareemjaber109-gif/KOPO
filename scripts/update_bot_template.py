import sys
sys.path.insert(0, ".")
import json
from src.ml.detection_engine import DetectionEngine

# 1. Update verified_attack_flows with best bot sample
vflows = json.load(open('data/models/verified_attack_flows.json'))
import numpy as np
eng = DetectionEngine()
eng.load()

y_test = np.load('data/processed/clean/y_test_multi.npy')
X_test = np.load('data/processed/clean/X_test.npy')
bot_idx = np.where(y_test == 1)[0]
scaler = eng.scaler
bot_raw = scaler.inverse_transform(X_test[bot_idx[8]:bot_idx[8]+1])[0]
bot_flow = dict(zip(eng.feature_cols, [float(x) for x in bot_raw]))
bot_flow['Destination Port'] = 6667
bot_flow['Protocol'] = 6.0

vflows['Bot'] = bot_flow
with open('data/models/verified_attack_flows.json', 'w') as f:
    json.dump(vflows, f, indent=2)

print("Updated data/models/verified_attack_flows.json with Bot sample 8!")
