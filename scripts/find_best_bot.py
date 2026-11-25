import sys
sys.path.insert(0, ".")
import numpy as np
import json
from src.ml.detection_engine import DetectionEngine

eng = DetectionEngine()
eng.load()

# 1. Extract Bot sample 8
y_test = np.load('data/processed/clean/y_test_multi.npy')
X_test = np.load('data/processed/clean/X_test.npy')
bot_idx = np.where(y_test == 1)[0]
scaler = eng.scaler
bot_raw = scaler.inverse_transform(X_test[bot_idx[8]:bot_idx[8]+1])[0]
bot_flow = dict(zip(eng.feature_cols, [float(x) for x in bot_raw]))
bot_flow['Destination Port'] = 6667
bot_flow['Protocol'] = 6.0

# Test Bot sample 8 with RF and XGB
r_bot = eng.predict(bot_flow)
print("Extracted Bot Sample 8:")
print("  RF:", r_bot['model_results']['rf'])
print("  XGB:", r_bot['model_results']['xgb'])
print("  AE Anom Score:", r_bot.get('anomaly_score'))
