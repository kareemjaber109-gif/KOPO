import sys
sys.path.insert(0, ".")
import numpy as np
from src.ml.detection_engine import DetectionEngine
import joblib

e = DetectionEngine()
e.load()

X_test = np.load("data/processed/clean/X_test.npy")
y_test = np.load("data/processed/clean/y_test_multi.npy")

print(f"X_test shape: {X_test.shape}")
print(f"y_test shape: {y_test.shape}")

# Look at 1 sample from each class
for cls_idx in range(8):
    cls_name = e.class_names[cls_idx]
    matches = np.where(y_test == cls_idx)[0]
    if len(matches) == 0:
        continue
    idx = matches[0]
    sample = X_test[idx]
    
    rf_pred = e.rf_model.predict_single(sample)
    
    xgb_probs = e.xgb_model.predict_proba(sample.reshape(1, -1))[0]
    xgb_pred_idx = int(np.argmax(xgb_probs))
    xgb_label = e.class_names[xgb_pred_idx]
    xgb_conf = float(xgb_probs[xgb_pred_idx])
    
    print(f"Class {cls_idx:1d} ({cls_name:12s}): RF={rf_pred['label']:12s} ({rf_pred['confidence']:.2f}) | XGB={xgb_label:12s} ({xgb_conf:.2f})")
    
    # What are the unscaled values?
    unscaled = e.scaler.inverse_transform(sample.reshape(1, -1))[0]
    print(f"   Unscaled: FlowDur={unscaled[1]:.0f}, FwdPkts={unscaled[2]:.0f}, BwdPkts={unscaled[3]:.0f}, FwdLenTotal={unscaled[4]:.0f}, FwdMax={unscaled[6]:.0f}, SYN={unscaled[42]:.0f}, PSH={unscaled[44]:.0f}, ACK={unscaled[45]:.0f}, WinFwd={unscaled[57]:.0f}, WinBwd={unscaled[58]:.0f}")
