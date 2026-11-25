import sys
sys.path.insert(0, ".")
import numpy as np
from src.ml.detection_engine import DetectionEngine

e = DetectionEngine()
e.load()

X_test = np.load("data/processed/clean/X_test.npy")
y_test = np.load("data/processed/clean/y_test_multi.npy")

portscan_indices = np.where(y_test == 6)[0][:10]
print(f"Found {len(portscan_indices)} PortScan samples.")

for idx in portscan_indices:
    unscaled = e.scaler.inverse_transform(X_test[idx].reshape(1, -1))[0]
    xgb_probs = e.xgb_model.predict_proba(X_test[idx].reshape(1, -1))[0]
    pred_idx = np.argmax(xgb_probs)
    print(f"PortScan {idx}: Pred={e.class_names[pred_idx]} ({xgb_probs[pred_idx]:.2f}) | Dur={unscaled[1]:.0f}, FwdPkts={unscaled[2]:.0f}, BwdPkts={unscaled[3]:.0f}, FwdMax={unscaled[6]:.0f}, SYN={unscaled[42]:.0f}, ACK={unscaled[45]:.0f}, WinFwd={unscaled[57]:.0f}, WinBwd={unscaled[58]:.0f}")
