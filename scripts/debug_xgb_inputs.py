import sys
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine
import numpy as np

e = DetectionEngine()
e.load()

# Let's take the HTTP_FLOOD from test_all_subtypes
from scripts.test_all_subtypes import generate_attack_flow

flow = generate_attack_flow("HTTP_FLOOD")
arr = e._preprocess(flow)

print(f"Preprocessed arr shape: {arr.shape}")
print(f"Preprocessed arr min={arr.min():.2f}, max={arr.max():.2f}, mean={arr.mean():.2f}")

# XGBoost probabilities
probs = e.xgb_model.predict_proba(arr.reshape(1, -1))[0]
print("\nXGBoost probabilities for synthetic HTTP_FLOOD:")
for i, c in enumerate(e.class_names):
    print(f"  {c:<12}: {probs[i]:.4f}")

# Random Forest probabilities
rf_probs = e.rf_model.predict_proba(arr.reshape(1, -1))[0]
print("\nRandom Forest probabilities for synthetic HTTP_FLOOD:")
for i, c in enumerate(e.class_names):
    print(f"  {c:<12}: {rf_probs[i]:.4f}")

# Now let's compare with a REAL DoS sample from test set
X_test = np.load("data/processed/clean/X_test.npy")
y_test = np.load("data/processed/clean/y_test_multi.npy")

dos_idx = np.where(y_test == 4)[0][0]
real_dos_scaled = X_test[dos_idx]

probs_real = e.xgb_model.predict_proba(real_dos_scaled.reshape(1, -1))[0]
print("\nXGBoost probabilities for REAL DoS sample:")
for i, c in enumerate(e.class_names):
    print(f"  {c:<12}: {probs_real[i]:.4f}")

# Let's compare the top 10 features between synthetic HTTP_FLOOD and real DoS!
print("\nTop features comparison (Synthetic vs Real DoS [both scaled]):")
top_feats = [44, 37, 36, 6, 8, 22, 9, 51, 40, 23, 12, 7, 13, 3, 52]
for idx in top_feats:
    fname = e.feature_cols[idx]
    print(f"  [{idx:2d}] {fname:<25}: Synthetic={arr[idx]:8.3f} | Real DoS={real_dos_scaled[idx]:8.3f}")
