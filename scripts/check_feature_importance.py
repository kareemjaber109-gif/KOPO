import sys
sys.path.insert(0, ".")
from src.ml.detection_engine import DetectionEngine
import numpy as np

e = DetectionEngine()
e.load()

# Let's see feature importances of XGBoost
xgb = e.xgb_model
rf = e.rf_model

if hasattr(xgb, "feature_importances_"):
    top_indices = np.argsort(xgb.feature_importances_)[::-1][:15]
    print("Top 15 most important features for XGBoost:")
    for idx in top_indices:
        print(f"  {idx:2d}: {e.feature_cols[idx]:<30} (importance: {xgb.feature_importances_[idx]:.4f})")

print("\nTop 15 most important features for Random Forest:")
if hasattr(rf, "feature_importances_"):
    top_indices_rf = np.argsort(rf.feature_importances_)[::-1][:15]
    for idx in top_indices_rf:
        print(f"  {idx:2d}: {e.feature_cols[idx]:<30} (importance: {rf.feature_importances_[idx]:.4f})")
