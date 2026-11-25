import sys
sys.path.insert(0, ".")
import numpy as np
import json
from src.ml.detection_engine import DetectionEngine

e = DetectionEngine()
e.load()

X_test = np.load("data/processed/clean/X_test.npy")
y_test = np.load("data/processed/clean/y_test_multi.npy")

# For each class, find samples where BOTH XGBoost and RF predict the true attack class with high confidence!
best_samples = {}

for cls_idx, cls_name in enumerate(e.class_names):
    matches = np.where(y_test == cls_idx)[0]
    print(f"\nSearching best sample for {cls_name} (total candidates: {len(matches)})...")
    
    best_idx = None
    best_score = -1.0
    
    # Check first 500 candidates
    for idx in matches[:500]:
        sample = X_test[idx]
        xgb_probs = e.xgb_model.predict_proba(sample.reshape(1, -1))[0]
        rf_probs = e.rf_model.predict_proba(sample.reshape(1, -1))[0]
        
        xgb_pred = np.argmax(xgb_probs)
        rf_pred = np.argmax(rf_probs)
        
        # We want xgb_pred == cls_idx
        if xgb_pred == cls_idx:
            score = float(xgb_probs[cls_idx]) + float(rf_probs[cls_idx])
            if score > best_score:
                best_score = score
                best_idx = idx
                if xgb_probs[cls_idx] > 0.95 and (cls_idx == 0 or rf_probs[cls_idx] > 0.5):
                    break
                    
    if best_idx is not None:
        raw_vals = e.scaler.inverse_transform(X_test[best_idx].reshape(1, -1))[0]
        # Map to 69 canonical feature dict
        feat_dict = {}
        for col_name, val in zip(e.feature_cols, raw_vals):
            feat_dict[col_name] = round(float(val), 2) if abs(val) < 1e7 else round(float(val))
        
        # Test back through engine.predict
        res = e.predict(feat_dict)
        xgb_l = res["model_results"]["xgb"]["label"]
        xgb_c = res["model_results"]["xgb"]["confidence"]
        rf_l = res["model_results"]["rf"]["label"]
        rf_c = res["model_results"]["rf"]["confidence"]
        
        print(f"  FOUND: True={cls_name} | XGB={xgb_l} ({xgb_c:.2f}) | RF={rf_l} ({rf_c:.2f}) | Verdict={res['attack_type']}")
        best_samples[cls_name] = feat_dict

with open("data/models/verified_attack_flows.json", "w") as f:
    json.dump(best_samples, f, indent=2)

print("\nSaved verified attack flows to data/models/verified_attack_flows.json")
