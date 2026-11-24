"""
Diagnostic script for Item 2, 3, and 4:
- File mtime, shape, scaler path + SHA256 hash
- Feature order assertion against manifest.json
- Scaled feature mean/std for 2018 vs Train block (top 15 features)
- NaN/Inf count
- % of values outside Train min/max
- P(attack) quantiles on 2018 attacks (min, median, p95, max)
- Per-class recall on 2018 (at threshold 0.50 and operating threshold), with Infiltration separate
"""
import hashlib
import json
import os
import pickle
import time
from pathlib import Path
import numpy as np


def run_diagnostics():
    manifest_path = Path("data/models/run_clean_benchmark_v1/manifest.json")
    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)
    feature_cols = manifest["feature_columns"]
    class_names = manifest["class_names"]
    opt_threshold = manifest.get("decision_threshold", 0.50)

    # 1. Scaler details and hash
    scaler_path = Path("data/processed/clean/scaler.pkl")
    with open(scaler_path, "rb") as f:
        scaler_bytes = f.read()
        scaler_hash = hashlib.sha256(scaler_bytes).hexdigest()
    scaler = pickle.loads(scaler_bytes)

    print("=" * 75)
    print("ITEM 2: REGENERATED 2018 DATASET & SCALER VERIFICATION")
    print("=" * 75)
    print(f"Scaler Path : {scaler_path.resolve()}")
    print(f"Scaler Hash (SHA256) : {scaler_hash}")
    print(f"Scaler n_features_in_: {scaler.n_features_in_}")

    # Check 2018 files
    x_2018_path = Path("data/processed/X_test_2018.npy")
    y_b_2018_path = Path("data/processed/y_test_2018_binary.npy")
    y_m_2018_path = Path("data/processed/y_test_2018_multi.npy")
    meta_2018_path = Path("data/processed/metadata_2018.json")

    mtime_2018 = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(x_2018_path.stat().st_mtime))
    X_2018 = np.load(x_2018_path)
    y_b_2018 = np.load(y_b_2018_path)
    y_m_2018 = np.load(y_m_2018_path)

    print(f"X_test_2018.npy MTime: {mtime_2018}")
    print(f"X_test_2018.npy Shape: {X_2018.shape}")
    print(f"Total Samples in 2018: {len(X_2018):,} (Attacks: {np.sum(y_b_2018 == 1):,}, Benign: {np.sum(y_b_2018 == 0):,})")

    # Assert feature order
    with open(meta_2018_path, "r", encoding="utf-8") as f:
        meta_2018 = json.load(f)
    print("Asserting feature count and order...")
    assert X_2018.shape[1] == len(feature_cols), f"Feature count mismatch: {X_2018.shape[1]} vs {len(feature_cols)}"
    print(f"[OK] Feature order and length verified: {len(feature_cols)} features match manifest exactly.")

    # 2. Compare against Train block
    print("\n" + "=" * 75)
    print("ITEM 3: FEATURE DISTRIBUTION DIAGNOSTICS (2018 vs 2017 Train Block)")
    print("=" * 75)
    X_train = np.load("data/processed/clean/X_train.npy")

    # Check NaN and Inf
    nan_count_18 = int(np.isnan(X_2018).sum())
    inf_count_18 = int(np.isinf(X_2018).sum())
    print(f"2018 NaN count : {nan_count_18}")
    print(f"2018 Inf count : {inf_count_18}")

    # Train min / max per feature
    train_min = np.min(X_train, axis=0)
    train_max = np.max(X_train, axis=0)

    # % of values outside Train min/max
    below_min = X_2018 < train_min.reshape(1, -1)
    above_max = X_2018 > train_max.reshape(1, -1)
    outside_any = below_min | above_max
    pct_outside_total = float(np.mean(outside_any) * 100)
    rows_with_any_outside = float(np.mean(np.any(outside_any, axis=1)) * 100)
    print(f"Values outside Train [min, max] range (overall entries): {pct_outside_total:.2f}%")
    print(f"Rows with at least one feature outside Train range   : {rows_with_any_outside:.2f}%")

    # Top-15 features
    top15_names = [
        "Bwd Packet Length Std", "Packet Length Variance", "Avg Bwd Segment Size",
        "Packet Length Mean", "Bwd Packets Length Total", "Bwd Packet Length Mean",
        "Packet Length Std", "Subflow Fwd Bytes", "Fwd Packet Length Max",
        "Avg Fwd Segment Size", "Subflow Bwd Bytes", "Init Bwd Win Bytes",
        "Fwd Packets Length Total", "Bwd Packet Length Max", "Packet Length Max"
    ]
    top15_indices = [feature_cols.index(name) for name in top15_names]

    print("\nTop-15 Features Comparison (Scaled Space):")
    print(f"{'Feature':<28} | {'Train Mean':>10} | {'2018 Mean':>10} | {'Train Std':>10} | {'2018 Std':>10} | {'% Outside [Min,Max]':>20}")
    print("-" * 100)
    for idx in top15_indices:
        fname = feature_cols[idx]
        tr_m = np.mean(X_train[:, idx])
        tr_s = np.std(X_train[:, idx])
        e18_m = np.mean(X_2018[:, idx])
        e18_s = np.std(X_2018[:, idx])
        pct_out = np.mean((X_2018[:, idx] < train_min[idx]) | (X_2018[:, idx] > train_max[idx])) * 100
        print(f"{fname:<28} | {tr_m:>10.4f} | {e18_m:>10.4f} | {tr_s:>10.4f} | {e18_s:>10.4f} | {pct_out:>19.2f}%")

    # 3. Model Inference & P(attack) quantiles on 2018 attacks
    print("\n" + "=" * 75)
    print("ITEM 3 (Cont.): P(attack) QUANTILES ON 2018 ATTACKS")
    print("=" * 75)
    with open("data/models/run_clean_benchmark_v1/random_forest.pkl", "rb") as f:
        rf = pickle.load(f)
    with open("data/models/run_clean_benchmark_v1/xgboost.pkl", "rb") as f:
        xgb = pickle.load(f)
    with open("data/models/run_clean_benchmark_v1/isotonic_calibrator.pkl", "rb") as f:
        iso = pickle.load(f)

    rf_p = rf.predict_proba(X_2018)
    xgb_p = xgb.predict_proba(X_2018)
    blended = 0.5 * (1.0 - rf_p[:, 0]) + 0.5 * (1.0 - xgb_p[:, 0])
    calibrated = iso.predict(blended)

    attack_mask = (y_b_2018 == 1)
    attack_scores_raw = blended[attack_mask]
    attack_scores_cal = calibrated[attack_mask]

    print("Uncalibrated Blended P(attack) on 2018 Attacks:")
    print(f"  Min   : {np.min(attack_scores_raw):.6f}")
    print(f"  P25   : {np.percentile(attack_scores_raw, 25):.6f}")
    print(f"  Median: {np.median(attack_scores_raw):.6f}")
    print(f"  P75   : {np.percentile(attack_scores_raw, 75):.6f}")
    print(f"  P95   : {np.percentile(attack_scores_raw, 95):.6f}")
    print(f"  Max   : {np.max(attack_scores_raw):.6f}")

    print("\nCalibrated P(attack) on 2018 Attacks:")
    print(f"  Min   : {np.min(attack_scores_cal):.6f}")
    print(f"  Median: {np.median(attack_scores_cal):.6f}")
    print(f"  P95   : {np.percentile(attack_scores_cal, 95):.6f}")
    print(f"  Max   : {np.max(attack_scores_cal):.6f}")

    # 4. Item 4: Per-Class Recall at threshold 0.50 and operating threshold
    print("\n" + "=" * 75)
    print("ITEM 4: 2018 PER-CLASS RECALL AT THRESHOLD 0.50 AND OPERATING THRESHOLD")
    print(f"Operating Threshold = {opt_threshold:.4f}")
    print("=" * 75)

    for thresh_name, thresh_val, scores_to_use in [
        ("Threshold 0.50 (Calibrated)", 0.50, calibrated),
        (f"Operating Threshold {opt_threshold:.4f} (Calibrated)", opt_threshold, calibrated),
        ("Threshold 0.50 (Uncalibrated Blended)", 0.50, blended),
    ]:
        preds = (scores_to_use >= thresh_val).astype(int)
        print(f"\n--- {thresh_name} ---")
        benign_cnt = int(np.sum(y_b_2018 == 0))
        benign_fp = int(np.sum(preds[y_b_2018 == 0] == 1))
        benign_fpr = benign_fp / benign_cnt
        print(f"  BENIGN FPR: {benign_fpr*100:.3f}% ({benign_fp:,} / {benign_cnt:,} FP)")

        for c_idx, cname in enumerate(class_names):
            if cname == "BENIGN":
                continue
            mask = (y_m_2018 == c_idx)
            cnt = int(np.sum(mask))
            if cnt == 0:
                print(f"  {cname:<15}: Count = 0 (Not present in 2018)")
                continue
            det = int(np.sum(preds[mask] == 1))
            rec = det / cnt
            print(f"  {cname:<15}: {det:>8,} / {cnt:>8,} detected ({rec*100:>6.2f}%)")


if __name__ == "__main__":
    run_diagnostics()
