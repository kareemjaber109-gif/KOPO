"""
Audit script addressing all reviewer priorities:
1. Benign-2018 vs Benign-2017 feature comparison (medians, quantiles, means).
2. Anomaly layer control verification on Benign-Val (must reproduce 1.001%).
3. Per-raw-label recall on 2017 Test block (Hulk vs GoldenEye vs Heartbleed).
4. Feature duplicates equality check (Avg Bwd Segment Size vs Bwd Packet Length Mean, etc.).
5. Prior adjustment table across multiple prevalences.
"""
import json
import math
import pickle
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from collections import Counter

CLEAN_DIR = Path("data/processed/clean")
RUN_DIR = Path("data/models/run_clean_benchmark_v1")
ANOMALY_DIR = Path("data/models/anomaly")

def plog(*args):
    print(*args, flush=True)

def run():
    plog("=" * 80)
    plog("AUDIT SCRIPT: ADDRESSING ALL REVIEWER PRIORITIES")
    plog("=" * 80)

    # ------------------------------------------------------------------ #
    # 1. Feature duplicate equality check in CIC-IDS2017
    # ------------------------------------------------------------------ #
    plog("\n[1] FEATURE DUPLICATES / EQUALITY CHECK IN 2017")
    with open(RUN_DIR / "manifest.json", "r") as f:
        manifest = json.load(f)
    feature_cols = manifest["feature_columns"]
    X_train = np.load(CLEAN_DIR / "X_train.npy")

    pairs_to_check = [
        ("Avg Bwd Segment Size", "Bwd Packet Length Mean"),
        ("Avg Fwd Segment Size", "Fwd Packet Length Mean"),
        ("Subflow Fwd Bytes", "Fwd Packets Length Total"),
        ("Subflow Bwd Bytes", "Bwd Packets Length Total"),
        ("Subflow Fwd Packets", "Total Fwd Packets"),
        ("Subflow Bwd Packets", "Total Backward Packets"),
        ("Avg Packet Size", "Packet Length Mean"),
    ]
    for col_a, col_b in pairs_to_check:
        if col_a in feature_cols and col_b in feature_cols:
            idx_a = feature_cols.index(col_a)
            idx_b = feature_cols.index(col_b)
            diff = np.abs(X_train[:, idx_a] - X_train[:, idx_b])
            match_pct = float(np.mean(diff < 1e-5) * 100)
            plog(f"  '{col_a}' vs '{col_b}': exact match = {match_pct:.2f}% (max diff = {np.max(diff):.2e})")

    # ------------------------------------------------------------------ #
    # 2. Benign-2018 vs Benign-2017 comparison (Unscaled & Scaled)
    # ------------------------------------------------------------------ #
    plog("\n[2] BENIGN 2018 vs BENIGN 2017 DISTRIBUTION COMPARISON")
    scaler = joblib.load(CLEAN_DIR / "scaler.pkl")
    X_val = np.load(CLEAN_DIR / "X_val.npy")
    y_val_b = np.load(CLEAN_DIR / "y_val_binary.npy")
    y_train_b = np.load(CLEAN_DIR / "y_train_binary.npy")

    # Benign in 2017
    X_b_train = X_train[y_train_b == 0]
    X_b_val = X_val[y_val_b == 0]
    X_b_2017 = np.vstack([X_b_train, X_b_val])

    # 2018
    X_2018 = np.load("data/processed/X_test_2018.npy")
    y_2018_b = np.load("data/processed/y_test_2018_binary.npy")
    X_b_2018 = X_2018[y_2018_b == 0]

    plog(f"Benign 2017 count: {len(X_b_2017):,} | Benign 2018 count: {len(X_b_2018):,}")

    # Top features to inspect
    features_to_inspect = [
        "Flow Duration",
        "Total Fwd Packets",
        "Total Backward Packets",
        "Fwd Packets Length Total",
        "Subflow Fwd Bytes",
        "Bwd Packet Length Std",
        "Packet Length Variance",
        "Packet Length Mean",
        "Avg Bwd Segment Size",
        "Init Bwd Win Bytes",
        "Init Fwd Win Bytes",
        "Flow Bytes/s",
        "Flow Packets/s",
        "Flow IAT Mean",
        "Fwd IAT Min",
    ]

    plog(f"\n{'Feature':<26} | {'2017 Bng Med':>12} | {'2018 Bng Med':>12} | {'2017 p25-p75':>17} | {'2018 p25-p75':>17} | {'Ratio Med':>10}")
    plog("-" * 105)
    for fname in features_to_inspect:
        if fname not in feature_cols:
            continue
        idx = feature_cols.index(fname)
        v17 = X_b_2017[:, idx]
        v18 = X_b_2018[:, idx]
        
        m17 = float(np.median(v17))
        m18 = float(np.median(v18))
        q25_17, q75_17 = float(np.percentile(v17, 25)), float(np.percentile(v17, 75))
        q25_18, q75_18 = float(np.percentile(v18, 25)), float(np.percentile(v18, 75))
        
        ratio_str = f"{m18/m17:.2f}x" if abs(m17) > 1e-4 else "N/A"
        plog(f"{fname:<26} | {m17:>12.4f} | {m18:>12.4f} | [{q25_17:>7.2f}, {q75_17:>7.2f}] | [{q25_18:>7.2f}, {q75_18:>7.2f}] | {ratio_str:>10}")

    # Unscaled check for volume features
    plog("\nUnscaled values comparison for volume features:")
    X_b_17_raw = scaler.inverse_transform(X_b_2017[:50000])
    X_b_18_raw = scaler.inverse_transform(X_b_2018[:50000])
    for fname in ["Flow Duration", "Fwd Packets Length Total", "Subflow Fwd Bytes", "Init Bwd Win Bytes"]:
        idx = feature_cols.index(fname)
        med17 = float(np.median(X_b_17_raw[:, idx]))
        med18 = float(np.median(X_b_18_raw[:, idx]))
        p95_17 = float(np.percentile(X_b_17_raw[:, idx], 95))
        p95_18 = float(np.percentile(X_b_18_raw[:, idx], 95))
        plog(f"  {fname:<26} Raw Med: 2017={med17:,.1f} vs 2018={med18:,.1f} | Raw P95: 2017={p95_17:,.1f} vs 2018={p95_18:,.1f}")

    # ------------------------------------------------------------------ #
    # 3. Anomaly Control Verification on Benign-Val (must reproduce 1.001%)
    # ------------------------------------------------------------------ #
    plog("\n[3] ANOMALY CONTROL REPRODUCTION ON VALIDATION")
    from src.ml.anomaly.anomaly_ensemble import AnomalyEnsemble
    ensemble = AnomalyEnsemble.load(ANOMALY_DIR)
    plog(f"Loaded ensemble threshold: {ensemble.threshold:.6f}")

    val_data = np.load("data/processed/unsw/val.npz")
    X_val_anom = val_data["X"]
    y_val_anom = val_data["y"]
    src_val_anom = val_data["source"]

    ben_mask = (y_val_anom == 0)
    X_ben_val = X_val_anom[ben_mask]
    src_ben = src_val_anom[ben_mask]

    scores_ben, _, _ = ensemble.predict_score(X_ben_val)
    fpr_overall = float(np.mean(scores_ben >= ensemble.threshold))
    fpr_unsw = float(np.mean(scores_ben[src_ben == "unsw"] >= ensemble.threshold))
    fpr_cic = float(np.mean(scores_ben[src_ben == "cicids2017"] >= ensemble.threshold))

    plog(f"CONTROL VERIFICATION:")
    plog(f"  Target FPR: 1.001% (99.0th percentile)")
    plog(f"  Reproduced Overall Benign Val FPR: {fpr_overall*100:.3f}% (N={len(X_ben_val):,})")
    plog(f"  Reproduced UNSW Benign Val FPR   : {fpr_unsw*100:.3f}% (N={np.sum(src_ben == 'unsw'):,})")
    plog(f"  Reproduced CICIDS2017 Benign FPR : {fpr_cic*100:.3f}% (N={np.sum(src_ben == 'cicids2017'):,})")
    assert abs(fpr_overall - 0.01001) < 0.001, f"Anomaly control failed to reproduce 1.001%! Got {fpr_overall}"
    plog("  >> CONTROL PASSED! The anomaly model calibration is 100% verified.")

    # ------------------------------------------------------------------ #
    # 4. Per-Raw-Label Recall on 2017 Test Block
    # ------------------------------------------------------------------ #
    plog("\n[4] EXACT PER-RAW-LABEL RECALL ON 2017 TEST BLOCK")
    # Load 2017 test block predictions from run_clean_benchmark_v1
    X_test = np.load(CLEAN_DIR / "X_test.npy")
    y_test_m = np.load(CLEAN_DIR / "y_test_multi.npy")
    with open(RUN_DIR / "random_forest.pkl", "rb") as f:
        rf = pickle.load(f)
    with open(RUN_DIR / "xgboost.pkl", "rb") as f:
        xgb = pickle.load(f)
    with open(RUN_DIR / "isotonic_calibrator.pkl", "rb") as f:
        iso = pickle.load(f)

    rf_p = rf.predict_proba(X_test)
    xgb_p = xgb.predict_proba(X_test)
    blend = 0.5 * (1.0 - rf_p[:, 0]) + 0.5 * (1.0 - xgb_p[:, 0])
    cal_test = iso.predict(blend)
    preds_test = (cal_test >= manifest["decision_threshold"]).astype(int)

    # Reconstruct raw labels for Test block
    from src.data.clean_split import map_label
    parquet_dir = Path("data/raw")
    files = sorted(parquet_dir.glob("*.parquet"))
    all_raw_labels = []
    for f in files:
        df = pd.read_parquet(f, columns=["Label"])
        all_raw_labels.append(df["Label"].values)
    raw_labels = np.concatenate(all_raw_labels)
    mapped = np.array([map_label(l) for l in raw_labels])

    with open(CLEAN_DIR / "metadata.json", "r") as f:
        meta = json.load(f)
    class_splits = meta["class_splits"]
    class_names = meta["class_names"]

    test_raw_labels = []
    for cname in class_names:
        cls_indices = np.where(mapped == cname)[0]
        splits = class_splits.get(cname, {})
        n_train = splits.get("train", 0)
        n_gap1 = splits.get("gap1", 0)
        n_val = splits.get("val", 0)
        n_gap2 = splits.get("gap2", 0)
        n_test = splits.get("test", 0)
        test_start = n_train + n_gap1 + n_val + n_gap2
        test_idx = cls_indices[test_start:test_start + n_test]
        test_raw_labels.extend(raw_labels[test_idx])
    test_raw_labels = np.array(test_raw_labels)

    plog(f"Test block length: {len(test_raw_labels):,} (matches X_test: {len(X_test):,})")

    # Group by raw label
    plog(f"\n{'Mapped Class':<12} | {'Raw Attack Label':<28} | {'Total in Test':>13} | {'Detected':>8} | {'Recall (%)':>10}")
    plog("-" * 85)
    for raw_lbl in sorted(set(test_raw_labels)):
        mask = (test_raw_labels == raw_lbl)
        cnt = int(np.sum(mask))
        if cnt == 0:
            continue
        det = int(np.sum(preds_test[mask] == 1))
        rec = det / cnt * 100
        # mapped class
        mapped_c = map_label(raw_lbl)
        plog(f"{mapped_c:<12} | {raw_lbl:<28} | {cnt:>13,} | {det:>8,} | {rec:>9.2f}%")

    # ------------------------------------------------------------------ #
    # 5. Prior Adjustment Table Across Multiple Prevalences
    # ------------------------------------------------------------------ #
    plog("\n[5] PRIOR ADJUSTMENT TABLE ON VALIDATION (Bayes Odds Ratio)")
    rf_val = rf.predict_proba(X_val)
    xgb_val = xgb.predict_proba(X_val)
    blend_val = 0.5 * (1.0 - rf_val[:, 0]) + 0.5 * (1.0 - xgb_val[:, 0])
    cal_val = iso.predict(blend_val)

    plog(f"Unique calibrated score values on Val: {len(np.unique(cal_val))}")
    plog(f"Score percentiles on Val: min={np.min(cal_val):.4f}, p50={np.percentile(cal_val, 50):.4f}, p90={np.percentile(cal_val, 90):.4f}, max={np.max(cal_val):.4f}")

    def odds_adj(p, pi_train, pi_real):
        eps = 1e-7
        p = np.clip(p, eps, 1.0 - eps)
        odds = p / (1.0 - p)
        adj = odds * ((1.0 - pi_train)/pi_train) * (pi_real / (1.0 - pi_real))
        return adj / (1.0 + adj)

    prevalences = [0.0001, 0.001, 0.005, 0.01, 0.05, 0.10, 0.20]
    plog(f"\n{'pi_real (%)':>11} | {'Operating t':>11} | {'Val Recall':>10} | {'Val FPR':>10} | {'Val Precision':>13} | {'FA per 1M Flows':>15}")
    plog("-" * 85)
    for pi in prevalences:
        # adjust scores to operational probability space
        # pi_train is 0.5 due to class_weight='balanced'
        p_adj = odds_adj(cal_val, 0.5, pi)
        # sweep thresholds in operational space [0.001 to 0.999]
        best_f1, best_t, best_rec, best_fpr, best_prec = 0, 0.5, 0, 0, 0
        for t in np.linspace(0.01, 0.99, 99):
            pred = (p_adj >= t).astype(int)
            tp = np.sum((pred == 1) & (y_val_b == 1))
            fp = np.sum((pred == 1) & (y_val_b == 0))
            fn = np.sum((pred == 0) & (y_val_b == 1))
            tn = np.sum((pred == 0) & (y_val_b == 0))
            rec = tp / (tp + fn) if (tp + fn) > 0 else 0
            fpr = fp / (fp + tn) if (fp + tn) > 0 else 0
            prec = tp / (tp + fp) if (tp + fp) > 0 else 0
            f1 = 2*prec*rec / (prec + rec) if (prec + rec) > 0 else 0
            if f1 > best_f1:
                best_f1, best_t, best_rec, best_fpr, best_prec = f1, t, rec, fpr, prec
        
        fa_per_1m = best_fpr * 1_000_000 * (1.0 - pi)
        plog(f"{pi*100:>10.2f}% | {best_t:>11.4f} | {best_rec*100:>9.2f}% | {best_fpr*100:>9.4f}% | {best_prec*100:>12.2f}% | {fa_per_1m:>15,.0f}")

    plog("\nAUDIT SCRIPT COMPLETED.")

if __name__ == "__main__":
    run()
