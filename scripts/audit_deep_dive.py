"""
Audit Deep Dive:
1. Flow Duration medians (scaled vs raw) for 2017 Benign vs 2018 Benign.
2. Fraction of flows with sentinels: Fwd IAT Std = -0.5 in 2018, Flow IAT Min < 0 in 2017.
3. Top adversarial validation features and AUC after removing them.
"""
import json
import pickle
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedKFold, cross_val_score
from xgboost import XGBClassifier

def plog(*args):
    print(*args, flush=True)

def main():
    plog("=" * 80)
    plog("AUDIT DEEP DIVE: ITEMS 1 & 2")
    plog("=" * 80)

    clean_dir = Path("data/processed/clean")
    proc_dir = Path("data/processed")
    run_dir = Path("data/models/run_clean_benchmark_v1")

    with open(run_dir / "manifest.json", "r") as f:
        manifest = json.load(f)
    feature_cols = manifest["feature_columns"]

    with open(clean_dir / "scaler.pkl", "rb") as f:
        scaler = pickle.load(f)

    X_tr_17 = np.load(clean_dir / "X_train.npy")
    y_tr_b_17 = np.load(clean_dir / "y_train_binary.npy")
    b_17_scaled = X_tr_17[y_tr_b_17 == 0]

    X_18_scaled = np.load(proc_dir / "X_test_2018.npy")
    y_b_18 = np.load(proc_dir / "y_test_2018_binary.npy")
    b_18_scaled = X_18_scaled[y_b_18 == 0]

    fd_idx = feature_cols.index("Flow Duration")
    mean_fd = scaler.mean_[fd_idx]
    scale_fd = scaler.scale_[fd_idx]

    plog(f"Scaler statistics for 'Flow Duration' (index {fd_idx}):")
    plog(f"  Mean = {mean_fd:,.2f}, Scale (std) = {scale_fd:,.2f}")

    # Scaled medians
    s_med_17 = np.median(b_17_scaled[:, fd_idx])
    s_med_18 = np.median(b_18_scaled[:, fd_idx])
    plog(f"\nScaled Flow Duration Medians:")
    plog(f"  2017 Benign Scaled Median: {s_med_17:.6f}")
    plog(f"  2018 Benign Scaled Median: {s_med_18:.6f}")
    plog(f"  Scaled difference: {abs(s_med_17 - s_med_18):.6f}")

    # Raw medians
    # Recover raw values using inverse transform for Flow Duration column
    raw_fd_17 = b_17_scaled[:, fd_idx] * scale_fd + mean_fd
    raw_fd_18 = b_18_scaled[:, fd_idx] * scale_fd + mean_fd

    r_med_17 = np.median(raw_fd_17)
    r_med_18 = np.median(raw_fd_18)
    plog(f"\nRaw Flow Duration Medians:")
    plog(f"  2017 Benign Raw Median: {r_med_17:,.1f} us ({r_med_17/1e6:.4f} s)")
    plog(f"  2018 Benign Raw Median: {r_med_18:,.1f} us ({r_med_18/1e6:.4f} s)")
    plog(f"  Ratio (2017 / 2018): {r_med_17 / r_med_18:.2f}x")
    plog(f"  log1p difference: {np.log1p(r_med_17) - np.log1p(r_med_18):.4f}")

    plog(f"\nWhy did scaled medians look identical (-0.5307 vs -0.5313)?")
    plog(f"  Because scaler.scale_ is HUGE ({scale_fd:,.1f} us = {scale_fd/1e6:.2f} s) due to massive 120s outlier flows!")
    plog(f"  (302,377 - 18,170,000) / 33,600,000 = { (302377 - mean_fd) / scale_fd :.4f}")
    plog(f"  (36,077 - 18,170,000) / 33,600,000 = { (36077 - mean_fd) / scale_fd :.4f}")
    plog(f"  The difference of 266,300 us gets divided by ~33.6 million, collapsing to a negligible ~0.007 in z-score space!")
    plog(f"  CONCLUSION: Both tables were reporting real numbers from their respective spaces, BUT claiming 'identical preprocessing proves distribution identical' was completely fallacious! The standard scaler compressed a 10x physical gap into a 0.007 z-score rounding margin.")

    # ----------------------------------------------------------------------- #
    # Sentinel analysis
    # ----------------------------------------------------------------------- #
    plog("\n" + "=" * 80)
    plog("SENTINEL VALUE ANALYSIS")
    plog("=" * 80)

    # 1. Fwd IAT Std in 2018
    fwd_iat_std_idx = feature_cols.index("Fwd IAT Std")
    raw_fwd_iat_std_18 = b_18_scaled[:, fwd_iat_std_idx] * scaler.scale_[fwd_iat_std_idx] + scaler.mean_[fwd_iat_std_idx]
    raw_all_fwd_iat_std_18 = X_18_scaled[:, fwd_iat_std_idx] * scaler.scale_[fwd_iat_std_idx] + scaler.mean_[fwd_iat_std_idx]

    neg_05_benign = np.isclose(raw_fwd_iat_std_18, -0.5, atol=1e-2)
    neg_benign_18 = raw_fwd_iat_std_18 < 0
    neg_all_18 = raw_all_fwd_iat_std_18 < 0
    neg_05_all = np.isclose(raw_all_fwd_iat_std_18, -0.5, atol=1e-2)

    plog(f"Fwd IAT Std in 2018:")
    plog(f"  Benign flows with Fwd IAT Std == -0.5: {np.sum(neg_05_benign):,} / {len(b_18_scaled):,} ({np.mean(neg_05_benign)*100:.2f}%)")
    plog(f"  Benign flows with Fwd IAT Std < 0    : {np.sum(neg_benign_18):,} / {len(b_18_scaled):,} ({np.mean(neg_benign_18)*100:.2f}%)")
    plog(f"  ALL 2018 flows with Fwd IAT Std == -0.5: {np.sum(neg_05_all):,} / {len(X_18_scaled):,} ({np.mean(neg_05_all)*100:.2f}%)")
    plog(f"  ALL 2018 flows with Fwd IAT Std < 0    : {np.sum(neg_all_18):,} / {len(X_18_scaled):,} ({np.mean(neg_all_18)*100:.2f}%)")

    # 2. Flow IAT Min in 2017
    flow_iat_min_idx = feature_cols.index("Flow IAT Min")
    raw_flow_iat_min_17 = b_17_scaled[:, flow_iat_min_idx] * scaler.scale_[flow_iat_min_idx] + scaler.mean_[flow_iat_min_idx]
    raw_all_flow_iat_min_17 = X_tr_17[:, flow_iat_min_idx] * scaler.scale_[flow_iat_min_idx] + scaler.mean_[flow_iat_min_idx]

    neg_iat_min_b17 = raw_flow_iat_min_17 < 0
    neg_iat_min_all17 = raw_all_flow_iat_min_17 < 0
    plog(f"\nFlow IAT Min in 2017:")
    plog(f"  Benign Train flows with Flow IAT Min < 0: {np.sum(neg_iat_min_b17):,} / {len(b_17_scaled):,} ({np.mean(neg_iat_min_b17)*100:.2f}%)")
    plog(f"  ALL Train flows with Flow IAT Min < 0   : {np.sum(neg_iat_min_all17):,} / {len(X_tr_17):,} ({np.mean(neg_iat_min_all17)*100:.2f}%)")
    plog(f"  Min value of Flow IAT Min in 2017 Train: {np.min(raw_all_flow_iat_min_17):.1f} us")

    # Check 2018 Flow IAT Min for negatives
    raw_flow_iat_min_18 = b_18_scaled[:, flow_iat_min_idx] * scaler.scale_[flow_iat_min_idx] + scaler.mean_[flow_iat_min_idx]
    plog(f"  Benign 2018 flows with Flow IAT Min < 0: {np.sum(raw_flow_iat_min_18 < 0):,} ({np.mean(raw_flow_iat_min_18 < 0)*100:.2f}%)")

    # ----------------------------------------------------------------------- #
    # Top features in Adversarial Validation & Ablation AUC
    # ----------------------------------------------------------------------- #
    plog("\n" + "=" * 80)
    plog("ADVERSARIAL VALIDATION TOP FEATURES & ABLATION")
    plog("=" * 80)

    rng = np.random.default_rng(42)
    n_samp = 15000
    idx_17 = rng.choice(len(b_17_scaled), n_samp, replace=False)
    idx_18 = rng.choice(len(b_18_scaled), n_samp, replace=False)

    sub_17 = b_17_scaled[idx_17]
    sub_18 = b_18_scaled[idx_18]

    X_adv = np.vstack([sub_17, sub_18])
    y_adv = np.concatenate([np.zeros(n_samp), np.ones(n_samp)])

    clf = XGBClassifier(
        n_estimators=100, max_depth=4, learning_rate=0.1,
        tree_method="hist", random_state=42, n_jobs=2, eval_metric="logloss"
    )
    clf.fit(X_adv, y_adv)

    importances = clf.feature_importances_
    sorted_idx = np.argsort(importances)[::-1]

    plog("\nTop 15 Features Distinguishing 2017 Benign from 2018 Benign:")
    for rank, i in enumerate(sorted_idx[:15], 1):
        plog(f"  {rank:>2}. {feature_cols[i]:<28}: importance = {importances[i]:.4f}")

    # Ablation: Remove top 1, top 3, top 5, top 10 features and re-evaluate AUC
    cv = StratifiedKFold(n_splits=3, shuffle=True, random_state=42)
    for k in [1, 3, 5, 10, 15, 20]:
        drop_indices = sorted_idx[:k]
        keep_indices = [i for i in range(len(feature_cols)) if i not in drop_indices]
        X_sub = X_adv[:, keep_indices]
        scores = cross_val_score(clf, X_sub, y_adv, cv=cv, scoring="roc_auc")
        plog(f"  Ablation (Drop Top {k:>2} features, {len(keep_indices)} left): ROC-AUC = {np.mean(scores):.4f} (+/- {np.std(scores):.4f})")

if __name__ == "__main__":
    main()
