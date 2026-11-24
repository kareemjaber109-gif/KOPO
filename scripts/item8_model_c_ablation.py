"""
Item 8: Model C — Bwd-direction + Init Win Bytes ablation.
- Drop: all Bwd* features + Init Fwd Win Bytes + Init Bwd Win Bytes.
- Train Model C on same Train split.
- Grouped permutation importance on stratified Val sample.
- Compare Model A vs Model C on Val and 2018 (corrected).
"""
import json
import math
import pickle
import sys
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.metrics import f1_score
from sklearn.inspection import permutation_importance

def plog(*args):
    print(*args, flush=True)

CLEAN_DIR = Path("data/processed/clean")
RUN_DIR   = Path("data/models/run_clean_benchmark_v1")
OUT_DIR   = Path("data/models/run_model_c_ablation")
OUT_DIR.mkdir(parents=True, exist_ok=True)


def compute_binary_metrics(y_true, y_pred):
    tp = int(np.sum((y_pred == 1) & (y_true == 1)))
    fp = int(np.sum((y_pred == 1) & (y_true == 0)))
    fn = int(np.sum((y_pred == 0) & (y_true == 1)))
    tn = int(np.sum((y_pred == 0) & (y_true == 0)))
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    fpr    = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    prec   = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    f1_b   = 2*prec*recall / (prec+recall) if (prec+recall) > 0 else 0.0
    f1_mac = f1_score(y_true, y_pred, average="macro", zero_division=0)
    return {"recall": recall, "fpr": fpr, "precision": prec, "f1_binary": f1_b, "f1_macro": f1_mac}


def run():
    plog("=" * 75)
    plog("ITEM 8: MODEL C (BWD + INIT-WIN ABLATION) + PERMUTATION IMPORTANCE")
    plog("=" * 75)

    with open(RUN_DIR / "manifest.json", "r") as f:
        manifest = json.load(f)
    feature_cols = manifest["feature_columns"]
    class_names  = manifest["class_names"]
    opt_threshold = manifest.get("decision_threshold", 0.50)

    # Features to drop for Model C
    bwd_prefix = "Bwd"
    init_win_exact = {"Init Fwd Win Bytes", "Init Bwd Win Bytes"}
    drop_features = [f for f in feature_cols if f.startswith(bwd_prefix) or f in init_win_exact]
    keep_indices = [i for i, f in enumerate(feature_cols) if f not in set(drop_features)]
    keep_names   = [feature_cols[i] for i in keep_indices]

    plog(f"Total features Model A : {len(feature_cols)}")
    plog(f"Dropped for Model C    : {len(drop_features)}")
    for d in drop_features:
        plog(f"  - {d}")
    plog(f"Remaining for Model C  : {len(keep_names)} features")

    # Load data
    plog("\nLoading datasets...")
    X_train   = np.load(CLEAN_DIR / "X_train.npy")
    y_train_b = np.load(CLEAN_DIR / "y_train_binary.npy")
    y_train_m = np.load(CLEAN_DIR / "y_train_multi.npy")
    X_val     = np.load(CLEAN_DIR / "X_val.npy")
    y_val_b   = np.load(CLEAN_DIR / "y_val_binary.npy")
    y_val_m   = np.load(CLEAN_DIR / "y_val_multi.npy")

    X_train_C = X_train[:, keep_indices]
    X_val_C   = X_val[:, keep_indices]

    # Train Model C RF (optimized tree count for fast ablation)
    plog("\nTraining Model C (RF, 50 trees, max_depth=14) on reduced feature set...")
    rf_C = RandomForestClassifier(
        n_estimators=50, max_depth=14, min_samples_leaf=20,
        class_weight="balanced", n_jobs=2, random_state=42
    )
    rf_C.fit(X_train_C, y_train_m)
    plog("RF training complete.")

    # Train Model C XGB
    plog("Training Model C (XGB, 100 trees, hist) on reduced feature set...")
    n_classes = len(class_names)
    xgb_C = XGBClassifier(
        n_estimators=100, max_depth=6, learning_rate=0.1,
        subsample=0.8, colsample_bytree=0.8,
        objective="multi:softprob", num_class=n_classes,
        eval_metric="mlogloss", tree_method="hist",
        use_label_encoder=False, random_state=42, n_jobs=2
    )
    xgb_C.fit(X_train_C, y_train_m)
    plog("XGBoost training complete.")

    # Calibrate on Val
    plog("Calibrating Model C (Isotonic on Val)...")
    rf_val_p  = rf_C.predict_proba(X_val_C)
    xgb_val_p = xgb_C.predict_proba(X_val_C)
    blended_val_C = 0.5 * (1.0 - rf_val_p[:, 0]) + 0.5 * (1.0 - xgb_val_p[:, 0])
    iso_C = IsotonicRegression(out_of_bounds="clip")
    iso_C.fit(blended_val_C, y_val_b)
    cal_val_C = iso_C.predict(blended_val_C)
    pred_val_C = (cal_val_C >= opt_threshold).astype(int)

    # Load Model A for comparison
    with open(RUN_DIR / "random_forest.pkl", "rb") as f:
        rf_A = pickle.load(f)
    with open(RUN_DIR / "xgboost.pkl", "rb") as f:
        xgb_A = pickle.load(f)
    with open(RUN_DIR / "isotonic_calibrator.pkl", "rb") as f:
        iso_A = pickle.load(f)

    rf_val_pA  = rf_A.predict_proba(X_val)
    xgb_val_pA = xgb_A.predict_proba(X_val)
    blended_val_A = 0.5 * (1.0 - rf_val_pA[:, 0]) + 0.5 * (1.0 - xgb_val_pA[:, 0])
    cal_val_A = iso_A.predict(blended_val_A)
    pred_val_A = (cal_val_A >= opt_threshold).astype(int)

    # Compare on Val
    met_A_val = compute_binary_metrics(y_val_b, pred_val_A)
    met_C_val = compute_binary_metrics(y_val_b, pred_val_C)

    plog("\n--- VAL COMPARISON: Model A vs Model C ---")
    plog(f"{'Metric':<18} {'Model A':>12} {'Model C':>12} {'Diff (C-A)':>12}")
    plog("-" * 55)
    for key in ["recall", "fpr", "precision", "f1_binary", "f1_macro"]:
        a = met_A_val[key]
        c = met_C_val[key]
        plog(f"{key:<18} {a:>12.4f} {c:>12.4f} {c-a:>+12.4f}")

    # Compare on 2018
    x_2018 = Path("data/processed/X_test_2018.npy")
    met_A_18 = {}
    met_C_18 = {}
    if x_2018.exists():
        X_2018   = np.load(x_2018)
        y_2018_b = np.load("data/processed/y_test_2018_binary.npy")
        X_2018_C = X_2018[:, keep_indices]

        # Model A on 2018
        rf_p_A  = rf_A.predict_proba(X_2018)
        xgb_p_A = xgb_A.predict_proba(X_2018)
        blend_A = 0.5*(1.0 - rf_p_A[:,0]) + 0.5*(1.0 - xgb_p_A[:,0])
        cal_A   = iso_A.predict(blend_A)
        pred_A_2018 = (cal_A >= opt_threshold).astype(int)

        # Model C on 2018
        rf_p_C  = rf_C.predict_proba(X_2018_C)
        xgb_p_C = xgb_C.predict_proba(X_2018_C)
        blend_C = 0.5*(1.0 - rf_p_C[:,0]) + 0.5*(1.0 - xgb_p_C[:,0])
        cal_C   = iso_C.predict(blend_C)
        pred_C_2018 = (cal_C >= opt_threshold).astype(int)

        met_A_18 = compute_binary_metrics(y_2018_b, pred_A_2018)
        met_C_18 = compute_binary_metrics(y_2018_b, pred_C_2018)

        plog("\n--- 2018 COMPARISON: Model A vs Model C ---")
        plog(f"{'Metric':<18} {'Model A':>12} {'Model C':>12} {'Diff (C-A)':>12}")
        plog("-" * 55)
        for key in ["recall", "fpr", "precision", "f1_binary", "f1_macro"]:
            a = met_A_18[key]
            c = met_C_18[key]
            plog(f"{key:<18} {a:>12.4f} {c:>12.4f} {c-a:>+12.4f}")

    # Permutation Importance on Stratified Val Sample
    plog("\n--- GROUPED PERMUTATION IMPORTANCE (Model C, Val sample N=25,000, n_repeats=3) ---")
    np.random.seed(42)
    # Stratified sample: preserve minority classes
    attack_idx = np.where(y_val_b == 1)[0]
    benign_idx = np.where(y_val_b == 0)[0]
    sample_att = np.random.choice(attack_idx, size=min(10000, len(attack_idx)), replace=False)
    sample_ben = np.random.choice(benign_idx, size=min(15000, len(benign_idx)), replace=False)
    sub_idx = np.concatenate([sample_att, sample_ben])
    np.random.shuffle(sub_idx)

    X_val_sub = X_val_C[sub_idx]
    y_val_sub = y_val_m[sub_idx]

    plog(f"Running permutation importance on {len(sub_idx):,} flows...")
    perm_result = permutation_importance(
        rf_C, X_val_sub, y_val_sub, n_repeats=3, random_state=42, n_jobs=2,
        scoring="f1_macro"
    )
    sorted_idx = np.argsort(perm_result.importances_mean)[::-1]
    plog(f"\n{'Rank':<5} {'Feature':<35} {'Mean Importance':>18} {'Std':>8}")
    plog("-" * 70)
    for rank, idx in enumerate(sorted_idx[:20], 1):
        fname = keep_names[idx]
        mean  = perm_result.importances_mean[idx]
        std   = perm_result.importances_std[idx]
        plog(f"{rank:<5} {fname:<35} {mean:>18.6f} {std:>8.6f}")

    # Groups: Fwd-only, Packet/Length, Flow, Flags
    plog("\n--- GROUP IMPORTANCE SUMMARY ---")
    fwd_indices = [i for i, f in enumerate(keep_names) if f.startswith("Fwd")]
    pkt_indices = [i for i, f in enumerate(keep_names) if "Packet" in f or "Length" in f]
    flow_indices= [i for i, f in enumerate(keep_names) if "Flow" in f]
    flag_indices= [i for i, f in enumerate(keep_names) if "Flag" in f]
    for group_name, group_idx in [
        ("Fwd features",     fwd_indices),
        ("Packet/Length",    pkt_indices),
        ("Flow features",    flow_indices),
        ("Flags",            flag_indices),
    ]:
        if not group_idx:
            continue
        group_imp = perm_result.importances_mean[group_idx].sum()
        plog(f"  {group_name:<20}: total importance = {group_imp:.6f}")

    # Save Model C
    with open(OUT_DIR / "random_forest_C.pkl", "wb") as f:
        pickle.dump(rf_C, f)
    with open(OUT_DIR / "xgboost_C.pkl", "wb") as f:
        pickle.dump(xgb_C, f)
    with open(OUT_DIR / "isotonic_calibrator_C.pkl", "wb") as f:
        pickle.dump(iso_C, f)

    top_features = [{"rank": r+1, "feature": keep_names[idx], "importance": float(perm_result.importances_mean[idx])} for r, idx in enumerate(sorted_idx[:15])]

    model_c_manifest = {
        "run_id": "run_model_c_ablation",
        "data_origin": "real",
        "certified": False,
        "run_type": "ablation",
        "note": "Model C: Bwd features + Init Win Bytes removed",
        "dropped_features": drop_features,
        "n_features": len(keep_names),
        "feature_columns": keep_names,
        "val_metrics": met_C_val,
        "model_a_val_metrics": met_A_val,
        "external_2018_metrics": met_C_18,
        "top_features_perm_importance": top_features,
    }
    with open(OUT_DIR / "manifest.json", "w") as f:
        json.dump(model_c_manifest, f, indent=2)
    plog(f"\nModel C saved to {OUT_DIR}")
    plog("ITEM 8 COMPLETE.")


if __name__ == "__main__":
    run()
