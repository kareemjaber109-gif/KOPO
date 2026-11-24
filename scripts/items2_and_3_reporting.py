"""
Items 2 & 3:
Item 2:
- Split Test recall into raw labels present in Train vs absent in Train
- Exact Hulk recall on Val vs Test
Item 3:
- Prior adjustment table with Bayes precision on TEST set at real operational pi
- Unrounded raw threshold vs probability space
- Sweep floor explanation
"""
import json
import pickle
import numpy as np
import pandas as pd
from pathlib import Path

def plog(*args):
    print(*args, flush=True)

CLEAN_DIR = Path("data/processed/clean")
RUN_DIR = Path("data/models/run_clean_benchmark_v1")

def run():
    plog("=" * 80)
    plog("ITEMS 2 & 3: RIGOROUS TEST REPORTING & BAYES PRIOR TABLE")
    plog("=" * 80)

    with open(RUN_DIR / "manifest.json", "r") as f:
        manifest = json.load(f)
    class_names = manifest["class_names"]
    opt_threshold = manifest.get("decision_threshold", 0.50)

    # Load models
    with open(RUN_DIR / "random_forest.pkl", "rb") as f:
        rf = pickle.load(f)
    with open(RUN_DIR / "xgboost.pkl", "rb") as f:
        xgb = pickle.load(f)
    with open(RUN_DIR / "isotonic_calibrator.pkl", "rb") as f:
        iso = pickle.load(f)

    # Load Val and Test
    X_val = np.load(CLEAN_DIR / "X_val.npy")
    y_val_b = np.load(CLEAN_DIR / "y_val_binary.npy")
    y_val_m = np.load(CLEAN_DIR / "y_val_multi.npy")

    X_test = np.load(CLEAN_DIR / "X_test.npy")
    y_test_b = np.load(CLEAN_DIR / "y_test_binary.npy")
    y_test_m = np.load(CLEAN_DIR / "y_test_multi.npy")

    # Predict Test
    rf_te = rf.predict_proba(X_test)
    xgb_te = xgb.predict_proba(X_test)
    blend_te = 0.5 * (1.0 - rf_te[:, 0]) + 0.5 * (1.0 - xgb_te[:, 0])
    cal_te = iso.predict(blend_te)
    pred_te = (cal_te >= opt_threshold).astype(int)

    # Predict Val
    rf_vl = rf.predict_proba(X_val)
    xgb_vl = xgb.predict_proba(X_val)
    blend_vl = 0.5 * (1.0 - rf_vl[:, 0]) + 0.5 * (1.0 - xgb_vl[:, 0])
    cal_vl = iso.predict(blend_vl)
    pred_vl = (cal_vl >= opt_threshold).astype(int)

    # ------------------------------------------------------------------ #
    # ITEM 2: Seen vs Unseen Attack Recall Split in Test Block
    # ------------------------------------------------------------------ #
    plog("\n" + "-" * 70)
    plog("ITEM 2: SEEN VS UNSEEN ATTACK RECALL SPLIT (2017 TEST BLOCK)")
    plog("-" * 70)

    # Reconstruct raw labels for Test
    from src.data.clean_split import map_label
    parquet_dir = Path("data/raw")
    files = sorted(parquet_dir.glob("*.parquet"))
    all_raw = []
    for f in files:
        df = pd.read_parquet(f, columns=["Label"])
        all_raw.append(df["Label"].values)
    raw_labels = np.concatenate(all_raw)
    mapped = np.array([map_label(l) for l in raw_labels])

    with open(CLEAN_DIR / "metadata.json", "r") as f:
        meta = json.load(f)
    class_splits = meta["class_splits"]

    test_raw_labels = []
    val_raw_labels = []
    for cname in class_names:
        cls_indices = np.where(mapped == cname)[0]
        sp = class_splits.get(cname, {})
        tr = sp.get("train", 0)
        g1 = sp.get("gap1", 0)
        vl = sp.get("val", 0)
        g2 = sp.get("gap2", 0)
        te = sp.get("test", 0)

        val_start = tr + g1
        test_start = val_start + vl + g2

        val_raw_labels.extend(raw_labels[cls_indices[val_start:val_start + vl]])
        test_raw_labels.extend(raw_labels[cls_indices[test_start:test_start + te]])

    test_raw_labels = np.array(test_raw_labels)
    val_raw_labels = np.array(val_raw_labels)

    # Hulk Recall on Val vs Test
    hulk_val_mask = (val_raw_labels == "DoS Hulk")
    hulk_val_cnt = int(np.sum(hulk_val_mask))
    hulk_val_det = int(np.sum(pred_vl[hulk_val_mask] == 1))
    hulk_val_rec = hulk_val_det / hulk_val_cnt if hulk_val_cnt > 0 else 0

    hulk_te_mask = (test_raw_labels == "DoS Hulk")
    hulk_te_cnt = int(np.sum(hulk_te_mask))
    hulk_te_det = int(np.sum(pred_te[hulk_te_mask] == 1))
    hulk_te_rec = hulk_te_det / hulk_te_cnt if hulk_te_cnt > 0 else 0

    plog(f"\nHulk Recall: Val vs Test Comparison:")
    plog(f"  Hulk in Val : {hulk_val_det:,} / {hulk_val_cnt:,} detected -> {hulk_val_rec*100:.2f}% recall (Missed: {hulk_val_cnt - hulk_val_det})")
    plog(f"  Hulk in Test: {hulk_te_det:,} / {hulk_te_cnt:,} detected -> {hulk_te_rec*100:.2f}% recall (Missed: {hulk_te_cnt - hulk_te_det})")
    plog(f"  Hulk Gap    : -{abs(hulk_val_rec - hulk_te_rec)*100:.2f}% drop between Val and Test for the EXACT same tool!")

    # Seen in Train vs Unseen in Train
    # Unseen in Train: DoS GoldenEye, Heartbleed, Web Attack Sql Injection
    unseen_labels = {"DoS GoldenEye", "Heartbleed", "Web Attack  Sql Injection"}
    
    seen_mask = np.isin(test_raw_labels, list(unseen_labels), invert=True) & (test_raw_labels != "Benign")
    unseen_mask = np.isin(test_raw_labels, list(unseen_labels))

    seen_cnt = int(np.sum(seen_mask))
    seen_det = int(np.sum(pred_te[seen_mask] == 1))
    seen_rec = seen_det / seen_cnt * 100

    unseen_cnt = int(np.sum(unseen_mask))
    unseen_det = int(np.sum(pred_te[unseen_mask] == 1))
    unseen_rec = unseen_det / unseen_cnt * 100

    plog(f"\nTest Block Recall Partitioned by Tool Presence in Training:")
    plog(f"  1. Tools Present in Train (Hulk, DDoS, SSH, Bot, XSS, PortScan):")
    plog(f"     {seen_det:,} / {seen_cnt:,} detected -> {seen_rec:.2f}% recall")
    plog(f"  2. Tools Absent in Train (GoldenEye, Heartbleed, SQL Injection):")
    plog(f"     {unseen_det:,} / {unseen_cnt:,} detected -> {unseen_rec:.2f}% recall")
    plog(f"  Overall Attack Test Recall: {seen_det + unseen_det:,} / {seen_cnt + unseen_cnt:,} -> {(seen_det + unseen_det)/(seen_cnt + unseen_cnt)*100:.2f}%")

    # ------------------------------------------------------------------ #
    # ITEM 3: Rigorous Bayes Prior Table on Test
    # ------------------------------------------------------------------ #
    plog("\n" + "-" * 70)
    plog("ITEM 3: RIGOROUS BAYES PRIOR ADJUSTMENT TABLE")
    plog("-" * 70)

    # Explanation of isotonic sweep floor:
    # Look at calibrated score values:
    cal_values = np.sort(np.unique(cal_vl))
    plog(f"Isotonic Calibrator steps on Val (unique output values):")
    plog(f"  {np.round(cal_values, 4)}")
    plog(f"  Lowest non-zero value: {cal_values[1]:.6f}")
    plog(f"  Is 0.0100 the sweep floor? The sweep started at 0.0100. Any threshold t in (0, {cal_values[1]:.4f}]")
    plog(f"  produces the exact same predictions because the step function has no intermediate values.")

    def odds_adj(p, pi_train, pi_real):
        eps = 1e-7
        p = np.clip(p, eps, 1.0 - eps)
        odds = p / (1.0 - p)
        factor = ((1.0 - pi_train)/pi_train) * (pi_real / (1.0 - pi_real))
        adj = odds * factor
        return adj / (1.0 + adj)

    # Prevalences requested (dropping 0.01% as noise)
    prevalences = [0.001, 0.005, 0.01, 0.05, 0.10]

    plog(f"\n{'pi_real (%)':>11} | {'Operating t (prob space)':>24} | {'Test Recall':>11} | {'Test FPR':>10} | {'Test Precision (Bayes)':>23} | {'FA per 1M Flows':>15}")
    plog("-" * 105)

    for pi in prevalences:
        # Determine operating threshold on Val using F1
        p_adj_vl = odds_adj(cal_vl, 0.5, pi)
        best_f1, best_t = 0, 0.5
        for t in np.linspace(0.001, 0.999, 999):
            p_bin = (p_adj_vl >= t).astype(int)
            tp = np.sum((p_bin == 1) & (y_val_b == 1))
            fp = np.sum((p_bin == 1) & (y_val_b == 0))
            fn = np.sum((p_bin == 0) & (y_val_b == 1))
            rec_v = tp / (tp + fn) if (tp + fn) > 0 else 0
            fpr_v = fp / (fp + np.sum(y_val_b == 0))
            prec_v = tp / (tp + fp) if (tp + fp) > 0 else 0
            f1_v = 2*prec_v*rec_v / (prec_v + rec_v) if (prec_v + rec_v) > 0 else 0
            if f1_v > best_f1:
                best_f1 = f1_v
                best_t = t

        # Apply that Val-selected operating threshold to TEST
        p_adj_te = odds_adj(cal_te, 0.5, pi)
        test_pred_adj = (p_adj_te >= best_t).astype(int)

        tp_te = int(np.sum((test_pred_adj == 1) & (y_test_b == 1)))
        fp_te = int(np.sum((test_pred_adj == 1) & (y_test_b == 0)))
        fn_te = int(np.sum((test_pred_adj == 0) & (y_test_b == 1)))
        tn_te = int(np.sum((test_pred_adj == 0) & (y_test_b == 0)))

        rec_te = tp_te / (tp_te + fn_te) if (tp_te + fn_te) > 0 else 0
        fpr_te = fp_te / (fp_te + tn_te) if (fp_te + tn_te) > 0 else 0

        # RIGOROUS BAYES PRECISION AT TRUE PREVALENCE:
        # P(Attack | Alert) = (Recall * pi) / (Recall * pi + FPR * (1 - pi))
        denom = (rec_te * pi) + (fpr_te * (1.0 - pi))
        bayes_precision = (rec_te * pi) / denom if denom > 0 else 0

        fa_per_1m = fpr_te * 1_000_000 * (1.0 - pi)

        plog(f"{pi*100:>10.2f}% | {best_t:>24.6f} | {rec_te*100:>10.2f}% | {fpr_te*100:>9.4f}% | {bayes_precision*100:>22.2f}% | {fa_per_1m:>15,.0f}")

    plog("\nITEMS 2 & 3 COMPLETED.")

if __name__ == "__main__":
    run()
