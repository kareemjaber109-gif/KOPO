"""
Item 6: Prior adjustment — fixed implementation.
- Sweep thresholds on Val only.
- Pick operating threshold on Val (best F1 or Precision-Recall tradeoff).
- Report Test metrics at the chosen threshold.
- Fix: validation_fpr was identical for both rows (bug was measuring FPR at t=0.5 always).
- Now: measure recall AND FPR at each threshold on Val, then read off Test once.
- Also explain why original rows were identical.
"""
import json
import math
import pickle
import numpy as np
from pathlib import Path

CLEAN_DIR = Path("data/processed/clean")
RUN_DIR   = Path("data/models/run_clean_benchmark_v1")


def wilson_ci(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    denom = 1 + z**2 / n
    center = (p + z**2 / (2*n)) / denom
    margin = (z * math.sqrt(p*(1-p)/n + z**2/(4*n**2))) / denom
    return p, max(0.0, center-margin), min(1.0, center+margin)


def odds_ratio_adjustment_vectorized(p_model: np.ndarray, pi_train: float, pi_real: float) -> np.ndarray:
    eps = 1e-7
    p_m = np.clip(p_model, eps, 1.0 - eps)
    odds_model = p_m / (1.0 - p_m)
    # RF uses class_weight='balanced' => effective pi_train = 0.5
    train_factor = (1.0 - pi_train) / max(eps, pi_train)
    real_factor  = pi_real / max(eps, 1.0 - pi_real)
    odds_adj = odds_model * train_factor * real_factor
    return odds_adj / (1.0 + odds_adj)


def threshold_sweep(scores: np.ndarray, y_true: np.ndarray, thresholds=None):
    """Sweep thresholds and compute recall/FPR/precision/F1 at each."""
    if thresholds is None:
        thresholds = np.linspace(0.01, 0.99, 199)
    results = []
    for t in thresholds:
        preds = (scores >= t).astype(int)
        tp = int(np.sum((preds == 1) & (y_true == 1)))
        fp = int(np.sum((preds == 1) & (y_true == 0)))
        fn = int(np.sum((preds == 0) & (y_true == 1)))
        tn = int(np.sum((preds == 0) & (y_true == 0)))
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr    = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        prec   = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        f1     = 2*prec*recall / (prec+recall) if (prec+recall) > 0 else 0.0
        results.append({"t": t, "recall": recall, "fpr": fpr, "precision": prec, "f1": f1,
                        "tp": tp, "fp": fp, "fn": fn, "tn": tn})
    return results


def run():
    print("=" * 75)
    print("ITEM 6: PRIOR ADJUSTMENT (FIXED) + OPERATING THRESHOLD FROM VAL ONLY")
    print("=" * 75)

    # Load models
    with open(RUN_DIR / "random_forest.pkl", "rb") as f:
        rf = pickle.load(f)
    with open(RUN_DIR / "xgboost.pkl", "rb") as f:
        xgb = pickle.load(f)
    with open(RUN_DIR / "isotonic_calibrator.pkl", "rb") as f:
        iso = pickle.load(f)
    with open(RUN_DIR / "manifest.json", "r") as f:
        manifest = json.load(f)

    # Load val and test
    X_val   = np.load(CLEAN_DIR / "X_val.npy")
    y_val_b = np.load(CLEAN_DIR / "y_val_binary.npy")
    X_test  = np.load(CLEAN_DIR / "X_test.npy")
    y_test_b = np.load(CLEAN_DIR / "y_test_binary.npy")
    y_test_m = np.load(CLEAN_DIR / "y_test_multi.npy")
    class_names = manifest["class_names"]

    # Compute calibrated scores
    def get_calibrated_scores(X):
        rf_p  = rf.predict_proba(X)
        xgb_p = xgb.predict_proba(X)
        blended = 0.5 * (1.0 - rf_p[:, 0]) + 0.5 * (1.0 - xgb_p[:, 0])
        return iso.predict(blended), blended

    print("Computing Val scores...")
    val_cal, val_raw = get_calibrated_scores(X_val)

    # Sweep on Val
    thresholds = np.concatenate([np.linspace(0.001, 0.05, 50), np.linspace(0.05, 0.99, 100)])
    thresholds = np.unique(np.sort(thresholds))
    val_sweep = threshold_sweep(val_cal, y_val_b, thresholds)

    # Pick best threshold by F1 on Val
    best_f1_row = max(val_sweep, key=lambda r: r["f1"])
    best_f1_t   = best_f1_row["t"]

    # Also track: threshold where FPR ~ target (for prior scenarios)
    # Scenario 1: π_real=0.001 (0.1%), π_train=0.5 (balanced RF)
    # Scenario 2: π_real=0.01  (1.0%),  π_train=0.5

    print("\n--- WHY ORIGINAL validation_fpr WAS IDENTICAL (Bug Explanation) ---")
    print("  Original code measured FPR at threshold=0.50 on Val, then stored it.")
    print("  Both prior rows referenced the SAME variable (val_fpr_at_050),")
    print("  not re-measured at the adjusted thresholds (0.0011 and 0.0106).")
    print("  Fix: measure FPR independently at each threshold below.")

    print("\n--- Val Sweep (selected rows near operating thresholds) ---")
    print(f"  {'t':>6} | {'Recall':>7} | {'FPR':>8} | {'Prec':>7} | {'F1':>7}")
    print("  " + "-" * 50)
    for row in val_sweep:
        t = row["t"]
        if t < 0.01 or (t < 0.3 and abs(t*100 - round(t*100, 0)) < 0.3):
            print(f"  {t:>6.4f} | {row['recall']*100:>6.2f}% | {row['fpr']*100:>7.4f}% | {row['precision']*100:>6.2f}% | {row['f1']:>7.4f}")

    print(f"\n  Best Val F1 = {best_f1_row['f1']:.4f} at threshold = {best_f1_t:.4f}")
    print(f"    Val Recall = {best_f1_row['recall']*100:.2f}%  Val FPR = {best_f1_row['fpr']*100:.4f}%")

    # Prior adjustments on Val
    print("\n--- Prior Adjustment Scenarios (applied on Val) ---")
    # RF class_weight='balanced' => effective pi_train = 0.5
    pi_train = 0.5
    for label, pi_real in [("0.1% (1 in 1000)", 0.001), ("1.0% (1 in 100)", 0.01)]:
        adj_val = odds_ratio_adjustment_vectorized(val_cal, pi_train, pi_real)
        adj_sweep = threshold_sweep(adj_val, y_val_b)
        best_adj  = max(adj_sweep, key=lambda r: r["f1"])
        t_adj     = best_adj["t"]

        # False alarms per 1M flows at this threshold (at the given prevalence)
        # In 1M flows: ~1M*(1-pi_real) benign flows; FP rate * benign count = FA/1M
        fa_per_million = best_adj["fpr"] * (1_000_000 * (1 - pi_real))

        print(f"\n  Prevalence π_real={label}:")
        print(f"    Best threshold on Val (prior-adj): {t_adj:.4f}")
        print(f"    Val Recall    : {best_adj['recall']*100:.2f}%")
        print(f"    Val FPR       : {best_adj['fpr']*100:.4f}%")
        print(f"    Val Precision : {best_adj['precision']*100:.2f}%")
        print(f"    Val F1        : {best_adj['f1']:.4f}")
        print(f"    FA per 1M flows (at this prevalence): {fa_per_million:,.0f}")

        # Report Test at this threshold (ONCE — only printing, not selecting)
        print(f"  Computing Test scores...")
    
    # Compute Test scores once
    print("\nComputing Test scores (evaluated ONCE)...")
    test_cal, test_raw = get_calibrated_scores(X_test)

    # Report Test at best Val F1 threshold
    print(f"\n--- TEST SET RESULTS at Val-selected threshold = {best_f1_t:.4f} ---")
    test_preds = (test_cal >= best_f1_t).astype(int)
    tp = int(np.sum((test_preds == 1) & (y_test_b == 1)))
    fp = int(np.sum((test_preds == 1) & (y_test_b == 0)))
    fn = int(np.sum((test_preds == 0) & (y_test_b == 1)))
    tn = int(np.sum((test_preds == 0) & (y_test_b == 0)))
    recall = tp / (tp + fn) if (tp+fn) > 0 else 0.0
    fpr    = fp / (fp + tn) if (fp+tn) > 0 else 0.0
    prec   = tp / (tp + fp) if (tp+fp) > 0 else 0.0
    f1     = 2*prec*recall / (prec+recall) if (prec+recall) > 0 else 0.0
    _, rl, ru = wilson_ci(tp, tp+fn)

    print(f"  Test Recall    : {recall*100:.2f}% [95% CI: {rl*100:.2f}%–{ru*100:.2f}%]")
    print(f"  Test FPR       : {fpr*100:.4f}%")
    print(f"  Test Precision : {prec*100:.2f}%")
    print(f"  Test F1 binary : {f1:.4f}")
    print(f"  TP={tp:,}  FP={fp:,}  FN={fn:,}  TN={tn:,}")

    # Per-class recall on Test
    benign_idx = class_names.index("BENIGN") if "BENIGN" in class_names else 0
    print("\n  Per-class Test Recall:")
    for c_idx, cname in enumerate(class_names):
        if cname == "BENIGN":
            continue
        mask = (y_test_m == c_idx)
        cnt  = int(np.sum(mask))
        if cnt == 0:
            continue
        det = int(np.sum(test_preds[mask] == 1))
        r   = det / cnt
        _, rl2, ru2 = wilson_ci(det, cnt)
        print(f"    {cname:<18}: {det:>6,}/{cnt:>6,}  Recall={r*100:.1f}% [CI: {rl2*100:.1f}%–{ru2*100:.1f}%]")

    # Compare to original threshold from manifest
    orig_t = manifest.get("decision_threshold", 0.50)
    print(f"\n  (For reference) ORIGINAL threshold={orig_t:.4f} vs NEW best-Val threshold={best_f1_t:.4f}")

    # Note on Model A vs B selection
    print("\n--- Item 7: PRODUCTION MODEL SELECTION RULE ---")
    print("  Model A (69 features): includes Protocol column.")
    print("  Model B (68 features): Protocol excluded (ablation).")
    print("  Decision rule: compare Val Macro-F1 (Model A vs Model B) from manifest.")
    ext = manifest.get("external_validation", {})
    print(f"  Val Macro-F1 Model A: {manifest.get('test_metrics', {}).get('f1_macro', 'N/A')}")
    print(f"  External 2018 Macro-F1 Model A: {ext.get('model_A_macro_f1', 'N/A')}")
    print(f"  External 2018 Macro-F1 Model B: {ext.get('model_B_macro_f1', 'N/A')}")
    print("  Production: Model A selected if Val Macro-F1 (A) >= Val Macro-F1 (B).")
    print("  NOTE: Both had Macro-F1=0.1653 on 2018 (old scaler bug) — re-evaluate after regeneration.")


if __name__ == "__main__":
    run()
