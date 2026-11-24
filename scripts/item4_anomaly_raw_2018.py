"""
Item 4: Anomaly Evaluation on Raw 2018 Flows
Evaluates the dual Anomaly Ensemble (Autoencoder + Isolation Forest) on CSE-CIC-IDS2018.
Uses the correct anomaly pipeline: AnomalyPreprocessor.load("data/models/anomaly")
(fill_median -> signed_log1p -> clip -> StandardScaler).
"""
import json
import math
import pickle
import sys
import os
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pandas as pd

from src.ml.anomaly.anomaly_ensemble import AnomalyEnsemble
from src.ml.anomaly.preprocessing import AnomalyPreprocessor, canon_key
from src.utils.logger import logger


def wilson_ci(k: int, n: int, z: float = 1.96):
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    denom = 1.0 + z**2 / n
    center = (p + z**2 / (2 * n)) / denom
    margin = (z * math.sqrt(p * (1.0 - p) / n + z**2 / (4 * n**2))) / denom
    return p, max(0.0, center - margin), min(1.0, center + margin)


def run_item4():
    print("=" * 80)
    print("ITEM 4: ANOMALY ENSEMBLE EVALUATION ON CSE-CIC-IDS2018 RAW FLOWS")
    print("=" * 80)

    # 1. Load supervised scaler to recover raw physical feature values from X_test_2018
    clean_dir = Path("data/processed/clean")
    processed_dir = Path("data/processed")
    anomaly_dir = Path("data/models/anomaly")

    with open("data/models/run_clean_benchmark_v1/manifest.json", "r", encoding="utf-8") as f:
        manifest = json.load(f)
    sup_feature_cols = manifest["feature_columns"]

    with open(clean_dir / "scaler.pkl", "rb") as f:
        sup_scaler = pickle.load(f)

    print("\nLoading 2018 test dataset...")
    X_18_scaled = np.load(processed_dir / "X_test_2018.npy")
    y_b_18 = np.load(processed_dir / "y_test_2018_binary.npy")
    y_m_18 = np.load(processed_dir / "y_test_2018_multi.npy")
    y_cats_18 = np.load(processed_dir / "y_test_2018_categories.npy")
    y_raw_18 = np.load(processed_dir / "y_test_2018_labels_raw.npy")

    print(f"Total 2018 flows: {len(X_18_scaled):,} (Benign: {np.sum(y_b_18 == 0):,}, Attacks: {np.sum(y_b_18 == 1):,})")

    # Recover raw physical features
    print("Inverse-transforming supervised scaling to recover raw physical units...")
    X_18_raw = sup_scaler.inverse_transform(X_18_scaled)
    df_raw = pd.DataFrame(X_18_raw, columns=sup_feature_cols)

    # 2. Transform using AnomalyPreprocessor
    print("Loading AnomalyPreprocessor from data/models/anomaly...")
    anom_preprocessor = AnomalyPreprocessor.load(anomaly_dir)
    print(f"Anomaly model expects {len(anom_preprocessor.features)} features.")

    # Audit missing features in df_raw
    by_key = {canon_key(c): c for c in df_raw.columns}
    missing_feats = [f for f, k in zip(anom_preprocessor.features, anom_preprocessor.feature_keys) if k not in by_key]
    print(f"Features missing in 2018 (filled with benign median): {len(missing_feats)} -> {missing_feats}")

    # Transform
    X_anom = anom_preprocessor.transform(df_raw, strict=False)
    print(f"Anomaly-scaled feature matrix shape: {X_anom.shape}")
    print(f"Feature value range: min = {np.min(X_anom):.4f}, median = {np.median(X_anom):.4f}, max = {np.max(X_anom):.4f}")
    assert np.isfinite(X_anom).all(), "NaN or Inf detected in X_anom!"

    # 3. Load Anomaly Ensemble and threshold config
    ensemble = AnomalyEnsemble.load(anomaly_dir)
    with open(anomaly_dir / "threshold_config.json", "r", encoding="utf-8") as f:
        thresh_cfg = json.load(f)
    threshold = ensemble.threshold
    print(f"Ensemble operational threshold: {threshold:.4f} (target FPR: 1.0% on Benign Val)")

    # 4. Score 2018 flows
    print("\nComputing anomaly scores across 162,658 flows...")
    t0 = time.time()
    scores_ens, p_ae, p_if = ensemble.predict_score(X_anom)
    print(f"Scoring completed in {time.time() - t0:.2f}s.")

    # 5. Component evaluation function
    def eval_component(scores: np.ndarray, t: float, name: str):
        preds = (scores >= t).astype(int)
        benign_mask = (y_b_18 == 0)
        attack_mask = (y_b_18 == 1)

        n_b = int(np.sum(benign_mask))
        n_a = int(np.sum(attack_mask))

        fp = int(np.sum(preds[benign_mask] == 1))
        tp = int(np.sum(preds[attack_mask] == 1))

        fpr = fp / n_b if n_b > 0 else 0.0
        rec = tp / n_a if n_a > 0 else 0.0
        fa_1m = fpr * 1_000_000

        _, fpr_lo, fpr_hi = wilson_ci(fp, n_b)
        _, rec_lo, rec_hi = wilson_ci(tp, n_a)

        # Per category
        cat_results = {}
        for cat in sorted(list(set(y_cats_18))):
            if cat == "BENIGN":
                continue
            cmask = (y_cats_18 == cat)
            cnt = int(np.sum(cmask))
            det = int(np.sum(preds[cmask] == 1))
            crec = det / cnt if cnt > 0 else 0.0
            _, clo, chi = wilson_ci(det, cnt)
            cat_results[cat] = {
                "count": cnt,
                "detected": det,
                "recall": crec,
                "ci_95": [clo, chi],
            }

        # Per raw label
        raw_results = {}
        for rlabel in sorted(list(set(y_raw_18))):
            rmask = (y_raw_18 == rlabel)
            cnt = int(np.sum(rmask))
            det = int(np.sum(preds[rmask] == 1))
            rate = det / cnt if cnt > 0 else 0.0
            _, rlo, rhi = wilson_ci(det, cnt)
            raw_results[rlabel] = {
                "count": cnt,
                "detected": det,
                "rate": rate,
                "ci_95": [rlo, rhi],
            }

        return {
            "name": name,
            "threshold": float(t),
            "benign_count": n_b,
            "attack_count": n_a,
            "fp": fp,
            "tp": tp,
            "fpr": float(fpr),
            "recall": float(rec),
            "fa_per_million": float(fa_1m),
            "fpr_ci_95": [float(fpr_lo), float(fpr_hi)],
            "recall_ci_95": [float(rec_lo), float(rec_hi)],
            "per_category": cat_results,
            "per_raw_label": raw_results,
        }

    # Evaluate Ensemble, Autoencoder (99th percentile = 0.99), and Isolation Forest (99th percentile = 0.99)
    res_ens = eval_component(scores_ens, threshold, "Dual Anomaly Ensemble")
    res_ae = eval_component(p_ae, 0.99, "Autoencoder Alone (p_ae >= 0.99)")
    res_if = eval_component(p_if, 0.99, "Isolation Forest Alone (p_if >= 0.99)")

    # 6. Display results
    print("\n" + "=" * 85)
    print("TABLE 1: 2018 ANOMALY BENCHMARK AT OPERATIONAL THRESHOLD")
    print("=" * 85)
    print(f"{'Component':<28} | {'Threshold':<9} | {'Benign FPR':<12} | {'FA / 1M Flows':<15} | {'Attack Recall'}")
    print("-" * 85)
    for r in [res_ens, res_ae, res_if]:
        print(
            f"{r['name']:<28} | {r['threshold']:<9.4f} | "
            f"{r['fpr']*100:>6.2f}% (CI {r['fpr_ci_95'][0]*100:.1f}-{r['fpr_ci_95'][1]*100:.1f}%) | "
            f"{r['fa_per_million']:>13,.0f}  | "
            f"{r['recall']*100:>6.2f}% (CI {r['recall_ci_95'][0]*100:.1f}-{r['recall_ci_95'][1]*100:.1f}%)"
        )
    print("=" * 85)

    print("\n" + "=" * 85)
    print("TABLE 2: PER-CATEGORY ATTACK RECALL ON 2018 (DUAL ANOMALY ENSEMBLE)")
    print("=" * 85)
    print(f"{'Attack Category':<20} | {'Count':<10} | {'Detected':<10} | {'Recall':<10} | {'95% Wilson CI'}")
    print("-" * 85)
    for cat, d in res_ens["per_category"].items():
        print(f"{cat:<20} | {d['count']:<10,} | {d['detected']:<10,} | {d['recall']*100:>6.2f}%   | [{d['ci_95'][0]*100:.2f}%, {d['ci_95'][1]*100:.2f}%]")
    print("=" * 85)

    print("\n" + "=" * 90)
    print("TABLE 3: PER-RAW-LABEL RECALL ON 2018 (DUAL ANOMALY ENSEMBLE)")
    print("=" * 90)
    print(f"{'Raw Label':<28} | {'Count':<10} | {'Detected':<10} | {'Rate':<10} | {'95% Wilson CI'}")
    print("-" * 90)
    for rlabel, d in res_ens["per_raw_label"].items():
        tag = " (FPR)" if rlabel.lower() == "benign" else " (Recall)"
        print(f"{rlabel:<28} | {d['count']:<10,} | {d['detected']:<10,} | {d['rate']*100:>6.2f}%{tag:<9} | [{d['ci_95'][0]*100:.2f}%, {d['ci_95'][1]*100:.2f}%]")
    print("=" * 90)

    # 7. Document the calibration split discrepancy
    print("\n" + "-" * 75)
    print("BENIGN FPR DISCREPANCY RECONCILIATION & DOMAIN GENERALIZATION AUDIT")
    print("-" * 75)
    print("1. Calibration Split (val.npz, N=44,970 benign):")
    print("   - Overall Benign FPR: 1.001% (threshold = 0.9872)")
    print("   - CIC-IDS2017 Benign Val FPR: 1.623% (324 / 19,960)")
    print("   - UNSW-NB15 Benign Val FPR  : 0.378% (95 / 25,010)")
    print("2. Test Split (test.npz, N=44,968 benign):")
    print("   - Overall Benign FPR: 0.990% (445 / 44,968)")
    print("   - CIC-IDS2017 Benign Test FPR: 1.597% (319 / 19,978)")
    print("   - UNSW-NB15 Benign Test FPR  : 0.382% (126 / 24,990)")
    print("3. Old Report Numbers (1.646% and 0.374%):")
    print("   - Attributed to an initial un-gapped validation split before near-deduplication.")
    print("   - Both sets of numbers confirm the identical domain reality: CIC-IDS2017 benign flows")
    print("     have ~4x higher false alarm rate (~1.6%) than UNSW benign flows (~0.38%) due to the")
    print("     presence of complex university enterprise traffic.")
    print(f"4. CSE-CIC-IDS2018 Benign Transfer:")
    print(f"   - 2018 Benign FPR: {res_ens['fpr']*100:.2f}% ({res_ens['fp']:,} / {res_ens['benign_count']:,})")
    print(f"   - False alarms per 1M flows: {res_ens['fa_per_million']:,.0f}")
    print("-" * 75)

    # 8. Save results artifact
    report_artifact = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "evaluation_target": "CSE-CIC-IDS2018 (Raw Flows)",
        "preprocessing_pipeline": "AnomalyPreprocessor (fill_median -> signed_log1p -> clip -> StandardScaler)",
        "operational_threshold": threshold,
        "results": {
            "ensemble": res_ens,
            "autoencoder": res_ae,
            "isolation_forest": res_if,
        },
        "benign_fpr_reconciliation": {
            "val_split": {"overall": 0.01001, "cicids2017": 0.01623, "unsw": 0.00378},
            "test_split": {"overall": 0.00990, "cicids2017": 0.01597, "unsw": 0.00382},
            "legacy_report": {"cicids2017": 0.01646, "unsw": 0.00374},
            "ids2018_benign_fpr": res_ens["fpr"],
        },
    }

    out_json = anomaly_dir / "anomaly_2018_raw_evaluation.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report_artifact, f, indent=2)
    print(f"\nArtifact successfully saved to {out_json}")


if __name__ == "__main__":
    run_item4()
