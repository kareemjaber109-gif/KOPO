import json
import time
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
from sklearn.metrics import (
    roc_auc_score,
    average_precision_score,
    confusion_matrix,
    classification_report,
)

from src.utils.config import settings
from src.utils.logger import logger
from src.ml.anomaly.anomaly_ensemble import AnomalyEnsemble

ATTACK_NAMES = {
    0: "Benign",
    1: "Analysis",
    2: "Backdoor",
    3: "DoS",
    4: "Exploits",
    5: "Fuzzers",
    6: "Generic",
    7: "Reconnaissance",
    8: "Shellcode",
    9: "Worms",
}


def evaluate_anomaly_models():
    data_dir = settings.data_processed_dir / "unsw"
    models_dir = settings.models_dir / "anomaly"

    logger.info("=" * 65)
    logger.info("▶ Starting Comprehensive Anomaly Evaluation on Test Set")
    logger.info("=" * 65)

    # 1. Load test data
    test_data = np.load(data_dir / "test.npz")
    X_test = test_data["X"]
    y_test_b = test_data["y"]
    category_test = test_data["category"]
    source_test = test_data["source"]

    summary_path = data_dir / "summary.json"
    meta = {}
    if summary_path.exists():
        with open(summary_path, "r", encoding="utf-8") as f:
            meta = json.load(f)

    logger.info(f"Loaded Test Set: {len(X_test):,} flows ({np.sum(y_test_b == 0):,} Benign, {np.sum(y_test_b == 1):,} Attacks)")

    # 2. Load Ensemble
    ensemble = AnomalyEnsemble.load(models_dir)
    threshold = ensemble.threshold
    logger.info(f"Loaded Anomaly Ensemble with Operational Threshold: {threshold:.4f}")

    # 3. Predict Scores
    logger.info("Computing anomaly scores on test set...")
    scores_ens, p_ae, p_if = ensemble.predict_score(X_test)

    # 4. Binary Metrics Function
    def _calc_metrics(scores: np.ndarray, thresh: float, name: str) -> Dict[str, Any]:
        preds = (scores >= thresh).astype(int)
        cm = confusion_matrix(y_test_b, preds, labels=[0, 1])
        tn, fp, fn, tp = cm.ravel()

        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
        prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        acc = (tp + tn) / len(y_test_b)
        f1 = (2 * prec * tpr) / (prec + tpr) if (prec + tpr) > 0 else 0.0
        roc_auc = float(roc_auc_score(y_test_b, scores))
        pr_auc = float(average_precision_score(y_test_b, scores))

        return {
            "name": name,
            "roc_auc": roc_auc,
            "pr_auc": pr_auc,
            "recall_tpr": tpr,
            "fpr": fpr,
            "precision": prec,
            "accuracy": acc,
            "f1": f1,
            "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
        }

    m_ens = _calc_metrics(scores_ens, threshold, "Ensemble (AE + IF)")
    m_ae = _calc_metrics(p_ae, np.percentile(p_ae[y_test_b == 0], 99.0), "Autoencoder (Alone)")
    m_if = _calc_metrics(p_if, np.percentile(p_if[y_test_b == 0], 99.0), "Isolation Forest (Alone)")

    # 5. Independent Benign FPR (Domain Generalization Verification)
    benign_mask = (y_test_b == 0)
    scores_benign = scores_ens[benign_mask]
    source_benign = source_test[benign_mask]

    unsw_mask = (source_benign == "unsw") | (source_benign == 0) | (source_benign == "0")
    cic_mask = (source_benign == "cicids2017") | (source_benign == "cicids") | (source_benign == 1) | (source_benign == "1")

    fpr_unsw = float(np.mean(scores_benign[unsw_mask] >= threshold)) if np.any(unsw_mask) else 0.0
    fpr_cic = float(np.mean(scores_benign[cic_mask] >= threshold)) if np.any(cic_mask) else 0.0

    # 6. Per-Attack Category Recall Breakdown
    per_class_recall = {}
    preds_ens = (scores_ens >= threshold).astype(int)

    unique_categories = sorted(list(set(category_test[category_test != "Benign"])))
    for cname in unique_categories:
        mask = (category_test == cname)
        count = int(np.sum(mask))
        if count == 0:
            continue
        detected = int(np.sum(preds_ens[mask] == 1))
        recall = detected / count
        display_label = ATTACK_NAMES.get(int(cname.replace("class_", "")), cname) if cname.startswith("class_") else cname
        per_class_recall[display_label] = {"count": count, "detected": detected, "recall": recall}

    # 7. Print Terminal Reporting Tables
    def _pct(v):
        return f"{v * 100:.2f}%" if v is not None else "N/A"

    print("\n" + "═" * 85)
    print("▶ TABLE 1: ANOMALY DETECTION TEST BENCHMARK (AT 1% TARGET FPR)")
    print("═" * 85)
    print(f"{'Model Component':<25} | {'ROC-AUC':<9} | {'PR-AUC':<9} | {'Recall (TPR)':<12} | {'FPR':<8} | {'Precision'}")
    print("-" * 85)
    for m in [m_ens, m_ae, m_if]:
        print(
            f"{m['name']:<25} | {_pct(m['roc_auc']):<9} | {_pct(m['pr_auc']):<9} | "
            f"{_pct(m['recall_tpr']):<12} | {_pct(m['fpr']):<8} | {_pct(m['precision'])}"
        )
    print("═" * 85)

    print("\n" + "═" * 85)
    print("▶ TABLE 2: PER-ATTACK CATEGORY DETECTION RATE (UNSW-NB15 TEST SET)")
    print("═" * 85)
    print(f"{'Attack Category':<20} | {'Test Samples':<15} | {'Detected':<15} | {'Detection Rate (Recall)'}")
    print("-" * 85)
    for cname, data in per_class_recall.items():
        print(f"{cname:<20} | {data['count']:<15,} | {data['detected']:<15,} | {_pct(data['recall'])}")
    print("═" * 85)

    print("\n" + "=" * 60)
    print("▶ DOMAIN INVARIANCE SANITY CHECK (TEST BENIGN FPR)")
    print("=" * 60)
    print(f"UNSW-NB15 Benign FPR  : {_pct(fpr_unsw)}")
    print(f"CICIDS2017 Benign FPR : {_pct(fpr_cic)}")
    print(f"Overall Benign FPR    : {_pct(m_ens['fpr'])} (Target: ~1.00%)")
    print("=" * 60 + "\n")

    # 8. Save JSON Report
    report_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "test_size": len(X_test),
        "threshold": threshold,
        "models_evaluated": {
            "ensemble": m_ens,
            "autoencoder": m_ae,
            "isolation_forest": m_if,
        },
        "domain_generalization": {
            "unsw_benign_fpr": fpr_unsw,
            "cicids_benign_fpr": fpr_cic,
            "overall_benign_fpr": m_ens["fpr"],
        },
        "per_attack_recall": per_class_recall,
    }

    out_json = models_dir / "anomaly_evaluation_report.json"
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    logger.success(f"Anomaly Evaluation Report saved → {out_json}")


if __name__ == "__main__":
    evaluate_anomaly_models()
