"""
Cross-dataset evaluation: CIC-IDS2017 (in-distribution) vs CSE-CIC-IDS2018 (out-of-distribution).
Evaluates production pipeline loaded via current.json manifest:
- Random Forest
- XGBoost
- Calibrated Ensemble (Isotonic) at active manifest threshold
- Reports per-class recall, Benign FPR, Macro-F1, Binary F1
"""
import json
import pickle
import time
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
from sklearn.metrics import confusion_matrix, f1_score, accuracy_score

from src.utils.config import settings
from src.utils.logger import logger


def compute_binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    attack_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    benign_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    acc = (tp + tn) / len(y_true) if len(y_true) > 0 else 0.0
    macro_f1 = f1_score(y_true, y_pred, average="macro", zero_division=0)
    binary_f1 = f1_score(y_true, y_pred, average="binary", zero_division=0)

    return {
        "accuracy": float(acc),
        "macro_f1": float(macro_f1),
        "binary_f1": float(binary_f1),
        "attack_recall_tpr": float(attack_recall),
        "benign_fpr": float(benign_fpr),
        "precision": float(precision),
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    }


def compute_per_class_recall(
    y_true_multi: np.ndarray,
    y_pred_binary: np.ndarray,
    class_names: List[str],
) -> Dict[str, Dict[str, Any]]:
    results = {}
    for idx, cname in enumerate(class_names):
        mask = (y_true_multi == idx)
        count = int(np.sum(mask))
        if count == 0:
            results[cname] = {"count": 0, "detected": 0, "recall": None}
            continue

        preds_for_class = y_pred_binary[mask]
        if cname == "BENIGN":
            correct = int(np.sum(preds_for_class == 0))
            recall = correct / count
            fpr = (count - correct) / count
            results[cname] = {"count": count, "correct": correct, "recall": recall, "fpr": fpr}
        else:
            detected = int(np.sum(preds_for_class == 1))
            recall = detected / count
            results[cname] = {"count": count, "detected": detected, "recall": recall}
    return results


def run_cross_dataset_evaluation(output_report_path: Path = None):
    # 1. Determine active model run directory from current.json
    current_path = settings.models_dir / "current.json"
    if current_path.exists():
        with open(current_path, "r", encoding="utf-8") as f:
            cdata = json.load(f)
        run_dir = Path(cdata.get("run_dir", settings.models_dir))
    else:
        run_dir = settings.models_dir

    manifest_path = run_dir / "manifest.json"
    if not manifest_path.exists():
        manifest_path = settings.models_dir / "run_clean_benchmark_v1" / "manifest.json"
        run_dir = manifest_path.parent

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    threshold = manifest.get("decision_threshold", 0.50)
    class_names = manifest["class_names"]
    logger.info(f"Loaded manifest from {run_dir} (threshold={threshold:.4f}, features={manifest['n_features']})")

    # 2. Load Models
    with open(run_dir / "random_forest.pkl", "rb") as f:
        rf = pickle.load(f)
    with open(run_dir / "xgboost.pkl", "rb") as f:
        xgb = pickle.load(f)
    with open(run_dir / "isotonic_calibrator.pkl", "rb") as f:
        iso = pickle.load(f)

    # 3. Load Datasets
    clean_dir = settings.data_processed_dir / "clean"
    if not clean_dir.exists():
        clean_dir = settings.data_processed_dir

    X_test_17 = np.load(clean_dir / "X_test.npy")
    y_test_b_17 = np.load(clean_dir / "y_test_binary.npy")
    y_test_m_17 = np.load(clean_dir / "y_test_multi.npy")

    X_test_18 = np.load(settings.data_processed_dir / "X_test_2018.npy")
    y_test_b_18 = np.load(settings.data_processed_dir / "y_test_2018_binary.npy")
    y_test_m_18 = np.load(settings.data_processed_dir / "y_test_2018_multi.npy")

    logger.info(f"2017 Test flows: {len(X_test_17):,} | 2018 Test flows: {len(X_test_18):,}")

    # 4. Predict
    def predict_pipeline(X):
        rf_p = rf.predict_proba(X)
        xgb_p = xgb.predict_proba(X)
        blended = 0.5 * (1.0 - rf_p[:, 0]) + 0.5 * (1.0 - xgb_p[:, 0])
        calibrated = iso.predict(blended)
        return (calibrated >= threshold).astype(int), calibrated, blended

    pred_17, cal_17, blend_17 = predict_pipeline(X_test_17)
    pred_18, cal_18, blend_18 = predict_pipeline(X_test_18)

    # 5. Compute Metrics
    met_17 = compute_binary_metrics(y_test_b_17, pred_17)
    met_18 = compute_binary_metrics(y_test_b_18, pred_18)
    per_class_17 = compute_per_class_recall(y_test_m_17, pred_17, class_names)
    per_class_18 = compute_per_class_recall(y_test_m_18, pred_18, class_names)

    report = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "run_id": manifest.get("run_id", "unknown"),
        "threshold": threshold,
        "metrics_2017": met_17,
        "metrics_2018": met_18,
        "per_class_2017": per_class_17,
        "per_class_2018": per_class_18,
    }

    out_path = output_report_path or (settings.models_dir / "cross_dataset_evaluation_report.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    logger.success(f"Cross-dataset evaluation report written to {out_path}")
    logger.info(f"2017 Test: Recall={met_17['attack_recall_tpr']*100:.2f}%, FPR={met_17['benign_fpr']*100:.3f}%, Macro-F1={met_17['macro_f1']:.4f}")
    logger.info(f"2018 Test: Recall={met_18['attack_recall_tpr']*100:.2f}%, FPR={met_18['benign_fpr']*100:.3f}%, Macro-F1={met_18['macro_f1']:.4f}")
    return report


if __name__ == "__main__":
    run_cross_dataset_evaluation()
