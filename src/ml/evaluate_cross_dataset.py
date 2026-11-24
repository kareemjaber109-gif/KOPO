import json
import pickle
import time
from pathlib import Path
from typing import Dict, Any, List
import numpy as np
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    recall_score,
    precision_score,
    accuracy_score,
)

from src.utils.config import settings
from src.utils.logger import logger
from src.ml.models.random_forest import RFModel
from src.ml.models.xgboost_model import XGBModel
from src.ml.models.isolation_forest import IsolationForestModel


def compute_binary_metrics(y_true: np.ndarray, y_pred: np.ndarray) -> Dict[str, float]:
    """Calculate rigorous binary metrics including Macro-F1, Attack Recall, and Benign FPR."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()

    attack_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    benign_fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    benign_recall = tn / (tn + fp) if (tn + fp) > 0 else 0.0
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
        "benign_recall": float(benign_recall),
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
    """Compute detection rate (recall) for each specific attack type under binary decision."""
    results = {}
    for idx, cname in enumerate(class_names):
        mask = (y_true_multi == idx)
        count = int(np.sum(mask))
        if count == 0:
            results[cname] = {"count": 0, "detected": 0, "recall": None}
            continue
        
        preds_for_class = y_pred_binary[mask]
        if cname == "BENIGN":
            # For benign: "detected" means correctly predicted as 0 (Benign)
            correct = int(np.sum(preds_for_class == 0))
            recall = correct / count
            fpr = (count - correct) / count
            results[cname] = {"count": count, "correct": correct, "recall": recall, "fpr": fpr}
        else:
            # For attack: "detected" means predicted as 1 (Attack)
            detected = int(np.sum(preds_for_class == 1))
            recall = detected / count
            results[cname] = {"count": count, "detected": detected, "recall": recall}
    return results


def run_cross_dataset_evaluation():
    processed_dir = settings.data_processed_dir
    models_dir = settings.models_dir

    logger.info("=" * 65)
    logger.info("▶ Starting Cross-Dataset Evaluation: CICIDS2017 vs CSE-CIC-IDS2018")
    logger.info("=" * 65)

    # 1. Load 2017 test set
    logger.info("Loading CICIDS2017 Test Set (In-Distribution)...")
    X_test_17 = np.load(processed_dir / "X_test.npy")
    y_test_b_17 = np.load(processed_dir / "y_test_binary.npy")
    y_test_m_17 = np.load(processed_dir / "y_test_multi.npy")

    # 2. Load 2018 test set
    logger.info("Loading CSE-CIC-IDS2018 Test Set (Cross-Dataset / OOD)...")
    X_test_18 = np.load(processed_dir / "X_test_2018.npy")
    y_test_b_18 = np.load(processed_dir / "y_test_2018_binary.npy")
    y_test_m_18 = np.load(processed_dir / "y_test_2018_multi.npy")

    with open(processed_dir / "metadata.json", "r", encoding="utf-8") as f:
        meta_17 = json.load(f)
    classes_17 = meta_17["class_names"]

    logger.info(f"2017 Test Set: {len(X_test_17):,} flows")
    logger.info(f"2018 Test Set: {len(X_test_18):,} flows")

    # 3. Load Trained Models
    logger.info("\nLoading pre-trained models from 2017...")
    rf = RFModel().load(models_dir / "random_forest.pkl")
    xgb = XGBModel.load(models_dir / "xgboost.pkl")
    if_model = IsolationForestModel.load(models_dir / "isolation_forest.pkl")

    # 4. Generate Predictions
    logger.info("Running inference on both datasets...")

    # Random Forest
    rf_pred_17 = rf.predict(X_test_17)
    rf_pred_18 = rf.predict(X_test_18)

    # XGBoost (multi-class predictions mapped to binary: >0 is attack)
    xgb_m_pred_17 = xgb.predict(X_test_17)
    xgb_b_pred_17 = (xgb_m_pred_17 != 0).astype(int)

    xgb_m_pred_18 = xgb.predict(X_test_18)
    xgb_b_pred_18 = (xgb_m_pred_18 != 0).astype(int)

    # Isolation Forest
    if_pred_17 = if_model.predict(X_test_17)
    if_pred_18 = if_model.predict(X_test_18)

    # Hierarchical Two-Stage IDS (Dynamic threshold from manifest if available)
    import json
    from pathlib import Path
    manifest_p = Path("data/models/run_clean_benchmark_v1/manifest.json")
    threshold = 0.50
    if manifest_p.exists():
        with open(manifest_p, "r", encoding="utf-8") as mf:
            threshold = json.load(mf).get("decision_threshold", 0.50)
    from src.ml.models.hierarchical_ids import HierarchicalIDS
    h_ids = HierarchicalIDS(rf_model=rf, xgb_model=xgb, class_names=classes_17)
    h_pred_17 = h_ids.predict_binary(X_test_17, attack_threshold=threshold)
    h_pred_18 = h_ids.predict_binary(X_test_18, attack_threshold=threshold)

    # 5. Compute Unified Binary Benchmark Metrics
    models_predictions = {
        "Random Forest": {"17": rf_pred_17, "18": rf_pred_18},
        "XGBoost (Binary Mapping)": {"17": xgb_b_pred_17, "18": xgb_b_pred_18},
        "Hierarchical IDS (Proposed)": {"17": h_pred_17, "18": h_pred_18},
        "Isolation Forest": {"17": if_pred_17, "18": if_pred_18},
    }

    binary_benchmark = {}
    for mname, preds in models_predictions.items():
        m17 = compute_binary_metrics(y_test_b_17, preds["17"])
        m18 = compute_binary_metrics(y_test_b_18, preds["18"])
        binary_benchmark[mname] = {"2017": m17, "2018": m18}

    # 6. Per-Attack Recall Breakdown (for RF, XGBoost, and Hierarchical IDS)
    per_attack_rf_17 = compute_per_class_recall(y_test_m_17, rf_pred_17, classes_17)
    per_attack_rf_18 = compute_per_class_recall(y_test_m_18, rf_pred_18, classes_17)

    per_attack_xgb_17 = compute_per_class_recall(y_test_m_17, xgb_b_pred_17, classes_17)
    per_attack_xgb_18 = compute_per_class_recall(y_test_m_18, xgb_b_pred_18, classes_17)

    per_attack_h_17 = compute_per_class_recall(y_test_m_17, h_pred_17, classes_17)
    per_attack_h_18 = compute_per_class_recall(y_test_m_18, h_pred_18, classes_17)

    # 7. Print Terminal Summary Tables
    def _pct(val):
        return f"{val * 100:.2f}%" if val is not None else "N/A"

    print("\n" + "═" * 90)
    print("▶ TABLE 1: UNIFIED BINARY BENCHMARK (CICIDS2017 vs CSE-CIC-IDS2018)")
    print("═" * 90)
    print(f"{'Model':<25} | {'Metric':<18} | {'2017 Test (In-Dist)':<20} | {'2018 Test (OOD)':<18}")
    print("-" * 90)

    for mname, data in binary_benchmark.items():
        print(f"[{mname}]")
        print(f"{'':<25} | {'Macro-F1':<18} | {_pct(data['2017']['macro_f1']):<20} | {_pct(data['2018']['macro_f1']):<18}")
        print(f"{'':<25} | {'Attack Recall (TPR)':<18} | {_pct(data['2017']['attack_recall_tpr']):<20} | {_pct(data['2018']['attack_recall_tpr']):<18}")
        print(f"{'':<25} | {'Benign FPR (False Alm)':<18} | {_pct(data['2017']['benign_fpr']):<20} | {_pct(data['2018']['benign_fpr']):<18}")
        print(f"{'':<25} | {'Accuracy':<18} | {_pct(data['2017']['accuracy']):<20} | {_pct(data['2018']['accuracy']):<18}")
        print("-" * 90)

    print("\n" + "═" * 105)
    print("▶ TABLE 2: PER-ATTACK DETECTION RATE (RECALL) - BASELINE VS HIERARCHICAL IDS")
    print("═" * 105)
    print(f"{'Attack Class':<15} | {'RF 2017':<9} | {'RF 2018':<9} | {'XGB 2017':<9} | {'XGB 2018':<9} | {'H-IDS 2017':<10} | {'H-IDS 2018':<10} | {'2018 Status'}")
    print("-" * 105)

    for cname in classes_17:
        if cname == "BENIGN":
            continue
        rf17_r = per_attack_rf_17[cname]["recall"]
        rf18_r = per_attack_rf_18[cname]["recall"]
        xgb17_r = per_attack_xgb_17[cname]["recall"]
        xgb18_r = per_attack_xgb_18[cname]["recall"]
        h17_r = per_attack_h_17[cname]["recall"]
        h18_r = per_attack_h_18[cname]["recall"]

        status = "Evaluated" if rf18_r is not None else "Not in 2018 (N/A)"
        print(
            f"{cname:<15} | {_pct(rf17_r):<9} | {_pct(rf18_r):<9} | "
            f"{_pct(xgb17_r):<9} | {_pct(xgb18_r):<9} | "
            f"{_pct(h17_r):<10} | {_pct(h18_r):<10} | {status}"
        )
    print("═" * 105)

    # 8. Diagnostic Analysis: Feature Extraction Mismatch vs Concept Drift
    rf_benign_fpr_18 = binary_benchmark["Random Forest"]["2018"]["benign_fpr"]
    xgb_benign_fpr_18 = binary_benchmark["XGBoost (Binary Mapping)"]["2018"]["benign_fpr"]
    h_benign_fpr_18 = binary_benchmark["Hierarchical IDS (Proposed)"]["2018"]["benign_fpr"]

    print("\n" + "=" * 60)
    print("▶ DIAGNOSTIC SANITY CHECK: 2018 BENIGN FALSE ALARM RATE")
    print("=" * 60)
    print(f"Random Forest Benign FPR on 2018    : {_pct(rf_benign_fpr_18)}")
    print(f"XGBoost Benign FPR on 2018          : {_pct(xgb_benign_fpr_18)}")
    print(f"Hierarchical IDS Benign FPR on 2018 : {_pct(h_benign_fpr_18)}")
    
    if rf_benign_fpr_18 > 0.25:
        print(">> Note: High Benign False Positive Rate suggests feature calculation differences")
        print("   between CICFlowMeter versions or normalization shift rather than attack drift.")
    else:
        print(">> Note: Acceptable Benign False Positive Rate confirms normal flow features align,")
        print("   and changes in attack recall reflect true generalization / payload shifts.")
    print("=" * 60 + "\n")

    # 9. Save JSON Evaluation Report
    report_data = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "test_counts": {
            "2017": len(X_test_17),
            "2018": len(X_test_18),
        },
        "binary_benchmark": binary_benchmark,
        "per_attack_recall": {
            "random_forest": {"2017": per_attack_rf_17, "2018": per_attack_rf_18},
            "xgboost": {"2017": per_attack_xgb_17, "2018": per_attack_xgb_18},
            "hierarchical_ids": {"2017": per_attack_h_17, "2018": per_attack_h_18},
        },
        "classes_evaluated": [c for c in classes_17 if c != "PortScan"],
        "classes_missing_in_2018": ["PortScan"],
    }

    out_file = models_dir / "cross_dataset_evaluation_report.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    logger.success(f"Full Cross-Dataset Evaluation Report saved → {out_file}")


if __name__ == "__main__":
    run_cross_dataset_evaluation()
