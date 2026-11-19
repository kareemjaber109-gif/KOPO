import argparse
import json
import time
import sys
from pathlib import Path
from typing import Dict, Any
import numpy as np

from src.utils.config import settings
from src.utils.logger import logger

# Keys in a sklearn classification_report dict that are not per-class rows.
AGGREGATE_KEYS = {"accuracy", "macro avg", "weighted avg", "micro avg"}


def load_dataset(processed_dir: Path):
    """Load preprocessed features, labels, and metadata with validation."""
    required_files = [
        "X_train.npy", "X_test.npy",
        "y_train_binary.npy", "y_test_binary.npy",
        "y_train_multi.npy", "y_test_multi.npy",
        "metadata.json",
    ]

    missing = [f for f in required_files if not (processed_dir / f).exists()]
    if missing:
        logger.error(f"Missing processed data files in {processed_dir}: {missing}")
        logger.error("Please run the preprocessor first: python -m src.data.preprocessor")
        sys.exit(1)

    logger.info("Loading preprocessed dataset...")
    X_train = np.load(processed_dir / "X_train.npy")
    X_test = np.load(processed_dir / "X_test.npy")
    y_train_b = np.load(processed_dir / "y_train_binary.npy")
    y_test_b = np.load(processed_dir / "y_test_binary.npy")
    y_train_m = np.load(processed_dir / "y_train_multi.npy")
    y_test_m = np.load(processed_dir / "y_test_multi.npy")

    with open(processed_dir / "metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)

    logger.info(
        f"Dataset loaded: {len(X_train):,} train samples, "
        f"{len(X_test):,} test samples, {meta.get('n_features')} features."
    )
    data = {
        "X_train": X_train,
        "X_test": X_test,
        "y_train_b": y_train_b,
        "y_test_b": y_test_b,
        "y_train_m": y_train_m,
        "y_test_m": y_test_m,
        "meta": meta,
    }
    check_alignment(data)
    return data


def check_alignment(data: dict) -> None:
    """Stop if features and labels have different lengths.

    The old code silently cut both arrays to min(len(X), len(y)). If rows were
    dropped from the middle of one array (NaN/inf removal, resampling, dedup),
    that pairs rows with the wrong labels and quietly ruins every score.
    """
    pairs = [
        ("X_train", "y_train_b"), ("X_train", "y_train_m"),
        ("X_test", "y_test_b"), ("X_test", "y_test_m"),
    ]
    bad = [
        (a, len(data[a]), b, len(data[b]))
        for a, b in pairs
        if len(data[a]) != len(data[b])
    ]
    if not bad:
        return
    for a, la, b, lb in bad:
        logger.error(f"Length mismatch: {a} has {la:,} rows but {b} has {lb:,} labels")
    logger.error(
        "Features and labels are out of sync. Fix this in src/data/preprocessor.py "
        "(filter X and y together) and re-run it. Truncating would mislabel rows."
    )
    sys.exit(1)


def report_metrics(report: dict) -> dict:
    """Pull the same summary numbers out of any classification_report dict."""
    if not isinstance(report, dict):
        return {}
    macro = report.get("macro avg", {})
    weighted = report.get("weighted avg", {})
    values = {
        "accuracy": report.get("accuracy"),
        "macro_precision": macro.get("precision"),
        "macro_recall": macro.get("recall"),
        "macro_f1": macro.get("f1-score"),
        "weighted_f1": weighted.get("f1-score"),
    }
    return {k: v for k, v in values.items() if v is not None}


def log_per_class(title: str, report: dict, class_names=None) -> None:
    """Log precision / recall / F1 for each class so weak classes stand out."""
    if not isinstance(report, dict):
        return
    rows = {
        k: v for k, v in report.items()
        if k not in AGGREGATE_KEYS and isinstance(v, dict)
    }
    if not rows:
        return
    logger.info(f"Per-class results: {title}")
    logger.info(f"  {'class':<16}{'precision':>10}{'recall':>10}{'f1':>10}{'support':>10}")
    for label, v in rows.items():
        name = str(label)
        if class_names is not None and name.isdigit() and int(name) < len(class_names):
            name = class_names[int(name)]
        logger.info(
            f"  {name:<16}{v.get('precision', 0.0):>10.4f}{v.get('recall', 0.0):>10.4f}"
            f"{v.get('f1-score', 0.0):>10.4f}{int(v.get('support', 0)):>10,}"
        )


def train_random_forest(data: dict) -> dict:
    from src.ml.models.random_forest import RFModel
    logger.info("\n" + "=" * 55)
    logger.info("▶ Training Model 1: Random Forest (Supervised Binary)")
    logger.info("=" * 55)

    start = time.time()
    model = RFModel()
    model.train(data["X_train"], data["y_train_b"])
    train_time = time.time() - start

    eval_start = time.time()
    results = model.evaluate(data["X_test"], data["y_test_b"])
    eval_time = time.time() - eval_start
    model.save()

    report = results.get("report", {})
    entry = {
        "name": "Random Forest",
        "type": "Supervised Binary",
        "f1": results["f1"],
        "precision": report.get("weighted avg", {}).get("precision", 0.0),
        "recall": report.get("weighted avg", {}).get("recall", 0.0),
        "accuracy": report.get("accuracy", 0.0),
        "per_class_report": report,
        "confusion_matrix": results["confusion_matrix"],
        "labels": results["labels"],
        "train_time_sec": round(train_time, 2),
        "eval_time_sec": round(eval_time, 2),
    }
    entry.update(report_metrics(report))
    log_per_class("Random Forest", report)
    return entry


def train_xgboost(data: dict) -> dict:
    from src.ml.models.xgboost_model import XGBModel
    from sklearn.preprocessing import LabelEncoder
    logger.info("\n" + "=" * 55)
    logger.info("▶ Training Model 2: XGBoost (Supervised Multi-Class)")
    logger.info("=" * 55)

    class_names = data["meta"]["class_names"]
    n_classes = len(class_names)

    X_train = data["X_train"]
    y_train = data["y_train_m"]

    le = LabelEncoder()
    y_train_enc = le.fit_transform(y_train)
    y_test_enc = le.transform(data["y_test_m"])

    start = time.time()
    model = XGBModel(n_classes=n_classes)
    model.class_names = class_names
    model.train(X_train, y_train_enc)
    train_time = time.time() - start

    eval_start = time.time()
    results = model.evaluate(data["X_test"], y_test_enc)
    eval_time = time.time() - eval_start
    model.save()

    report = results.get("report", {})
    entry = {
        "name": "XGBoost",
        "type": "Supervised Multi-Class",
        "f1": results["macro_f1"],
        "precision": report.get("macro avg", {}).get("precision", 0.0),
        "recall": report.get("macro avg", {}).get("recall", 0.0),
        "accuracy": report.get("accuracy", 0.0),
        "per_class_report": report,
        "confusion_matrix": results["confusion_matrix"],
        "class_names": class_names,
        "train_time_sec": round(train_time, 2),
        "eval_time_sec": round(eval_time, 2),
    }
    entry.update(report_metrics(report))
    log_per_class("XGBoost", report, class_names)
    return entry


def train_lstm(data: dict, epochs: int = 20) -> dict:
    from src.ml.models.lstm_model import LSTMModel
    logger.info("\n" + "=" * 55)
    logger.info("▶ Training Model 3: Deep LSTM (Sequential Binary)")
    logger.info("=" * 55)

    n_features = data["meta"]["n_features"]
    X_train = data["X_train"]
    y_train = data["y_train_b"]

    start = time.time()
    model = LSTMModel(input_size=n_features)
    model.EPOCHS = epochs
    model.train(X_train, y_train)
    train_time = time.time() - start

    eval_start = time.time()
    results = model.evaluate(data["X_test"], data["y_test_b"])
    eval_time = time.time() - eval_start
    model.save()

    report = results.get("report", {})
    entry = {
        "name": "LSTM Network",
        "type": "Sequential Deep Learning",
        "f1": results["f1"],
        "precision": report.get("weighted avg", {}).get("precision", 0.0),
        "recall": report.get("weighted avg", {}).get("recall", 0.0),
        "accuracy": report.get("accuracy", 0.0),
        "per_class_report": report,
        "confusion_matrix": results["confusion_matrix"],
        "labels": results["labels"],
        "train_time_sec": round(train_time, 2),
        "eval_time_sec": round(eval_time, 2),
    }
    entry.update(report_metrics(report))
    log_per_class("LSTM", report)
    return entry


def train_isolation_forest(data: dict, contamination: float = 0.02) -> dict:
    from src.ml.models.isolation_forest import IsolationForestModel
    logger.info("\n" + "=" * 55)
    logger.info("▶ Training Model 4: Isolation Forest (Unsupervised Anomaly Detector)")
    logger.info("=" * 55)

    start = time.time()
    # Train purely on BENIGN samples (unsupervised profile of normal traffic)
    model = IsolationForestModel(contamination=contamination)
    model.train(data["X_train"], data["y_train_b"])
    train_time = time.time() - start

    eval_start = time.time()
    results = model.evaluate(data["X_test"], data["y_test_b"])
    eval_time = time.time() - eval_start
    model.save()

    logger.info(
        f"Isolation Forest: detection rate {results['detection_rate_tpr']:.2%} at "
        f"{results['false_alarm_rate_fpr']:.2%} false alarms "
        f"(contamination setting {contamination:.2%}, which sets the false-alarm budget)."
    )

    entry = {
        "name": "Isolation Forest",
        "type": "Unsupervised Anomaly",
        "f1": results["f1"],
        "precision": results["precision"],
        "recall": results["recall"],
        "accuracy": results["accuracy"],
        "per_class_report": results.get("report", {}),
        "confusion_matrix": results["confusion_matrix"],
        "detection_rate_tpr": results["detection_rate_tpr"],
        "false_alarm_rate_fpr": results["false_alarm_rate_fpr"],
        "roc_auc": results["roc_auc"],
        "train_time_sec": round(train_time, 2),
        "eval_time_sec": round(eval_time, 2),
    }
    entry.update(report_metrics(entry["per_class_report"]))
    return entry


def _pct(value) -> str:
    return "n/a" if value is None else f"{value * 100:.2f}%"


def print_summary_table(metrics: list[dict]):
    """Print an executive ASCII comparison summary table."""
    width = 112
    logger.info("\n" + "═" * width)
    logger.info("              FINAL TRAINING & EVALUATION SCOREBOARD")
    logger.info("═" * width)

    header = (
        f"{'Model':<18} | {'Paradigm':<24} | {'Accuracy':<9} | {'Macro-F1':<9} | "
        f"{'Recall/TPR':<10} | {'FPR':<7} | {'Train Time'}"
    )
    logger.info(header)
    logger.info("-" * width)

    for m in metrics:
        # Detection rate for the anomaly model, macro recall for classifiers.
        recall = m.get("detection_rate_tpr", m.get("macro_recall", m.get("recall")))
        logger.info(
            f"{m['name']:<18} | {m['type']:<24} | {_pct(m.get('accuracy')):<9} | "
            f"{_pct(m.get('macro_f1')):<9} | {_pct(recall):<10} | "
            f"{_pct(m.get('false_alarm_rate_fpr')):<7} | {m.get('train_time_sec', 0.0)}s"
        )
    logger.info("-" * width)
    logger.info("Binary and multi-class scores are not directly comparable.")
    logger.info("═" * width + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Enterprise Training Pipeline for Network IDS & Anomaly Detection",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--model",
        type=str,
        default="all",
        choices=["all", "rf", "xgb", "lstm", "isolation_forest", "main_three"],
        help="Specify which model to train.",
    )
    parser.add_argument(
        "--lstm-epochs",
        type=int,
        default=20,
        help="Number of epochs for LSTM training.",
    )
    parser.add_argument(
        "--contamination",
        type=float,
        default=0.02,
        help="Expected anomaly contamination rate for Isolation Forest "
             "(this is also the false-alarm budget on normal traffic).",
    )
    parser.add_argument(
        "--save-report",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Save comprehensive JSON report to models directory "
             "(use --no-save-report to skip).",
    )

    args = parser.parse_args()

    processed_dir = settings.data_processed_dir
    data = load_dataset(processed_dir)

    metrics_list = []

    if args.model in ["all", "rf", "main_three"]:
        metrics_list.append(train_random_forest(data))

    if args.model in ["all", "xgb", "main_three"]:
        metrics_list.append(train_xgboost(data))

    if args.model in ["all", "isolation_forest", "main_three"]:
        metrics_list.append(train_isolation_forest(data, contamination=args.contamination))

    if args.model in ["all", "lstm"]:
        metrics_list.append(train_lstm(data, epochs=args.lstm_epochs))

    print_summary_table(metrics_list)

    if args.save_report:
        report_path = settings.models_dir / "training_summary.json"
        report_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "dataset_info": {
                "n_train": len(data["X_train"]),
                "n_test": len(data["X_test"]),
                "n_features": data["meta"].get("n_features"),
                "classes": data["meta"].get("class_names"),
            },
            "models_evaluated": metrics_list,
        }
        with open(report_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2)
        logger.success(f"Full training report saved → {report_path}")


if __name__ == "__main__":
    main()