import json
import pickle
from pathlib import Path
import numpy as np

from src.utils.config import settings
from src.utils.logger import logger
from src.ml.anomaly.anomaly_ensemble import AnomalyEnsemble


def recalibrate_and_create_manifest():
    data_dir = settings.data_processed_dir / "unsw"
    anomaly_dir = settings.models_dir / "anomaly"

    logger.info("Loading validation data for Anomaly Recalibration...")
    val_data = np.load(data_dir / "val.npz")
    X_val = val_data["X"]
    y_val = val_data["y"]
    source_val = val_data["source"]

    benign_mask = (y_val == 0)
    X_benign = X_val[benign_mask]
    source_benign = source_val[benign_mask]

    n_benign_total = len(X_benign)
    unsw_mask = (source_benign == "unsw")
    cic_mask = (source_benign == "cicids2017")
    n_unsw_benign = int(np.sum(unsw_mask))
    n_cic_benign = int(np.sum(cic_mask))

    logger.info(f"Benign Validation flows: total={n_benign_total:,} (UNSW={n_unsw_benign:,}, CIC-IDS2017={n_cic_benign:,})")

    # Load anomaly ensemble
    ensemble = AnomalyEnsemble.load(anomaly_dir)

    # Compute scores on benign validation
    scores_benign, p_ae, p_if = ensemble.predict_score(X_benign)

    # Calibrate at exactly 99th percentile (FPR <= 1.0%)
    target_percentile = 99.0
    threshold = float(np.percentile(scores_benign, target_percentile))
    ensemble.threshold = threshold

    # Compute per-source FPR
    fpr_overall = float(np.mean(scores_benign >= threshold))
    fpr_unsw = float(np.mean(scores_benign[unsw_mask] >= threshold))
    fpr_cic = float(np.mean(scores_benign[cic_mask] >= threshold))

    logger.success(f"Recalibrated Threshold at {target_percentile}th percentile: {threshold:.6f}")
    logger.info(f"  Overall Benign FPR        : {fpr_overall * 100:.3f}% (target <= 1.00%)")
    logger.info(f"  UNSW-NB15 Benign FPR      : {fpr_unsw * 100:.3f}%")
    logger.info(f"  CIC-IDS2017 Benign FPR     : {fpr_cic * 100:.3f}%")

    # 1. Update ensemble_meta.pkl
    meta_path = anomaly_dir / "ensemble_meta.pkl"
    with open(meta_path, "rb") as f:
        bundle = pickle.load(f)
    bundle["threshold"] = threshold
    with open(meta_path, "wb") as f:
        pickle.dump(bundle, f)
    logger.info(f"Updated {meta_path} with threshold {threshold:.6f}")

    # 2. Update threshold_config.json
    config_path = anomaly_dir / "threshold_config.json"
    config = {
        "threshold": threshold,
        "target_percentile": target_percentile,
        "weight_ae": ensemble.weight_ae,
        "weight_if": ensemble.weight_if,
        "models": ["Autoencoder", "IsolationForest"],
        "calibration": "Percentile-Rank on Benign Validation (99th percentile)",
        "fpr_overall": fpr_overall,
        "fpr_unsw": fpr_unsw,
        "fpr_cicids2017": fpr_cic
    }
    with open(config_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    logger.info(f"Updated {config_path}")

    # 3. Create independent manifest.json (data_origin=real)
    manifest_path = anomaly_dir / "manifest.json"
    manifest = {
        "run_id": "anomaly_real_v1",
        "data_origin": "real",
        "model_type": "anomaly_ensemble",
        "status": "ready",
        "dataset": "UNSW-NB15 + CIC-IDS2017 Benign Baseline",
        "target_percentile": target_percentile,
        "threshold": threshold,
        "calibration": {
            "total_benign_val": n_benign_total,
            "n_unsw_benign_val": n_unsw_benign,
            "n_cicids_benign_val": n_cic_benign,
            "fpr_overall": fpr_overall,
            "fpr_unsw": fpr_unsw,
            "fpr_cicids2017": fpr_cic,
        },
        "components": [
            "autoencoder.pt",
            "isolation_forest.pkl",
            "ensemble_meta.pkl",
            "scaler_anomaly.pkl",
            "feature_names.json",
            "threshold_config.json"
        ],
        "action_routing": {
            "above_threshold": "REVIEW",
            "below_threshold": "ALLOW"
        }
    }
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
    logger.success(f"Created independent Anomaly manifest: {manifest_path} (data_origin=real)")


if __name__ == "__main__":
    recalibrate_and_create_manifest()
