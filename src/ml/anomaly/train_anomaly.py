import json
import time
from pathlib import Path
import numpy as np

from src.utils.config import settings
from src.utils.logger import logger
from src.ml.anomaly.autoencoder import FlowAutoencoder
from src.ml.anomaly.isolation_forest import FlowIsolationForest
from src.ml.anomaly.anomaly_ensemble import AnomalyEnsemble
from src.ml.anomaly.threshold import calibrate_and_select_threshold


def train_anomaly_pipeline(epochs: int = 15, batch_size: int = 512):
    data_dir = settings.data_processed_dir / "unsw"
    models_dir = settings.models_dir / "anomaly"
    models_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 65)
    logger.info("▶ Starting Anomaly Detection Training Pipeline")
    logger.info("=" * 65)

    # 1. Load data
    logger.info(f"Loading preprocessed arrays from {data_dir}...")
    train_data = np.load(data_dir / "train.npz")
    val_data = np.load(data_dir / "val.npz")
    X_train_b = train_data["X"]
    X_val = val_data["X"]
    y_val_b = val_data["y"]
    source_val = val_data["source"]

    input_dim = X_train_b.shape[1]
    logger.info(f"Dataset Loaded: {len(X_train_b):,} Benign Train flows, {len(X_val):,} Val flows, {input_dim} features.")

    # 2. Train Model 1: PyTorch Autoencoder (Strictly on Benign Train!)
    logger.info("\n" + "-" * 50)
    logger.info("▶ [1/2] Training PyTorch Deep Autoencoder")
    logger.info("-" * 50)
    ae = FlowAutoencoder(input_dim=input_dim, latent_dim=12)
    start_ae = time.time()
    ae.train(X_train_b, epochs=epochs, batch_size=batch_size, lr=0.001)
    train_time_ae = time.time() - start_ae

    # 3. Train Model 2: Isolation Forest (Strictly on Benign Train!)
    logger.info("\n" + "-" * 50)
    logger.info("▶ [2/2] Training Scikit-Learn Isolation Forest")
    logger.info("-" * 50)
    iso_forest = FlowIsolationForest(n_estimators=200, max_samples=50000)
    start_if = time.time()
    iso_forest.train(X_train_b)
    train_time_if = time.time() - start_if

    # 4. Assemble Ensemble & Calibrate Threshold at 99th percentile of Benign Val
    logger.info("\n" + "-" * 50)
    logger.info("▶ [3/3] Assembling Ensemble & Calibrating 99th Percentile Threshold")
    logger.info("-" * 50)
    ensemble = AnomalyEnsemble(autoencoder=ae, iso_forest=iso_forest, weight_ae=0.5, weight_if=0.5)

    threshold_info = calibrate_and_select_threshold(
        ensemble=ensemble,
        X_val=X_val,
        y_val_binary=y_val_b,
        source_val=source_val,
        target_percentile=99.0,
    )

    # 5. Persist Models and Configurations
    logger.info(f"\nSaving trained models to {models_dir}...")
    ensemble.save(models_dir)

    summary = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "input_dim": input_dim,
        "n_train_benign": len(X_train_b),
        "train_time_autoencoder_sec": round(train_time_ae, 2),
        "train_time_isolation_forest_sec": round(train_time_if, 2),
        "threshold_calibration": threshold_info,
    }
    with open(models_dir / "training_summary.json", "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    logger.success("=" * 65)
    logger.success("✔ Anomaly Training & Calibration Completed Successfully!")
    logger.info(f"  Autoencoder Training Time: {train_time_ae:.1f}s")
    logger.info(f"  Isolation Forest Time    : {train_time_if:.1f}s")
    logger.info(f"  Calibrated Threshold     : {ensemble.threshold:.4f}")
    logger.info(f"  Saved Models Directory   : {models_dir}")
    logger.success("=" * 65)
    return ensemble


if __name__ == "__main__":
    train_anomaly_pipeline(epochs=15, batch_size=512)
