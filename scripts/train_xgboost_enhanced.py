import sys
from pathlib import Path

# Add project root to sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import json
import time
import pickle
import numpy as np
from sklearn.metrics import classification_report, f1_score
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from src.utils.config import settings
from src.utils.logger import logger


def train_enhanced_xgboost():
    logger.info("=" * 65)
    logger.info("▶ Training High-Capacity XGBoost (Multi-Class + PortScan Focus)")
    logger.info("=" * 65)

    clean_dir = settings.data_processed_dir / "clean"
    run_dir = settings.models_dir / "run_clean_benchmark_v1"
    run_dir.mkdir(parents=True, exist_ok=True)

    with open(clean_dir / "metadata.json", "r", encoding="utf-8") as f:
        meta = json.load(f)

    feature_cols = meta["feature_columns"]
    class_names = meta["class_names"]
    n_classes = len(class_names)
    logger.info(f"Loaded metadata: {len(feature_cols)} features, {n_classes} classes: {class_names}")

    logger.info("Loading training and validation sets...")
    X_train = np.load(clean_dir / "X_train.npy")
    y_train_multi = np.load(clean_dir / "y_train_multi.npy")
    y_train_b = np.load(clean_dir / "y_train_binary.npy")

    X_val = np.load(clean_dir / "X_val.npy")
    y_val_multi = np.load(clean_dir / "y_val_multi.npy")

    X_test = np.load(clean_dir / "X_test.npy")
    y_test_multi = np.load(clean_dir / "y_test_multi.npy")

    # Subsampling: include ALL attacks (~235k) and representative 250k benign
    rng = np.random.RandomState(42)
    benign_idx = np.where(y_train_b == 0)[0]
    attack_idx = np.where(y_train_b == 1)[0]
    n_sample_benign = min(len(benign_idx), 250000)
    sampled_benign = rng.choice(benign_idx, size=n_sample_benign, replace=False)

    sub_train_idx = np.concatenate([attack_idx, sampled_benign])
    rng.shuffle(sub_train_idx)

    X_sub = X_train[sub_train_idx]
    y_sub = y_train_multi[sub_train_idx]

    logger.info(f"Subsampled Train: {len(X_sub):,} flows ({len(attack_idx):,} attacks, {n_sample_benign:,} benign)")

    # Compute balanced sample weights
    logger.info("Computing balanced class weights with priority multipliers...")
    sample_weights = compute_sample_weight("balanced", y_sub)

    # Class-specific multipliers to guarantee sharp discrimination for minority & scan attacks
    boost_map = {
        "PortScan": 3.5,       # Focus specifically on PortScan
        "Bot": 2.5,
        "Infiltration": 5.0,
        "WebAttack": 3.0,
        "BruteForce": 2.0,
    }

    for cname, mult in boost_map.items():
        if cname in class_names:
            cidx = class_names.index(cname)
            mask = (y_sub == cidx)
            count = np.sum(mask)
            sample_weights[mask] *= mult
            logger.info(f"  Boosted {cname} (class {cidx}, count={count}): {mult}x weight")

    # Define high-capacity XGBoost model
    xgb = XGBClassifier(
        n_estimators=300,
        max_depth=9,
        learning_rate=0.08,
        subsample=0.85,
        colsample_bytree=0.85,
        min_child_weight=1,
        gamma=0.05,
        objective="multi:softprob",
        num_class=n_classes,
        eval_metric="mlogloss",
        tree_method="hist",
        n_jobs=-1,
        random_state=42,
        verbosity=1,
    )

    logger.info("Fitting XGBoost model...")
    t0 = time.time()
    xgb.fit(X_sub, y_sub, sample_weight=sample_weights)
    train_time = time.time() - t0
    logger.success(f"XGBoost trained successfully in {train_time:.1f}s")

    # Evaluate on Validation Set
    logger.info("\nEvaluating on Validation Set:")
    y_val_pred = xgb.predict(X_val)
    val_macro_f1 = f1_score(y_val_multi, y_val_pred, average="macro", zero_division=0)
    logger.info(f"Validation Macro F1: {val_macro_f1:.4f}")

    # Evaluate on Test Set
    logger.info("\nEvaluating on Test Set:")
    y_test_pred = xgb.predict(X_test)
    test_macro_f1 = f1_score(y_test_multi, y_test_pred, average="macro", zero_division=0)
    logger.success(f"Test Macro F1: {test_macro_f1:.4f}")

    test_report = classification_report(
        y_test_multi,
        y_test_pred,
        target_names=class_names,
        digits=4,
        zero_division=0,
    )
    logger.info(f"\nClassification Report on Test Block:\n{test_report}")

    # Attach class_names directly onto the model object
    xgb.class_names = class_names

    # Save to run_clean_benchmark_v1 and base models dir
    save_paths = [
        run_dir / "xgboost.pkl",
        settings.models_dir / "xgboost.pkl",
    ]

    for p in save_paths:
        with open(p, "wb") as f:
            pickle.dump(xgb, f)
        logger.success(f"Saved model to: {p}")

    logger.info("=" * 65)
    logger.info("▶ XGBoost Retraining Completed Successfully!")
    logger.info("=" * 65)


if __name__ == "__main__":
    train_enhanced_xgboost()
