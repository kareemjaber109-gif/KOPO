import json
from pathlib import Path
from typing import Dict, Any
import numpy as np

from src.utils.logger import logger
from src.ml.anomaly.anomaly_ensemble import AnomalyEnsemble


def calibrate_and_select_threshold(
    ensemble: AnomalyEnsemble,
    X_val: np.ndarray,
    y_val_binary: np.ndarray,
    source_val: np.ndarray,
    target_percentile: float = 99.0,
) -> Dict[str, Any]:
    """
    Select decision threshold strictly from Benign validation flows at target_percentile (default 99th percentile = ~1% FPR).
    Evaluates independent FPR on UNSW Benign vs CICIDS2017 Benign.
    """
    logger.info("=" * 65)
    logger.info(f"▶ Calibrating Decision Threshold at {target_percentile}th Percentile on Benign Validation")
    logger.info("=" * 65)

    # 1. Filter Benign validation flows only (ZERO leakage from attacks!)
    benign_mask = (y_val_binary == 0)
    X_benign_val = X_val[benign_mask]
    source_benign_val = source_val[benign_mask]

    # 2. First calibrate the empirical percentile rank tables on Benign validation
    ensemble.calibrate_percentiles(X_benign_val)

    # 3. Compute ensemble scores on Benign validation flows
    scores_benign, _, _ = ensemble.predict_score(X_benign_val)

    # 4. Threshold is the exact 99th percentile of Benign validation scores
    threshold = float(np.percentile(scores_benign, target_percentile))
    ensemble.threshold = threshold
    logger.info(f"Selected Operational Anomaly Threshold: {threshold:.4f} (at {target_percentile}% percentile)")

    # 5. Measure independent FPR for each source on Benign validation
    # Source can be string ('unsw', 'cicids2017') or numeric (0, 1)
    unsw_mask = (source_benign_val == "unsw") | (source_benign_val == 0) | (source_benign_val == "0")
    cic_mask = (source_benign_val == "cicids2017") | (source_benign_val == 1) | (source_benign_val == "1")

    fpr_overall = float(np.mean(scores_benign >= threshold))
    fpr_unsw = float(np.mean(scores_benign[unsw_mask] >= threshold)) if np.any(unsw_mask) else None
    fpr_cic = float(np.mean(scores_benign[cic_mask] >= threshold)) if np.any(cic_mask) else None

    logger.info("\nValidation Benign False Alarm Rate (FPR) Verification:")
    logger.info(f"  Overall Benign FPR        : {fpr_overall * 100:.2f}% (Target: ~1.00%)")
    if fpr_unsw is not None:
        logger.info(f"  UNSW-NB15 Benign FPR      : {fpr_unsw * 100:.2f}%")
    if fpr_cic is not None:
        logger.info(f"  CICIDS2017 Benign FPR     : {fpr_cic * 100:.2f}%")

    config = {
        "threshold": threshold,
        "target_percentile": target_percentile,
        "fpr_overall": fpr_overall,
        "fpr_unsw": fpr_unsw,
        "fpr_cicids": fpr_cic,
        "n_benign_val_total": int(len(scores_benign)),
        "n_unsw_benign_val": int(np.sum(unsw_mask)),
        "n_cicids_benign_val": int(np.sum(cic_mask)),
    }
    return config
