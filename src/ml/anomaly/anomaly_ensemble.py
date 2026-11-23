import json
import pickle
from pathlib import Path
from typing import Optional, Tuple
import numpy as np
from scipy import stats

from src.utils.logger import logger
from src.ml.anomaly.autoencoder import FlowAutoencoder
from src.ml.anomaly.isolation_forest import FlowIsolationForest


class AnomalyEnsemble:
    """
    Dual Anomaly Ensemble (Autoencoder + Isolation Forest):
    - Score Normalization: Empirical Percentile Rank calibrated strictly on Benign Validation flows.
    - Aggregation: Balanced 50/50 weighted combination in [0.0, 1.0].
    """

    def __init__(
        self,
        autoencoder: Optional[FlowAutoencoder] = None,
        iso_forest: Optional[FlowIsolationForest] = None,
        weight_ae: float = 0.5,
        weight_if: float = 0.5,
    ):
        self.ae = autoencoder
        self.if_model = iso_forest
        self.weight_ae = weight_ae
        self.weight_if = weight_if
        self.ref_ae_scores_sorted: Optional[np.ndarray] = None
        self.ref_if_scores_sorted: Optional[np.ndarray] = None
        self.threshold: float = 0.99  # default threshold (calibrated by threshold.py)

    def calibrate_percentiles(self, X_benign_val: np.ndarray):
        """Calibrate percentile rank references strictly on Benign Validation flows."""
        logger.info(f"Calibrating score percentiles on {len(X_benign_val):,} Benign Validation flows...")
        raw_ae = self.ae.reconstruction_error(X_benign_val)
        raw_if = self.if_model.anomaly_score(X_benign_val)

        self.ref_ae_scores_sorted = np.sort(raw_ae)
        self.ref_if_scores_sorted = np.sort(raw_if)
        logger.success("Empirical percentile rank calibration complete.")

    def _to_percentile_rank(self, scores: np.ndarray, sorted_ref: np.ndarray) -> np.ndarray:
        """Map raw score vector monotonically to [0.0, 1.0] using empirical CDF of benign reference."""
        idx = np.searchsorted(sorted_ref, scores, side="right")
        return idx / float(len(sorted_ref))

    def predict_score(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        Compute ensemble anomaly score:
        Returns:
            ensemble_score, p_ae, p_if
        """
        if self.ref_ae_scores_sorted is None or self.ref_if_scores_sorted is None:
            raise RuntimeError("AnomalyEnsemble percentiles not calibrated. Call calibrate_percentiles() first.")

        raw_ae = self.ae.reconstruction_error(X)
        raw_if = self.if_model.anomaly_score(X)

        p_ae = self._to_percentile_rank(raw_ae, self.ref_ae_scores_sorted)
        p_if = self._to_percentile_rank(raw_if, self.ref_if_scores_sorted)

        ensemble_score = (self.weight_ae * p_ae) + (self.weight_if * p_if)
        return ensemble_score, p_ae, p_if

    def predict_anomaly(self, X: np.ndarray, threshold: Optional[float] = None) -> np.ndarray:
        """Binary anomaly prediction: 1 if score >= threshold else 0."""
        t = threshold if threshold is not None else self.threshold
        scores, _, _ = self.predict_score(X)
        return (scores >= t).astype(np.int32)

    def save(self, directory: Path):
        directory.mkdir(parents=True, exist_ok=True)
        # Save models
        self.ae.save(directory / "autoencoder.pt")
        self.if_model.save(directory / "isolation_forest.pkl")

        bundle = {
            "ref_ae_scores_sorted": self.ref_ae_scores_sorted,
            "ref_if_scores_sorted": self.ref_if_scores_sorted,
            "weight_ae": self.weight_ae,
            "weight_if": self.weight_if,
            "threshold": self.threshold,
        }
        with open(directory / "ensemble_meta.pkl", "wb") as f:
            pickle.dump(bundle, f)

        config_json = {
            "threshold": self.threshold,
            "weight_ae": self.weight_ae,
            "weight_if": self.weight_if,
            "models": ["Autoencoder", "IsolationForest"],
            "calibration": "Percentile-Rank on Benign Validation",
        }
        with open(directory / "threshold_config.json", "w", encoding="utf-8") as f:
            json.dump(config_json, f, indent=2)
        logger.success(f"Anomaly Ensemble saved → {directory}")

    @classmethod
    def load(cls, directory: Path | str):
        directory = Path(directory)
        ae = FlowAutoencoder.load(directory / "autoencoder.pt")
        if_model = FlowIsolationForest.load(directory / "isolation_forest.pkl")

        with open(directory / "ensemble_meta.pkl", "rb") as f:
            bundle = pickle.load(f)

        obj = cls(
            autoencoder=ae,
            iso_forest=if_model,
            weight_ae=bundle.get("weight_ae", 0.5),
            weight_if=bundle.get("weight_if", 0.5),
        )
        obj.ref_ae_scores_sorted = bundle["ref_ae_scores_sorted"]
        obj.ref_if_scores_sorted = bundle["ref_if_scores_sorted"]
        obj.threshold = bundle.get("threshold", 0.99)
        logger.info(f"Anomaly Ensemble loaded from {directory} (threshold={obj.threshold:.4f})")
        return obj
