import pickle
from pathlib import Path
from typing import Optional
import numpy as np
from sklearn.ensemble import IsolationForest

from src.utils.config import settings
from src.utils.logger import logger


class FlowIsolationForest:
    """Isolation Forest Anomaly Detector calibrated on normal network flows."""

    def __init__(
        self,
        n_estimators: int = 200,
        max_samples: int | float = 50000,
        contamination: float = "auto",
        random_state: int = settings.random_seed,
    ):
        self.n_estimators = n_estimators
        self.max_samples = max_samples
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            max_samples=self.max_samples,
            contamination=self.contamination,
            random_state=self.random_state,
            n_jobs=-1,
        )
        self.is_fitted = False

    def train(self, X_train: np.ndarray):
        """Train Isolation Forest on Benign flows."""
        logger.info(
            f"Training Isolation Forest ({self.n_estimators} trees, max_samples={self.max_samples}) "
            f"on {len(X_train):,} Benign flows..."
        )
        self.model.fit(X_train)
        self.is_fitted = True
        logger.success("Isolation Forest training complete.")
        return self

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        """
        Compute continuous anomaly score where higher = more anomalous.
        sklearn score_samples() returns negative anomaly score (-path length offset),
        so we invert it with negation (-score_samples).
        """
        raw_scores = self.model.score_samples(X)
        return -raw_scores

    def save(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self.model, f)
        logger.success(f"Isolation Forest model saved → {path}")

    @classmethod
    def load(cls, path: Path):
        with open(path, "rb") as f:
            underlying = pickle.load(f)
        obj = cls()
        obj.model = underlying
        obj.is_fitted = True
        logger.info(f"Isolation Forest loaded from {path}")
        return obj
