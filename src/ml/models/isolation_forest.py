import pickle
import numpy as np
from pathlib import Path
from typing import Optional
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, f1_score, roc_auc_score, confusion_matrix
from src.utils.config import settings
from src.utils.logger import logger


class IsolationForestModel:
    """
    Unsupervised Anomaly Detection Model using Isolation Forest.
    Trained strictly on normal (BENIGN) network flows to identify unseen
    and zero-day anomalies based on path length deviations.
    """

    def __init__(
        self,
        n_estimators: int = 250,
        max_samples: int | float = 50000,
        contamination: float = 0.03,
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

    def train(self, X_train: np.ndarray, y_train: Optional[np.ndarray] = None):
        if y_train is not None:
            # Filter strictly for normal traffic (0 = BENIGN)
            benign_mask = (y_train == 0)
            X_fit = X_train[benign_mask]
            logger.info(
                f"Training Isolation Forest ({self.n_estimators} trees, max_samples={self.max_samples}) on {len(X_fit):,} BENIGN flows..."
            )
        else:
            X_fit = X_train
            logger.info(f"Training Isolation Forest on {len(X_fit):,} unlabelled flows...")

        self.model.fit(X_fit)
        self.is_fitted = True
        logger.success("Isolation Forest training complete")
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        raw_preds = self.model.predict(X)
        return np.where(raw_preds == -1, 1, 0)

    def anomaly_score(self, X: np.ndarray) -> np.ndarray:
        raw_scores = self.model.decision_function(X)
        scores = 0.5 - (raw_scores / 2.0)
        return np.clip(scores, 0.0, 1.0)

    def predict_single(self, features: np.ndarray) -> dict:
        feat_reshaped = features.reshape(1, -1)
        pred_binary = int(self.predict(feat_reshaped)[0])
        score = float(self.anomaly_score(feat_reshaped)[0])

        is_attack = (pred_binary == 1)
        confidence = score if is_attack else (1.0 - score)

        return {
            "prediction": pred_binary,
            "label": "ATTACK" if is_attack else "BENIGN",
            "is_attack": is_attack,
            "anomaly_score": round(score, 4),
            "confidence": round(confidence, 4),
            "model": "IsolationForest",
        }

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        y_pred = self.predict(X_test)
        scores = self.anomaly_score(X_test)

        f1 = f1_score(y_test, y_pred, average="binary", zero_division=0)

        cm = confusion_matrix(y_test, y_pred)
        tn, fp, fn, tp = cm.ravel() if cm.shape == (2, 2) else (0, 0, 0, 0)

        tpr = tp / (tp + fn) if (tp + fn) > 0 else 0.0            # recall / detection rate
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0             # false alarm rate
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0       # NEW: real precision
        total = tp + tn + fp + fn
        accuracy = (tp + tn) / total if total > 0 else 0.0         # NEW: real accuracy

        try:
            auc = roc_auc_score(y_test, scores)
        except Exception:
            auc = 0.0

        report = classification_report(
            y_test, y_pred, target_names=["BENIGN", "ATTACK"],
            zero_division=0, output_dict=True,
        )

        logger.info("\n" + classification_report(
            y_test, y_pred, target_names=["BENIGN", "ATTACK"], zero_division=0
        ))
        logger.info(f"  Detection Rate (TPR) : {tpr * 100:.2f}%")
        logger.info(f"  False Alarm Rate(FPR): {fpr * 100:.2f}%")
        logger.info(f"  Precision            : {precision * 100:.2f}%")
        logger.info(f"  Accuracy             : {accuracy * 100:.2f}%")
        logger.info(f"  ROC-AUC Score        : {auc:.4f}")

        return {
            "f1": float(f1),
            "precision": float(precision),
            "recall": float(tpr),
            "accuracy": float(accuracy),
            "detection_rate_tpr": float(tpr),
            "false_alarm_rate_fpr": float(fpr),
            "roc_auc": float(auc),
            "report": report,
            "confusion_matrix": {"TN": int(tn), "FP": int(fp), "FN": int(fn), "TP": int(tp)},
        }

    def save(self, path: Path = None) -> Path:
        if path is None:
            path = settings.models_dir / "isolation_forest.pkl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)
        logger.success(f"Isolation Forest saved → {path}")
        return path

    @classmethod
    def load(cls, path: Path = None):
        if path is None:
            path = settings.models_dir / "isolation_forest.pkl"
        with open(path, "rb") as f:
            obj = pickle.load(f)
        logger.info(f"Isolation Forest loaded from {path}")
        return obj