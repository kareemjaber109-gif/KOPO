import pickle
import numpy as np
from pathlib import Path
from xgboost import XGBClassifier
from sklearn.metrics import classification_report, f1_score, confusion_matrix
from src.utils.config import settings
from src.utils.logger import logger


class XGBModel:

    def __init__(self, n_classes: int = 8):
        self.n_classes   = n_classes
        self.class_names = []
        self.model       = XGBClassifier(
            n_estimators=400,
            max_depth=9,
            learning_rate=0.08,
            subsample=0.85,
            colsample_bytree=0.85,
            min_child_weight=3,
            gamma=0.05,
            objective="multi:softprob",
            num_class=n_classes,
            eval_metric="mlogloss",
            tree_method="hist",
            n_jobs=-1,
            random_state=settings.random_seed,
            verbosity=0,
        )

    def train(
        self,
        X_train: np.ndarray,
        y_train: np.ndarray,
        sample_weight: np.ndarray = None,
        use_cost_sensitive: bool = False,
        infilt_boost: float = 1.5,
    ):
        if sample_weight is None and use_cost_sensitive:
            from sklearn.utils.class_weight import compute_sample_weight
            logger.info(f"Applying Cost-Sensitive Sample Weights (balanced + Infiltration boost={infilt_boost}x)...")
            sample_weight = compute_sample_weight("balanced", y_train)
            if self.class_names and "Infiltration" in self.class_names:
                infilt_idx = self.class_names.index("Infiltration")
                sample_weight[y_train == infilt_idx] *= infilt_boost

        logger.info(f"Training High-Performance XGBoost ({self.model.n_estimators} trees, max_depth={self.model.max_depth}) on {len(X_train):,} samples...")
        self.model.fit(X_train, y_train, sample_weight=sample_weight)
        logger.success("XGBoost training complete")
        return self

    def predict(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict(X)

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        return self.model.predict_proba(X)

    def predict_single(self, features: np.ndarray) -> dict:
        proba = self.predict_proba(features.reshape(1, -1))[0]
        pred  = int(np.argmax(proba))
        names = self.class_names or [str(i) for i in range(len(proba))]
        label = names[pred] if pred < len(names) else f"class_{pred}"
        return {
            "prediction":        pred,
            "label":             label,
            "confidence":        float(proba[pred]),
            "is_attack":         label != "BENIGN",
            "all_probabilities": {
                names[i]: float(p) for i, p in enumerate(proba)
            },
        }

    def evaluate(self, X_test: np.ndarray, y_test: np.ndarray) -> dict:
        y_pred   = self.predict(X_test)
        macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
        report   = classification_report(
            y_test, y_pred,
            target_names=self.class_names or None,
            output_dict=True,
        )
        cm = confusion_matrix(y_test, y_pred)

        logger.info("\n" + classification_report(
            y_test, y_pred,
            target_names=self.class_names or None,
        ))
        logger.info(f"Confusion Matrix:\n{cm}")

        return {
            "macro_f1": float(macro_f1),
            "report": report,
            "confusion_matrix": cm.tolist(),
            "labels": self.class_names or list(range(self.n_classes)),
        }

    def feature_importance(self, feature_names: list, n: int = 15) -> list:
        scores  = self.model.feature_importances_
        indices = np.argsort(scores)[::-1][:n]
        return [
            {"feature": feature_names[i], "importance": float(scores[i])}
            for i in indices
        ]

    def save(self, path: Path = None) -> Path:
        if path is None:
            path = settings.models_dir / "xgboost.pkl"
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)
        logger.success(f"XGBoost saved → {path}")
        return path

    @classmethod
    def load(cls, path: Path = None):
        if path is None:
            path = settings.models_dir / "xgboost.pkl"
        with open(path, "rb") as f:
            obj = pickle.load(f)
        logger.info(f"XGBoost loaded from {path}")
        return obj