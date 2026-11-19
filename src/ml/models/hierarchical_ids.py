import json
import pickle
from pathlib import Path
from typing import Dict, Any, List
import numpy as np

from src.utils.config import settings
from src.utils.logger import logger
from src.ml.models.random_forest import RFModel
from src.ml.models.xgboost_model import XGBModel


class HierarchicalIDS:
    """
    Two-Stage Hierarchical Intrusion Detection Architecture:
    - Stage 1 (Binary Guard): Random Forest / Binary Classifier filters normal vs suspicious flows.
    - Stage 2 (Multi-Class Expert): Cost-Sensitive XGBoost classifies the specific threat type.
    - Fusion Logic: Solves the single-flow argmax bottleneck for stealthy attacks (Infiltration/WebAttacks)
      by allowing Stage 1 to alert Stage 2, and Stage 2 to override borderline Stage 1 decisions.
    """

    def __init__(self, rf_model: RFModel = None, xgb_model: XGBModel = None, class_names: List[str] = None):
        self.rf = rf_model or RFModel()
        self.xgb = xgb_model or XGBModel()
        self.class_names = class_names or [
            "BENIGN", "Bot", "BruteForce", "DDoS", "DoS", "Infiltration", "PortScan", "WebAttack"
        ]
        self.xgb.class_names = self.class_names

    def load_models(self, rf_path: Path = None, xgb_path: Path = None):
        rf_path = rf_path or settings.models_dir / "random_forest.pkl"
        xgb_path = xgb_path or settings.models_dir / "xgboost.pkl"
        self.rf.load(rf_path)
        self.xgb = XGBModel.load(xgb_path)
        if not self.xgb.class_names:
            self.xgb.class_names = self.class_names
        return self

    def predict_binary(self, X: np.ndarray, attack_threshold: float = 0.35) -> np.ndarray:
        """
        Unified binary prediction using soft two-stage consensus:
        - If RF says ATTACK (1) -> ATTACK.
        - If XGBoost's combined attack probability exceeds threshold -> ATTACK.
        """
        rf_pred = self.rf.predict(X)
        xgb_proba = self.xgb.predict_proba(X)
        
        # XGBoost combined attack probability = 1.0 - proba(BENIGN)
        benign_idx = self.class_names.index("BENIGN") if "BENIGN" in self.class_names else 0
        xgb_attack_proba = 1.0 - xgb_proba[:, benign_idx]

        # Two-stage consensus:
        combined = (rf_pred == 1) | (xgb_attack_proba >= attack_threshold)
        return combined.astype(np.int32)

    def predict_multi(self, X: np.ndarray, attack_threshold: float = 0.35) -> np.ndarray:
        """
        Hierarchical multi-class prediction:
        - If binary guard flags flow as BENIGN -> 0 (BENIGN).
        - If flagged as ATTACK -> assign the most likely attack category (argmax excluding BENIGN).
        """
        is_attack = self.predict_binary(X, attack_threshold=attack_threshold)
        xgb_proba = self.xgb.predict_proba(X)
        benign_idx = self.class_names.index("BENIGN") if "BENIGN" in self.class_names else 0

        # Mask benign probability when flow is flagged as attack to pick best attack type
        attack_proba = xgb_proba.copy()
        attack_proba[:, benign_idx] = -1.0
        best_attack = np.argmax(attack_proba, axis=1)

        final_preds = np.where(is_attack == 1, best_attack, benign_idx)
        return final_preds

    def save(self, path: Path = None) -> Path:
        if path is None:
            path = settings.models_dir / "hierarchical_ids.pkl"
        with open(path, "wb") as f:
            pickle.dump(self, f)
        logger.success(f"Hierarchical IDS saved → {path}")
        return path

    @classmethod
    def load(cls, path: Path = None):
        if path is None:
            path = settings.models_dir / "hierarchical_ids.pkl"
        with open(path, "rb") as f:
            obj = pickle.load(f)
        return obj
