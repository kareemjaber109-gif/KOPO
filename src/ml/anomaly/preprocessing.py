"""Shared preprocessing for the KOPO anomaly detectors.

One class is used for BOTH training (prepare_unsw_nb15.py) and inference
(detection_engine.py) so the two can never drift apart (train/serve skew).

Pipeline (all statistics are fitted on Benign-train only):
    raw flow -> fill NaN/inf with Benign median -> signed log1p
             -> clip to [p0.1, p99.9] of Benign-train -> StandardScaler

Artifacts written by ``save``:
    scaler_anomaly.pkl   sklearn StandardScaler (independent of KOPO's scaler.pkl)
    feature_names.json   ordered feature list + clip bounds + fill values
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable, Mapping, Sequence

import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler

ARTIFACT_VERSION = 1
SCALER_FILE = "scaler_anomaly.pkl"
FEATURES_FILE = "feature_names.json"

# --------------------------------------------------------------------------- #
# Column-name canonicalisation
# CICFlowMeter v3 "short" names (CIC-IDS2018 / many newer exports) -> CICIDS2017
# names. Matching is done on a normalised key, so case, spaces, underscores and
# leading spaces (" Destination Port") never matter.
# --------------------------------------------------------------------------- #
_SHORT_TO_2017_PAIRS = [
    ("Dst Port", "Destination Port"),
    ("Tot Fwd Pkts", "Total Fwd Packets"),
    ("Tot Bwd Pkts", "Total Backward Packets"),
    ("TotLen Fwd Pkts", "Total Length of Fwd Packets"),
    ("TotLen Bwd Pkts", "Total Length of Bwd Packets"),
    ("Fwd Pkt Len Max", "Fwd Packet Length Max"),
    ("Fwd Pkt Len Min", "Fwd Packet Length Min"),
    ("Fwd Pkt Len Mean", "Fwd Packet Length Mean"),
    ("Fwd Pkt Len Std", "Fwd Packet Length Std"),
    ("Bwd Pkt Len Max", "Bwd Packet Length Max"),
    ("Bwd Pkt Len Min", "Bwd Packet Length Min"),
    ("Bwd Pkt Len Mean", "Bwd Packet Length Mean"),
    ("Bwd Pkt Len Std", "Bwd Packet Length Std"),
    ("Flow Byts/s", "Flow Bytes/s"),
    ("Flow Pkts/s", "Flow Packets/s"),
    ("Fwd Header Len", "Fwd Header Length"),
    ("Bwd Header Len", "Bwd Header Length"),
    ("Fwd Pkts/s", "Fwd Packets/s"),
    ("Bwd Pkts/s", "Bwd Packets/s"),
    ("Pkt Len Min", "Min Packet Length"),
    ("Pkt Len Max", "Max Packet Length"),
    ("Pkt Len Mean", "Packet Length Mean"),
    ("Pkt Len Std", "Packet Length Std"),
    ("Pkt Len Var", "Packet Length Variance"),
    ("FIN Flag Cnt", "FIN Flag Count"),
    ("SYN Flag Cnt", "SYN Flag Count"),
    ("RST Flag Cnt", "RST Flag Count"),
    ("PSH Flag Cnt", "PSH Flag Count"),
    ("ACK Flag Cnt", "ACK Flag Count"),
    ("URG Flag Cnt", "URG Flag Count"),
    ("ECE Flag Cnt", "ECE Flag Count"),
    ("Pkt Size Avg", "Average Packet Size"),
    ("Fwd Seg Size Avg", "Avg Fwd Segment Size"),
    ("Bwd Seg Size Avg", "Avg Bwd Segment Size"),
    ("Fwd Byts/b Avg", "Fwd Avg Bytes/Bulk"),
    ("Fwd Pkts/b Avg", "Fwd Avg Packets/Bulk"),
    ("Fwd Blk Rate Avg", "Fwd Avg Bulk Rate"),
    ("Bwd Byts/b Avg", "Bwd Avg Bytes/Bulk"),
    ("Bwd Pkts/b Avg", "Bwd Avg Packets/Bulk"),
    ("Bwd Blk Rate Avg", "Bwd Avg Bulk Rate"),
    ("Subflow Fwd Pkts", "Subflow Fwd Packets"),
    ("Subflow Fwd Byts", "Subflow Fwd Bytes"),
    ("Subflow Bwd Pkts", "Subflow Bwd Packets"),
    ("Subflow Bwd Byts", "Subflow Bwd Bytes"),
    ("Init Fwd Win Byts", "Init_Win_bytes_forward"),
    ("Init Bwd Win Byts", "Init_Win_bytes_backward"),
    ("Fwd Act Data Pkts", "act_data_pkt_fwd"),
    ("Fwd Seg Size Min", "min_seg_size_forward"),
    # UNSW & Parquet specific variants mapped to canonical CICIDS2017 names
    ("Total Fwd Packet", "Total Fwd Packets"),
    ("Total Bwd packets", "Total Backward Packets"),
    ("Total Length of Fwd Packet", "Total Length of Fwd Packets"),
    ("Total Length of Bwd Packet", "Total Length of Bwd Packets"),
    ("Fwd Packets Length Total", "Total Length of Fwd Packets"),
    ("Bwd Packets Length Total", "Total Length of Bwd Packets"),
    ("Avg Packet Size", "Average Packet Size"),
    ("Fwd Segment Size Avg", "Avg Fwd Segment Size"),
    ("Bwd Segment Size Avg", "Avg Bwd Segment Size"),
    ("Fwd Bytes/Bulk Avg", "Fwd Avg Bytes/Bulk"),
    ("Fwd Packet/Bulk Avg", "Fwd Avg Packets/Bulk"),
    ("Fwd Bulk Rate Avg", "Fwd Avg Bulk Rate"),
    ("Bwd Bytes/Bulk Avg", "Bwd Avg Bytes/Bulk"),
    ("Bwd Packet/Bulk Avg", "Bwd Avg Packets/Bulk"),
    ("Bwd Bulk Rate Avg", "Bwd Avg Bulk Rate"),
    ("FWD Init Win Bytes", "Init_Win_bytes_forward"),
    ("Bwd Init Win Bytes", "Init_Win_bytes_backward"),
    ("Init Fwd Win Bytes", "Init_Win_bytes_forward"),
    ("Init Bwd Win Bytes", "Init_Win_bytes_backward"),
    ("Fwd Act Data Packets", "act_data_pkt_fwd"),
    ("CWR Flag Count", "CWE Flag Count"),
]

# Columns that identify a flow or the testbed rather than describe its behaviour.
# (Protocol is dropped by project decision; Destination Port because raw port
# numbers are testbed-specific and widen the UNSW <-> CICIDS domain gap.)
# Keys are normalised (see ``canon_key``).
NON_BEHAVIORAL_KEYS = {
    "flowid", "srcip", "sourceip", "dstip", "destinationip",
    "srcport", "sourceport", "timestamp", "protocol", "unnamed0",
    "label", "labels", "attack", "attackcat", "attackcategory", "class",
    "category", "binarylabel", "binarylabels", "target",
}
PORT_KEYS = {"dstport", "destinationport"}


def _norm(name: object) -> str:
    s = str(name).strip().lower().replace("_", " ")
    return re.sub(r"\s+", " ", s)


_ALIAS = {_norm(short): long for short, long in _SHORT_TO_2017_PAIRS}


def display_name(name: object) -> str:
    """Name in CICIDS2017 style (stripped); unknown names are returned stripped."""
    n = _norm(name)
    return _ALIAS.get(n, str(name).strip())


def canon_key(name: object) -> str:
    """Matching key that is identical for equivalent names in both conventions."""
    return re.sub(r"[^a-z0-9]", "", display_name(name).lower())


def signed_log1p(x: np.ndarray) -> np.ndarray:
    return np.sign(x) * np.log1p(np.abs(x))


class MissingFeaturesError(ValueError):
    pass


class AnomalyPreprocessor:
    """Fit on Benign-train only; transform anything."""

    def __init__(self, clip_quantiles: tuple[float, float] = (0.001, 0.999)):
        self.clip_quantiles = tuple(clip_quantiles)
        self.features: list[str] = []          # display names, in model order
        self.feature_keys: list[str] = []
        self.fill_values: np.ndarray | None = None
        self.clip_lo: np.ndarray | None = None
        self.clip_hi: np.ndarray | None = None
        self.dropped_zero_variance: list[str] = []
        self.scaler: StandardScaler | None = None

    # ------------------------------------------------------------------ fit
    def fit(self, df: pd.DataFrame, features: Sequence[str]) -> "AnomalyPreprocessor":
        """``df`` columns must already be named exactly like ``features``."""
        X = df[list(features)].apply(pd.to_numeric, errors="coerce").to_numpy(np.float64, copy=True)
        X[~np.isfinite(X)] = np.nan
        fill = np.nanmedian(X, axis=0)
        fill = np.where(np.isfinite(fill), fill, 0.0)
        X = np.where(np.isnan(X), fill, X)

        Z = signed_log1p(X)
        lo = np.quantile(Z, self.clip_quantiles[0], axis=0)
        hi = np.quantile(Z, self.clip_quantiles[1], axis=0)
        Z = np.clip(Z, lo, hi)

        keep = Z.std(axis=0) > 1e-12
        feats = np.asarray(list(features))
        self.dropped_zero_variance = feats[~keep].tolist()
        self.features = feats[keep].tolist()
        self.feature_keys = [canon_key(f) for f in self.features]
        self.fill_values = fill[keep]
        self.clip_lo = lo[keep]
        self.clip_hi = hi[keep]
        self.scaler = StandardScaler().fit(Z[:, keep])
        return self

    # ------------------------------------------------------------ transform
    def transform(self, data: pd.DataFrame | Mapping | Iterable[Mapping],
                  strict: bool = True) -> np.ndarray:
        """Return float32 array (n, n_features).

        ``data`` may be a DataFrame, one dict (a single flow) or a list of dicts
        with ANY of the supported naming conventions. Features are picked by
        name, never by position. With ``strict=False`` a missing feature is
        replaced by its Benign median instead of raising.
        """
        self._check_fitted()
        if isinstance(data, Mapping):
            df = pd.DataFrame([data])
        elif isinstance(data, pd.DataFrame):
            df = data
        else:
            df = pd.DataFrame(list(data))

        by_key = {canon_key(c): c for c in df.columns}
        missing = [f for f, k in zip(self.features, self.feature_keys) if k not in by_key]
        if missing and strict:
            raise MissingFeaturesError(
                f"{len(missing)} feature(s) missing for the anomaly model: {missing[:8]}"
                + (" ..." if len(missing) > 8 else ""))

        cols = []
        for i, k in enumerate(self.feature_keys):
            if k in by_key:
                col = pd.to_numeric(df[by_key[k]], errors="coerce").to_numpy(np.float64)
            else:
                col = np.full(len(df), np.nan)
            cols.append(col)
        X = np.column_stack(cols) if cols else np.empty((len(df), 0))
        X[~np.isfinite(X)] = np.nan
        X = np.where(np.isnan(X), self.fill_values, X)
        Z = np.clip(signed_log1p(X), self.clip_lo, self.clip_hi)
        return self.scaler.transform(Z).astype(np.float32)

    # ---------------------------------------------------------- persistence
    def save(self, out_dir: str | Path) -> None:
        self._check_fitted()
        out = Path(out_dir)
        out.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.scaler, out / SCALER_FILE)
        meta = {
            "version": ARTIFACT_VERSION,
            "transform": "fill_median -> signed_log1p -> clip -> standard_scaler",
            "clip_quantiles": list(self.clip_quantiles),
            "features": self.features,
            "n_features": len(self.features),
            "clip_lo": self.clip_lo.tolist(),
            "clip_hi": self.clip_hi.tolist(),
            "fill_values": self.fill_values.tolist(),
            "dropped_zero_variance": self.dropped_zero_variance,
        }
        (out / FEATURES_FILE).write_text(json.dumps(meta, indent=2), encoding="utf-8")

    @classmethod
    def load(cls, model_dir: str | Path) -> "AnomalyPreprocessor":
        d = Path(model_dir)
        meta = json.loads((d / FEATURES_FILE).read_text(encoding="utf-8"))
        if meta.get("version") != ARTIFACT_VERSION:
            raise ValueError(f"Unsupported anomaly preprocessing version: {meta.get('version')}")
        obj = cls(tuple(meta["clip_quantiles"]))
        obj.features = list(meta["features"])
        obj.feature_keys = [canon_key(f) for f in obj.features]
        obj.clip_lo = np.asarray(meta["clip_lo"], dtype=np.float64)
        obj.clip_hi = np.asarray(meta["clip_hi"], dtype=np.float64)
        obj.fill_values = np.asarray(meta["fill_values"], dtype=np.float64)
        obj.dropped_zero_variance = list(meta.get("dropped_zero_variance", []))
        obj.scaler = joblib.load(d / SCALER_FILE)
        return obj

    def _check_fitted(self) -> None:
        if self.scaler is None:
            raise RuntimeError("AnomalyPreprocessor is not fitted/loaded")
