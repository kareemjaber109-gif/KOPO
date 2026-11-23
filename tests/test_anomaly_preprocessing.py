"""Self-contained tests for the anomaly preprocessing (no dataset needed).

Run like the existing engine test:   python -m tests.test_anomaly_preprocessing
or with pytest:                      pytest tests/test_anomaly_preprocessing.py
"""
import tempfile

import numpy as np
import pandas as pd

from src.ml.anomaly.preprocessing import (
    AnomalyPreprocessor, MissingFeaturesError, canon_key,
)

FEATS = ["Flow Duration", "Total Fwd Packets", "Flow Bytes/s", "Packet Length Mean", "SYN Flag Count"]


def _benign(n=2000, seed=0):
    rng = np.random.default_rng(seed)
    df = pd.DataFrame(rng.lognormal(3, 1.5, (n, len(FEATS))), columns=FEATS)
    df["SYN Flag Count"] = rng.integers(0, 2, n)
    return df


def test_short_and_long_names_match():
    assert canon_key("Tot Fwd Pkts") == canon_key(" Total Fwd Packets")
    assert canon_key("Flow Byts/s") == canon_key("Flow Bytes/s")
    assert canon_key("Init_Win_bytes_forward") == canon_key("Init Fwd Win Byts")


def test_fit_is_benign_only_and_standardised():
    train = _benign()
    pre = AnomalyPreprocessor().fit(train, FEATS)
    Z = pre.transform(train)
    assert np.allclose(Z.mean(0), 0, atol=1e-3) and np.allclose(Z.std(0), 1, atol=1e-2)


def test_outliers_are_clipped():
    train = _benign()
    pre = AnomalyPreprocessor().fit(train, FEATS)
    spike = train.iloc[[0]].copy()
    spike["Flow Bytes/s"] = 1e15
    z = pre.transform(spike)[0, pre.features.index("Flow Bytes/s")]
    zmax = pre.transform(train)[:, pre.features.index("Flow Bytes/s")].max()
    assert z <= zmax + 1e-4        # clipped at the Benign p99.9, not 1e15


def test_save_load_roundtrip_and_name_conventions():
    train = _benign()
    pre = AnomalyPreprocessor().fit(train, FEATS)
    with tempfile.TemporaryDirectory() as d:
        pre.save(d)
        loaded = AnomalyPreprocessor.load(d)
    renamed = train.rename(columns={"Total Fwd Packets": " Tot Fwd Pkts", "Flow Bytes/s": "flow_byts/s"})
    assert np.allclose(pre.transform(train), loaded.transform(renamed), atol=1e-6)


def test_bad_values_and_missing_features():
    train = _benign()
    pre = AnomalyPreprocessor().fit(train, FEATS)
    row = train.iloc[[0]].copy()
    row["Flow Bytes/s"] = np.inf
    assert np.isfinite(pre.transform(row)).all()
    try:
        pre.transform(row.drop(columns=["Flow Duration"]))
        raise AssertionError("expected MissingFeaturesError")
    except MissingFeaturesError:
        pass
    assert np.isfinite(pre.transform(row.drop(columns=["Flow Duration"]), strict=False)).all()


def test_zero_variance_feature_is_dropped():
    train = _benign()
    train["SYN Flag Count"] = 0
    pre = AnomalyPreprocessor().fit(train, FEATS)
    assert "SYN Flag Count" not in pre.features and "SYN Flag Count" in pre.dropped_zero_variance


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for t in tests:
        t()
        print("PASS", t.__name__)
    print(f"{len(tests)} tests passed")
