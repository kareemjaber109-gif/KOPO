import os
import json
from pathlib import Path
import pytest
from src.ml.detection_engine import DetectionEngine


@pytest.fixture(autouse=True)
def clean_engine_singleton():
    """Ensure clean singleton instance before each test."""
    DetectionEngine._instance = None
    yield
    DetectionEngine._instance = None


def test_engine_singleton():
    """Verify DetectionEngine enforces the singleton pattern."""
    e1 = DetectionEngine.get_instance()
    e2 = DetectionEngine.get_instance()
    assert e1 is e2


def test_feature_completion_and_derivation():
    """Verify partial network flow dictionaries are completed with expected flow metrics."""
    partial_flow = {
        "Destination Port": 80,
        "Flow Duration": 50000,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 5,
        "Fwd Packet Length Max": 1460,
    }
    completed = DetectionEngine._complete_partial_features(partial_flow)
    assert "Flow Bytes/s" in completed
    assert "Flow Packets/s" in completed
    assert "Avg Packet Size" in completed
    assert completed["Total Fwd Packets"] == 10
    assert completed["Destination Port"] == 80


def test_severity_calculation():
    """Verify severity calculation conforms to SOC standards (ANOMALY capped at Medium)."""
    engine = DetectionEngine()
    
    # Benign flow
    benign_sev = engine._severity("BENIGN", 0.99)
    assert benign_sev["severity_score"] == 0
    assert benign_sev["severity_label"] == "None"
    assert benign_sev["is_attack"] is False

    # Anomaly flow (capped at score 3 / Medium)
    anomaly_sev = engine._severity("ANOMALY", 0.99)
    assert anomaly_sev["severity_score"] <= 3
    assert anomaly_sev["severity_label"] in ["Medium", "Low", "Info"]

    # Critical Attack (DDoS / DoS)
    dos_sev = engine._severity("DDOS_ATTACK", 0.98)
    assert dos_sev["severity_score"] >= 4
    assert dos_sev["severity_label"] in ["High", "Critical"]
    assert dos_sev["is_attack"] is True


def test_anomaly_manifest_exists_and_is_real():
    """Verify data/models/anomaly/manifest.json exists and specifies certified real data."""
    manifest_path = Path("data/models/anomaly/manifest.json")
    assert manifest_path.exists(), "Anomaly manifest.json is missing"
    
    with open(manifest_path, "r", encoding="utf-8") as f:
        meta = json.load(f)
        
    assert meta["data_origin"] == "real"
    assert meta["model_type"] == "anomaly_ensemble"
    assert meta["status"] == "ready"
    assert meta["target_percentile"] >= 99.0
    assert meta["calibration"]["fpr_overall"] <= 0.011
    assert "action_routing" in meta
    assert meta["action_routing"]["above_threshold"] == "REVIEW"
    assert meta["action_routing"]["below_threshold"] == "ALLOW"


def test_engine_strict_mode_anomaly_loaded():
    """Verify in strict mode that anomaly ensemble loads with real origin and certified real models are active."""
    os.environ["KOPO_DEMO_MODE"] = "false"
    engine = DetectionEngine.get_instance()
    engine.load()

    # Real benchmark run is active, so data_origin is real and production engine is ready
    assert engine.data_origin == "real"
    assert engine.is_ready is True

    # Anomaly model is independent real run
    assert engine.anomaly_ready is True
    assert engine.anomaly_origin == "real"
    assert engine.anomaly_ensemble is not None
    assert engine.anomaly_ensemble.threshold >= 0.98


def test_engine_demo_mode_full_predict():
    """Verify demo mode loads models and executes end-to-end prediction with action routing."""
    os.environ["KOPO_DEMO_MODE"] = "true"
    engine = DetectionEngine.get_instance()
    engine.load()

    assert engine.is_ready is True

    # 1. Normal traffic
    normal_flow = {
        "Protocol": 6,
        "Destination Port": 443,
        "Flow Duration": 50000,
        "Total Fwd Packets": 10,
        "Total Backward Packets": 8,
        "Fwd Packet Length Max": 512,
        "Flow Bytes/s": 1200.0,
        "Flow Packets/s": 15.0,
        "SYN Flag Count": 1,
        "ACK Flag Count": 8,
        "FIN Flag Count": 1,
        "Avg Packet Size": 512.0
    }
    res_normal = engine.predict(normal_flow)
    assert res_normal["action"] in ["ALLOW", "REVIEW"]
    assert "attack_type" in res_normal
    assert "confidence" in res_normal
    assert "severity_score" in res_normal

    # 2. DoS SYN Flood attack traffic
    attack_flow = {
        "Protocol": 6,
        "Destination Port": 80,
        "Flow Duration": 100000,
        "Total Fwd Packets": 5000,
        "Total Backward Packets": 0,
        "Fwd Packet Length Max": 60,
        "Flow Bytes/s": 3000000.0,
        "Flow Packets/s": 50000.0,
        "SYN Flag Count": 5000,
        "ACK Flag Count": 0,
        "FIN Flag Count": 0,
        "Avg Packet Size": 60.0
    }
    res_attack = engine.predict(attack_flow)
    assert res_attack["is_attack"] is True
    assert res_attack["action"] in ["DROP", "REVIEW"]
    assert res_attack["severity_score"] >= 2
