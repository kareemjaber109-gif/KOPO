from pathlib import Path
import json
import os
import subprocess
import pytest
from fastapi.testclient import TestClient
from src.api.main import app
from src.ml.detection_engine import DetectionEngine


@pytest.fixture
def synthetic_pointer():
    """Temporarily point current.json to quarantine_synthetic_v0 to test synthetic guardrails."""
    cpath = Path("data/models/current.json")
    original = cpath.read_text(encoding="utf-8") if cpath.exists() else None
    synthetic_config = {
        "active_run_id": "quarantine_synthetic_v0",
        "run_dir": "data/models/_quarantine_synthetic",
        "data_origin": "synthetic"
    }
    with open(cpath, "w", encoding="utf-8") as f:
        json.dump(synthetic_config, f, indent=2)
    DetectionEngine._instance = None
    yield
    if original is not None:
        cpath.write_text(original, encoding="utf-8")
    DetectionEngine._instance = None


def test_simulator_train_granular_blocked():
    """Verify train_granular_35.py refuses to run and raises PermissionError without explicit override."""
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    env.pop("KOPO_ALLOW_SIMULATOR_OVERWRITE", None)
    res = subprocess.run(
        ["python", "tools/simulator/train_granular_35.py"],
        capture_output=True,
        text=True,
        env=env
    )
    assert res.returncode != 0
    assert "PermissionError" in res.stderr
    assert "CRITICAL PROTOCOL VIOLATION" in res.stderr


def test_simulator_train_expanded_blocked():
    """Verify train_expanded_models.py refuses to run and raises PermissionError without explicit override."""
    env = os.environ.copy()
    env["PYTHONPATH"] = "."
    env.pop("KOPO_ALLOW_SIMULATOR_OVERWRITE", None)
    res = subprocess.run(
        ["python", "tools/simulator/train_expanded_models.py"],
        capture_output=True,
        text=True,
        env=env
    )
    assert res.returncode != 0
    assert "PermissionError" in res.stderr
    assert "CRITICAL PROTOCOL VIOLATION" in res.stderr


def test_engine_strict_by_default_rejects_synthetic(synthetic_pointer):
    """Verify DetectionEngine refuses to load synthetic weights in default strict mode."""
    os.environ["KOPO_DEMO_MODE"] = "false"
    engine = DetectionEngine()
    engine.load()
    assert engine.data_origin == "synthetic"
    assert engine.is_ready is False


def test_health_reports_model_origin_and_run_id(synthetic_pointer):
    """Verify /api/health returns model_origin, run_id, and degraded status when synthetic."""
    os.environ["KOPO_DEMO_MODE"] = "false"
    engine = DetectionEngine.get_instance()
    engine.load()
    client = TestClient(app)
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "degraded"
    assert data["model_origin"] == "synthetic"
    assert "quarantine" in data["run_id"]
    assert data["is_ready"] is False


def test_detect_endpoint_returns_503_in_strict_mode(synthetic_pointer):
    """Verify /api/detect returns 503 when synthetic models are quarantined and real run is pending."""
    os.environ["KOPO_DEMO_MODE"] = "false"
    engine = DetectionEngine.get_instance()
    engine.load()
    app.state.engine = engine
    client = TestClient(app)
    res = client.post("/api/detect", json={
        "source_ip": "198.51.100.1",
        "dest_ip": "10.0.0.1",
        "features": {"Destination Port": 80, "Flow Duration": 1000}
    })
    assert res.status_code == 503
    assert "Detection engine not ready" in res.json()["detail"]
    assert "Production strict mode requires a certified real benchmark run" in res.json()["detail"]
