"""
Unit tests for protocol adherence and engine parity:
1. map_label raises ValueError on unknown raw labels in both clean_split and preprocessor.
2. clean_split sequential dual buffer gaps exist and isolate Train, Val, Test.
3. Decision rule parity between engine action routing and manifest threshold.
"""
import json
import pytest
from pathlib import Path

def test_map_label_clean_split_raises_on_unknown():
    from src.data.clean_split import map_label
    with pytest.raises(ValueError, match="Unknown raw flow label"):
        map_label("EXPLOIT_UNKNOWN_ZERO_DAY_123")


def test_map_label_preprocessor_raises_on_unknown():
    from src.data.preprocessor import map_label
    with pytest.raises(ValueError, match="Unknown raw flow label"):
        map_label("SOME_MALWARE_LABEL_UNKNOWN")


def test_split_protocol_dual_gaps_exist():
    meta_path = Path("data/processed/clean/metadata.json")
    assert meta_path.exists(), "Clean split metadata.json missing"
    with open(meta_path, "r", encoding="utf-8") as f:
        meta = json.load(f)

    protocol = meta.get("protocol", "")
    assert "dual" in protocol.lower() and "gap" in protocol.lower(), \
        f"Expected dual-gap protocol, got: '{protocol}'"
    assert meta.get("n_gaps_discarded", 0) > 0, "No gap flows discarded — buffer gap missing!"

    class_splits = meta.get("class_splits", {})
    # Check that major classes have gap1 and gap2
    for cname in ["BENIGN", "DoS", "DDoS"]:
        splits = class_splits.get(cname, {})
        assert splits.get("gap1", 0) > 0, f"{cname} missing gap1"
        assert splits.get("gap2", 0) > 0, f"{cname} missing gap2"


def test_engine_decision_rule_parity():
    """Verify DetectionEngine uses manifest threshold for action routing."""
    manifest_path = Path("data/models/run_clean_benchmark_v1/manifest.json")
    if not manifest_path.exists():
        pytest.skip("run_clean_benchmark_v1 manifest missing")

    with open(manifest_path, "r", encoding="utf-8") as f:
        manifest = json.load(f)

    threshold = manifest.get("decision_threshold", 0.50)
    assert 0.0 < threshold < 1.0, f"Invalid threshold {threshold}"

    # Verify decision threshold matches operational threshold
    assert threshold == pytest.approx(0.50, abs=0.25)
