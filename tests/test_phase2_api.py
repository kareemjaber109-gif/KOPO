import asyncio
import json
import os
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from src.api import database as db_mod
from src.api.database import Alert, Base, _apply_sqlite_migrations, get_db
from src.api.main import app
from src.ml.detection_engine import DetectionEngine


def _make_syn_flood_flow(port: int = 80) -> dict:
    return {
        "Protocol": 6,
        "Destination Port": port,
        "Flow Duration": 100000,
        "Total Fwd Packets": 5000,
        "Total Backward Packets": 0,
        "Fwd Packet Length Max": 60,
        "Flow Bytes/s": 3000000.0,
        "Flow Packets/s": 50000.0,
        "SYN Flag Count": 5000,
        "ACK Flag Count": 0,
        "FIN Flag Count": 0,
        "Avg Packet Size": 60.0,
    }


def _make_benign_flow() -> dict:
    return {
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
        "Avg Packet Size": 512.0,
    }


@pytest.fixture
def phase2_client(tmp_path, monkeypatch):
    """Isolated FastAPI TestClient backed by a fresh temp SQLite database and real benchmark engine."""
    os.environ["KOPO_DEMO_MODE"] = "false"
    DetectionEngine._instance = None

    test_db_path = tmp_path / "phase2_test.db"
    test_engine = create_async_engine(
        f"sqlite+aiosqlite:///{test_db_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )
    test_session_maker = async_sessionmaker(test_engine, expire_on_commit=False)

    monkeypatch.setattr(db_mod, "engine", test_engine)
    monkeypatch.setattr(db_mod, "AsyncSessionLocal", test_session_maker)

    async def override_get_db():
        async with test_session_maker() as session:
            yield session

    app.dependency_overrides[get_db] = override_get_db

    with TestClient(app) as client:
        yield client, test_session_maker, test_db_path

    app.dependency_overrides.clear()
    DetectionEngine._instance = None
    asyncio.run(test_engine.dispose())


def test_sqlite_migration_preserves_legacy_rows(tmp_path):
    """Verify legacy alerts & analysis_log tables migrate cleanly without dropping rows."""
    db_file = tmp_path / "legacy.db"
    raw_conn = sqlite3.connect(db_file)
    raw_conn.execute(
        """
        CREATE TABLE alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            attack_type VARCHAR(64) NOT NULL,
            severity_score INTEGER NOT NULL,
            severity_label VARCHAR(16) NOT NULL,
            confidence FLOAT NOT NULL,
            is_attack BOOLEAN,
            source_ip VARCHAR(45),
            dest_ip VARCHAR(45),
            is_acknowledged BOOLEAN,
            raw_result TEXT
        )
        """
    )
    raw_conn.execute(
        """
        CREATE TABLE analysis_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp DATETIME,
            is_attack BOOLEAN NOT NULL,
            attack_type VARCHAR(64) NOT NULL,
            confidence FLOAT NOT NULL
        )
        """
    )
    raw_conn.execute(
        """
        INSERT INTO alerts (timestamp, attack_type, severity_score, severity_label, confidence, is_attack, source_ip, dest_ip, is_acknowledged, raw_result)
        VALUES ('2026-11-24 01:00:00', 'DDoS', 5, 'Critical', 0.96, 1, '198.51.100.77', '10.0.0.1', 0, '{"note": "legacy"}')
        """
    )
    raw_conn.execute(
        """
        INSERT INTO analysis_log (timestamp, is_attack, attack_type, confidence)
        VALUES ('2026-11-24 01:00:00', 1, 'DDoS', 0.96)
        """
    )
    raw_conn.commit()
    raw_conn.close()

    async_engine = create_async_engine(
        f"sqlite+aiosqlite:///{db_file.as_posix()}",
        connect_args={"check_same_thread": False},
    )

    async def _run_migration():
        async with async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await conn.run_sync(_apply_sqlite_migrations)
        await async_engine.dispose()

    asyncio.run(_run_migration())

    verify_conn = sqlite3.connect(db_file)
    tables = {
        r[0]
        for r in verify_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
    }
    assert {"alerts", "analysis_log", "incidents", "incident_notes", "agent_approvals"} <= tables

    alert_cols = {r[1] for r in verify_conn.execute("PRAGMA table_info(alerts)").fetchall()}
    assert {"action", "incident_id", "acknowledged_by", "acknowledged_at", "anomaly_score", "is_anomaly"} <= alert_cols

    log_cols = {r[1] for r in verify_conn.execute("PRAGMA table_info(analysis_log)").fetchall()}
    assert {"action", "source_ip", "dest_ip", "anomaly_score", "is_anomaly"} <= log_cols

    preserved = verify_conn.execute(
        "SELECT id, attack_type, source_ip FROM alerts"
    ).fetchall()
    assert preserved == [(1, "DDoS", "198.51.100.77")]
    assert verify_conn.execute("SELECT COUNT(*) FROM analysis_log").fetchone()[0] == 1
    verify_conn.close()


def test_health_and_model_report_truthfulness(phase2_client):
    """Verify /api/health and /api/model-report expose exact uncertified research baseline telemetry."""
    client, _, _ = phase2_client

    h_res = client.get("/api/health")
    assert h_res.status_code == 200
    h = h_res.json()
    assert h["status"] == "ok"
    assert h["model_origin"] == "real"
    assert h["run_id"] == "run_clean_benchmark_v1"
    assert h["certified"] is False
    assert h["run_type"] == "research_baseline"

    r_res = client.get("/api/model-report")
    assert r_res.status_code == 200
    rep = r_res.json()
    assert rep["certified"] is False
    assert rep["active_run_id"] == "run_clean_benchmark_v1"
    assert rep["models"]["lstm"]["status"] == "excluded_in_manifest"
    assert rep["benchmark_2017"]["metrics"]["recall_tpr"] == pytest.approx(0.8057744, rel=1e-4)
    assert rep["external_2018"]["metrics"]["attack_recall_tpr"] == pytest.approx(0.05522219, rel=1e-4)
    assert rep["anomaly_benchmark"]["threshold"] == pytest.approx(0.98716, rel=1e-4)
    assert rep["models"]["anomaly_ensemble"]["threshold"] == pytest.approx(0.98716, rel=1e-4)


def test_batch_detect_upload_incidents_notes_stats_approvals_drift(phase2_client):
    """End-to-end integration test of Phase 2 detection, upload, alerts, incidents, stats, approvals, and drift."""
    client, session_maker, _ = phase2_client

    # 1. Batch detection (2 SYN floods from same IP + 1 benign flow) with auto-aggregation
    batch_res = client.post(
        "/api/detect/batch",
        json={
            "aggregate_incidents": True,
            "flows": [
                {"source_ip": "198.51.100.20", "dest_ip": "10.0.0.5", "features": _make_syn_flood_flow(80)},
                {"source_ip": "198.51.100.20", "dest_ip": "10.0.0.5", "features": _make_syn_flood_flow(80)},
                {"source_ip": "192.168.1.50", "dest_ip": "10.0.0.5", "features": _make_benign_flow()},
            ],
        },
    )
    assert batch_res.status_code == 200
    batch = batch_res.json()
    assert batch["total"] == 3
    assert batch["attacks_detected"] >= 2
    assert batch["alerts_created"] >= 2
    assert batch["incidents_created"] >= 1

    # 2. CSV upload with Src IP, Dst IP, Label (must strip Label and detect attacks)
    csv_header = "Src IP,Dst IP,Protocol,Destination Port,Flow Duration,Total Fwd Packets,Total Backward Packets,Fwd Packet Length Max,Flow Bytes/s,Flow Packets/s,SYN Flag Count,ACK Flag Count,FIN Flag Count,Avg Packet Size,Label"
    csv_row1 = "203.0.113.44,10.0.0.8,6,80,100000,5000,0,60,3000000,50000,5000,0,0,60,DDoS"
    csv_row2 = "192.168.1.99,10.0.0.8,6,443,50000,10,8,512,1200,15,1,8,1,512,BENIGN"
    csv_bytes = f"{csv_header}\n{csv_row1}\n{csv_row2}\n".encode("utf-8")

    up_res = client.post(
        "/api/flows/upload",
        files={"file": ("capture.csv", csv_bytes, "text/csv")},
        data={"aggregate_incidents": "true"},
    )
    assert up_res.status_code == 200
    up = up_res.json()
    assert up["filename"] == "capture.csv"
    assert up["total_rows"] == 2
    assert up["processed"] == 2
    assert up["attacks_detected"] >= 1
    assert up["alerts_created"] >= 1

    # Reject empty file upload cleanly with 400
    empty_res = client.post(
        "/api/flows/upload",
        files={"file": ("empty.csv", b"", "text/csv")},
    )
    assert empty_res.status_code == 400

    # 3. Alerts listing, search, DB notes, detail, and bulk-acknowledge
    alerts_res = client.get("/api/alerts?limit=50")
    assert alerts_res.status_code == 200
    alerts_data = alerts_res.json()
    assert alerts_data["total"] >= 3
    first_alert = alerts_data["alerts"][0]
    first_id = first_alert["id"]

    note_res = client.post(
        f"/api/alerts/{first_id}/notes",
        json={"note": "Verified SYN storm signature in firewall syslog", "author": "sara"},
    )
    assert note_res.status_code == 200
    assert note_res.json()["alert_id"] == first_id

    detail_res = client.get(f"/api/alerts/{first_id}")
    assert detail_res.status_code == 200
    assert len(detail_res.json()["notes"]) == 1
    assert "SYN storm" in detail_res.json()["notes"][0]["note"]

    notes_list = client.get(f"/api/alerts/{first_id}/notes")
    assert notes_list.status_code == 200
    assert len(notes_list.json()) == 1

    # Bulk acknowledge first alert
    bulk_res = client.patch(
        "/api/alerts/bulk-acknowledge",
        json={"alert_ids": [first_id], "analyst": "tier1_omar"},
    )
    assert bulk_res.status_code == 200
    assert bulk_res.json()["updated_count"] == 1

    # 4. Incidents workspace lifecycle + linked alert resolution
    inc_res = client.get("/api/incidents")
    assert inc_res.status_code == 200
    incidents = inc_res.json()["incidents"]
    assert len(incidents) >= 1
    inc_id = incidents[0]["id"]

    inc_note = client.post(
        f"/api/incidents/{inc_id}/notes",
        json={"note": "Escalated source host to perimeter block review", "author": "tier2_hana"},
    )
    assert inc_note.status_code == 200

    patch_res = client.patch(
        f"/api/incidents/{inc_id}",
        json={
            "status": "resolved",
            "assigned_to": "tier2_hana",
            "acknowledge_alerts": True,
            "analyst": "tier2_hana",
        },
    )
    assert patch_res.status_code == 200
    patched = patch_res.json()
    assert patched["status"] == "resolved"
    assert patched["assigned_to"] == "tier2_hana"
    # Incident detail includes both the linked alert note and the direct incident note
    assert len(patched["notes"]) == 2
    assert any(n["alert_id"] == first_id for n in patched["notes"])
    assert any(n["alert_id"] is None and n["author"] == "tier2_hana" for n in patched["notes"])
    assert all(a["is_acknowledged"] for a in patched["alerts"])

    # Verify JSONL upload & incident filter on alerts
    jsonl_body = (
        json.dumps({"source_ip": "198.51.100.88", "dest_ip": "10.0.0.10", "features": _make_syn_flood_flow(80)})
        + "\n"
    ).encode("utf-8")
    jl_res = client.post(
        "/api/flows/upload",
        files={"file": ("stream.jsonl", jsonl_body, "application/x-ndjson")},
        data={"aggregate_incidents": "true"},
    )
    assert jl_res.status_code == 200
    assert jl_res.json()["processed"] == 1

    # Explicit 404 check on missing alert/incident
    assert client.get("/api/alerts/999999").status_code == 404
    assert client.get("/api/incidents/999999").status_code == 404

    # 5. Stats and Timeline buckets
    stats_res = client.get("/api/stats")
    assert stats_res.status_code == 200
    st = stats_res.json()
    assert st["total_analyzed"] >= 6
    assert st["total_alerts"] >= 4
    assert "by_action" in st

    tl_res = client.get("/api/stats/timeline?hours=24&bucket=1h")
    assert tl_res.status_code == 200
    tl = tl_res.json()
    assert tl["hours"] == 24
    assert tl["bucket"] == "1h"
    assert sum(b["total_analyzed"] for b in tl["buckets"]) == st["total_analyzed"]
    assert sum(b["total_alerts"] for b in tl["buckets"]) == st["total_alerts"]

    # 6. Approvals seeded from High/Critical unacked alerts & decision audit
    # Insert a guaranteed unacked Critical alert with source_ip and anomalous telemetry for approvals & drift
    async def _seed_alert_and_anomaly():
        async with session_maker() as session:
            now = datetime.utcnow()
            session.add(
                Alert(
                    timestamp=now - timedelta(minutes=2),
                    attack_type="SYN_FLOOD",
                    severity_score=5,
                    severity_label="Critical",
                    confidence=0.98,
                    anomaly_score=0.992,
                    is_anomaly=True,
                    is_attack=True,
                    action="DROP",
                    source_ip="198.51.100.250",
                    dest_ip="10.0.0.99",
                    raw_result=json.dumps(
                        {
                            "input_features_sample": {
                                "SYN Flag Count": 4000,
                                "Flow Packets/s": 42000,
                            }
                        }
                    ),
                )
            )
            await session.commit()

    asyncio.run(_seed_alert_and_anomaly())

    sync_res = client.post("/api/approvals/sync")
    assert sync_res.status_code == 200
    assert sync_res.json()["created"] >= 1

    appr_list = client.get("/api/approvals").json()
    target_appr = next(a for a in appr_list if a["target"] == "198.51.100.250")
    dec_res = client.post(
        f"/api/approvals/{target_appr['id']}/decide",
        json={"decision": "approved", "comment": "Confirmed DDoS source", "analyst": "lead_ali"},
    )
    assert dec_res.status_code == 200
    dec = dec_res.json()
    assert dec["status"] == "approved"
    assert dec["decided_by"] == "lead_ali"

    # 7. Drift clusters computed dynamically from DB alerts
    drift_res = client.get("/api/drift-clusters")
    assert drift_res.status_code == 200
    clusters = drift_res.json()
    assert len(clusters) >= 1
    assert clusters[0]["sample_count"] >= 1
    assert clusters[0]["divergent_features"]
