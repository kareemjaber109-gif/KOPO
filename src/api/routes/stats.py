import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import Alert, AnalysisLog, Incident, get_db
from src.api.models import StatsResponse, TimelineBucket, TimelineResponse
from src.utils.config import settings

router = APIRouter()

_BUCKET_MINUTES = {
    "15m": 15,
    "1h": 60,
    "6h": 360,
    "1d": 1440,
}


def _read_json_if_exists(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


@router.get("/stats", response_model=StatsResponse)
async def get_stats(db: AsyncSession = Depends(get_db)):
    total_analyzed = (
        await db.execute(select(func.count()).select_from(AnalysisLog))
    ).scalar() or 0

    total_alerts = (
        await db.execute(select(func.count()).select_from(Alert))
    ).scalar() or 0

    open_alerts = (
        await db.execute(
            select(func.count()).select_from(Alert).where(Alert.is_acknowledged.is_(False))
        )
    ).scalar() or 0

    open_incidents = (
        await db.execute(
            select(func.count())
            .select_from(Incident)
            .where(Incident.status.in_(["open", "investigating"]))
        )
    ).scalar() or 0

    attack_rate = total_alerts / total_analyzed if total_analyzed > 0 else 0.0

    rows = (
        await db.execute(
            select(Alert.attack_type, func.count().label("cnt")).group_by(Alert.attack_type)
        )
    ).all()
    by_attack_type = {r.attack_type: r.cnt for r in rows}

    rows2 = (
        await db.execute(
            select(Alert.severity_label, func.count().label("cnt")).group_by(Alert.severity_label)
        )
    ).all()
    by_severity = {r.severity_label: r.cnt for r in rows2}

    rows3 = (
        await db.execute(
            select(Alert.action, func.count().label("cnt"))
            .where(Alert.action.is_not(None))
            .group_by(Alert.action)
        )
    ).all()
    by_action = {r.action: r.cnt for r in rows3}

    since = datetime.utcnow() - timedelta(hours=24)
    recent_24h = (
        await db.execute(
            select(func.count()).select_from(Alert).where(Alert.timestamp >= since)
        )
    ).scalar() or 0

    return StatsResponse(
        total_analyzed=total_analyzed,
        total_alerts=total_alerts,
        attack_rate=round(attack_rate, 4),
        by_attack_type=by_attack_type,
        by_severity=by_severity,
        recent_24h=recent_24h,
        open_alerts=open_alerts,
        open_incidents=open_incidents,
        by_action=by_action,
    )


_UTC_EPOCH = datetime(1970, 1, 1)


def _to_utc_epoch(dt: datetime) -> int:
    if dt.tzinfo is not None:
        dt = dt.replace(tzinfo=None)
    return int((dt - _UTC_EPOCH).total_seconds())


@router.get("/stats/timeline", response_model=TimelineResponse)
async def get_stats_timeline(
    hours: int = Query(24, ge=1, le=720),
    bucket: Literal["15m", "1h", "6h", "1d"] = Query("1h"),
    db: AsyncSession = Depends(get_db),
):
    bucket_minutes = _BUCKET_MINUTES[bucket]
    bucket_sec = bucket_minutes * 60
    now = datetime.utcnow()
    since = now - timedelta(hours=hours)

    start_epoch = (_to_utc_epoch(since) // bucket_sec) * bucket_sec
    end_epoch = (_to_utc_epoch(now) // bucket_sec) * bucket_sec
    since_floor = _UTC_EPOCH + timedelta(seconds=start_epoch)

    slots: dict[int, dict[str, Any]] = {}
    cur = start_epoch
    while cur <= end_epoch:
        dt = _UTC_EPOCH + timedelta(seconds=cur)
        label = dt.strftime("%m-%d %H:%M") if hours > 24 or bucket in ("6h", "1d") else dt.strftime("%H:%M")
        slots[cur] = {
            "timestamp": dt.isoformat() + "Z",
            "label": label,
            "total_analyzed": 0,
            "total_alerts": 0,
            "critical_alerts": 0,
            "high_alerts": 0,
            "benign_flows": 0,
        }
        cur += bucket_sec

    log_rows = (
        await db.execute(
            select(AnalysisLog.timestamp, AnalysisLog.is_attack)
            .where(AnalysisLog.timestamp >= since_floor)
        )
    ).all()
    for ts, is_atk in log_rows:
        if ts is None:
            continue
        key = (_to_utc_epoch(ts) // bucket_sec) * bucket_sec
        if key in slots:
            slots[key]["total_analyzed"] += 1
            if not is_atk:
                slots[key]["benign_flows"] += 1

    alert_rows = (
        await db.execute(
            select(Alert.timestamp, Alert.severity_label)
            .where(Alert.timestamp >= since_floor)
        )
    ).all()
    for ts, sev in alert_rows:
        if ts is None:
            continue
        key = (_to_utc_epoch(ts) // bucket_sec) * bucket_sec
        if key in slots:
            slots[key]["total_alerts"] += 1
            if sev == "Critical":
                slots[key]["critical_alerts"] += 1
            elif sev == "High":
                slots[key]["high_alerts"] += 1

    ordered = [TimelineBucket(**slots[k]) for k in sorted(slots.keys())]
    return TimelineResponse(hours=hours, bucket=bucket, buckets=ordered)


@router.get("/model-report")
async def model_report(request: Request):
    engine = request.app.state.engine
    status = engine.status()

    models_dir = settings.models_dir
    current_cfg = _read_json_if_exists(models_dir / "current.json")
    run_dir_str = current_cfg.get("run_dir", "")
    run_dir = Path(run_dir_str) if run_dir_str else (models_dir / "run_clean_benchmark_v1")
    if not run_dir.is_absolute():
        run_dir = Path.cwd() / run_dir
    if not (run_dir / "manifest.json").exists():
        run_dir = models_dir / "run_clean_benchmark_v1"

    manifest = _read_json_if_exists(run_dir / "manifest.json")
    cross_report = _read_json_if_exists(models_dir / "cross_dataset_evaluation_report.json")
    anom_manifest = _read_json_if_exists(models_dir / "anomaly" / "manifest.json")
    anom_report = _read_json_if_exists(models_dir / "anomaly" / "anomaly_evaluation_report.json")
    anom_2018_report = _read_json_if_exists(models_dir / "anomaly" / "anomaly_2018_raw_evaluation.json")

    test_met = manifest.get("test_metrics", {})
    ext_2018 = cross_report.get("metrics_2018", {})
    anom_ens = (anom_report.get("models_evaluated") or {}).get("ensemble", {})
    anom_if = (anom_report.get("models_evaluated") or {}).get("isolation_forest", {})
    anom_ae = (anom_report.get("models_evaluated") or {}).get("autoencoder", {})
    anom_2018_ens = (anom_2018_report.get("results") or {}).get("ensemble", {})
    anom_cal = anom_manifest.get("calibration", {})
    anom_rec = anom_2018_report.get("benign_fpr_reconciliation", {})

    certified = bool(manifest.get("certified", False))
    run_type = manifest.get("run_type", "research_baseline")
    excluded_models = manifest.get("excluded_models", [])
    lstm_excluded = any("lstm" in str(item).lower() for item in excluded_models)

    status["certified"] = certified
    status["run_type"] = run_type
    status["audit_status"] = (
        "CERTIFIED PRODUCTION"
        if certified
        else "RESEARCH BASELINE (NOT CERTIFIED - PHASE 1 INCOMPLETE / OPEN AUDIT ITEMS)"
    )
    status["training_dataset"] = manifest.get("training_dataset", "CIC-IDS2017 Clean Benchmark")
    status["decision_threshold"] = manifest.get("decision_threshold", 0.5)
    status["excluded_models"] = excluded_models
    status["prior_adjustments"] = manifest.get("prior_adjustments", {})

    # Ensemble-level CIC-IDS2017 & CSE-CIC-IDS2018 verified metrics from manifest + report
    status["benchmark_2017"] = {
        "metrics": test_met,
        "per_class": manifest.get("test_per_class", {}),
    }
    status["external_2018"] = {
        "dataset": (manifest.get("external_validation") or {}).get("dataset", "CSE-CIC-IDS2018"),
        "metrics": ext_2018,
        "per_class": cross_report.get("per_class_2018", {}),
        "model_c_ablation": manifest.get("model_c_ablation", {}),
    }
    status["anomaly_benchmark"] = {
        "threshold": anom_manifest.get("threshold"),
        "calibration_val": anom_cal,
        "test_evaluation": anom_ens,
        "ids2018_raw": {
            "fpr": anom_2018_ens.get("fpr"),
            "recall": anom_2018_ens.get("recall"),
            "benign_count": anom_2018_ens.get("benign_count"),
            "attack_count": anom_2018_ens.get("attack_count"),
        },
        "benign_fpr_reconciliation": anom_rec,
    }

    # Note: RF + XGBoost + Isotonic are evaluated jointly as the supervised binary ensemble
    shared_ensemble_summary = {
        "f1": test_met.get("f1_binary"),
        "macro_f1": test_met.get("f1_macro"),
        "accuracy": test_met.get("accuracy"),
        "precision": test_met.get("precision"),
        "recall": test_met.get("recall_tpr"),
        "benign_fpr": test_met.get("benign_fpr"),
        "external_2018_recall": ext_2018.get("attack_recall_tpr"),
        "external_2018_macro_f1": ext_2018.get("macro_f1"),
        "metrics_scope": "Ensemble (RF + XGBoost + Isotonic Calibration)",
    }

    status["models"] = {
        "random_forest": {
            "status": "trained" if engine.rf_model else "not_trained",
            **shared_ensemble_summary,
        },
        "xgboost": {
            "status": "trained" if engine.xgb_model else "not_trained",
            **shared_ensemble_summary,
        },
        "lstm": {
            "status": (
                "excluded_in_manifest"
                if lstm_excluded
                else ("trained" if engine.lstm_model else "not_trained")
            ),
            "loaded_legacy_fallback": bool(engine.lstm_model and lstm_excluded),
            "note": excluded_models[0] if excluded_models else None,
        },
        "isolation_forest": {
            "status": "trained" if (engine.iso_model or anom_if) else "not_trained",
            "f1": anom_if.get("f1"),
            "accuracy": anom_if.get("accuracy"),
            "roc_auc": anom_if.get("roc_auc"),
            "pr_auc": anom_if.get("pr_auc"),
            "detection_rate_tpr": anom_if.get("recall_tpr"),
            "false_alarm_rate_fpr": anom_if.get("fpr"),
            "precision": anom_if.get("precision"),
        },
        "anomaly_ensemble": {
            "status": "trained" if getattr(engine, "anomaly_ensemble", None) else "not_trained",
            "f1": anom_ens.get("f1"),
            "accuracy": anom_ens.get("accuracy"),
            "roc_auc": anom_ens.get("roc_auc"),
            "pr_auc": anom_ens.get("pr_auc"),
            "precision": anom_ens.get("precision"),
            "recall": anom_ens.get("recall_tpr"),
            "fpr": anom_ens.get("fpr"),
            "threshold": anom_manifest.get("threshold"),
            "unsw_benign_fpr": anom_cal.get("fpr_unsw"),
            "cicids_benign_fpr": anom_cal.get("fpr_cicids2017"),
            "autoencoder_roc_auc": anom_ae.get("roc_auc"),
            "ids2018_raw_fpr": anom_2018_ens.get("fpr"),
            "ids2018_raw_recall": anom_2018_ens.get("recall"),
        },
    }
    return status
