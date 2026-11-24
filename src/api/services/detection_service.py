import csv
import io
import json
import math
from collections import Counter
from datetime import datetime
from typing import Any, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import Alert, AnalysisLog
from src.api.models import DetectionResponse, NetworkFlowRequest
from src.utils.logger import logger

_SRC_IP_KEYS = {"source_ip", "src_ip", "Src IP", "Source IP", "srcip"}
_DST_IP_KEYS = {"dest_ip", "dst_ip", "Dst IP", "Destination IP", "dstip"}
_IGNORE_KEYS = _SRC_IP_KEYS | _DST_IP_KEYS | {"Label", "label", "Flow ID", "Timestamp"}


def extract_clean_features(payload: NetworkFlowRequest) -> dict[str, float]:
    """Normalize explicit or extra flow payload fields into a clean float dictionary."""
    raw_features = payload.features
    if raw_features is None:
        extra = payload.model_extra or {}
        raw_features = {k: v for k, v in extra.items() if k not in ("source_ip", "dest_ip")}

    clean_features: dict[str, float] = {}
    for k, v in (raw_features or {}).items():
        key = str(k).strip()
        if not key or key in _IGNORE_KEYS:
            continue
        try:
            num = float(v)
        except (ValueError, TypeError):
            continue
        if math.isfinite(num):
            clean_features[key] = num
    return clean_features


def _compact_raw_result(result: dict[str, Any], features: dict[str, float]) -> str:
    """Serialize detection metadata + a capped subset of input flow features for audit inspection."""
    payload = {k: v for k, v in result.items() if k != "model_results"}
    if features:
        payload["input_features_sample"] = dict(list(features.items())[:25])
    if "model_results" in result:
        compact_models = {}
        for mname, mdata in result["model_results"].items():
            if isinstance(mdata, dict):
                compact_models[mname] = {
                    k: v for k, v in mdata.items() if k != "all_probabilities"
                }
        payload["model_results"] = compact_models
    return json.dumps(payload)


def parse_uploaded_flows(
    filename: str,
    content: bytes,
    max_rows: int = 2000,
) -> tuple[list[NetworkFlowRequest], int, int]:
    """Parse uploaded CSV, JSON, or JSONL flow files into NetworkFlowRequest objects.

    Returns (flows, total_rows, skipped_rows).
    """
    text_body = content.decode("utf-8-sig", errors="replace").strip()
    if not text_body:
        raise ValueError("Uploaded file is empty")

    ext = (filename or "").lower().rsplit(".", 1)[-1]
    raw_records: list[dict[str, Any]] = []

    if ext in {"json", "jsonl"} or text_body.startswith("[") or text_body.startswith("{"):
        try:
            parsed = json.loads(text_body)
            if isinstance(parsed, dict):
                if isinstance(parsed.get("flows"), list):
                    raw_records = parsed["flows"]
                else:
                    raw_records = [parsed]
            elif isinstance(parsed, list):
                raw_records = parsed
        except json.JSONDecodeError:
            # Fall back to JSON Lines format
            for line in text_body.splitlines():
                line = line.strip()
                if not line:
                    continue
                obj = json.loads(line)
                if isinstance(obj, dict):
                    raw_records.append(obj)
    else:
        reader = csv.DictReader(io.StringIO(text_body))
        if not reader.fieldnames:
            raise ValueError("CSV file has no header row")
        for row in reader:
            raw_records.append(row)

    total_rows = len(raw_records)
    if total_rows == 0:
        raise ValueError("No flow records found in uploaded file")
    if total_rows > max_rows:
        raise ValueError(
            f"Upload exceeds limit of {max_rows} rows (got {total_rows}). Split file into smaller batches."
        )

    flows: list[NetworkFlowRequest] = []
    skipped = 0

    for row in raw_records:
        if not isinstance(row, dict):
            skipped += 1
            continue

        # Support wrapped {features: {...}, source_ip, dest_ip} objects as well as flat rows
        if isinstance(row.get("features"), dict):
            src_ip = row.get("source_ip")
            dst_ip = row.get("dest_ip")
            raw_feats = row["features"]
        else:
            src_ip = next((str(row[k]).strip() for k in _SRC_IP_KEYS if row.get(k)), None)
            dst_ip = next((str(row[k]).strip() for k in _DST_IP_KEYS if row.get(k)), None)
            raw_feats = {k: v for k, v in row.items() if k and k.strip() not in _IGNORE_KEYS}

        clean_feats: dict[str, float] = {}
        for k, v in raw_feats.items():
            key = str(k).strip()
            if not key or key in _IGNORE_KEYS:
                continue
            try:
                num = float(v)
            except (ValueError, TypeError):
                continue
            if math.isfinite(num):
                clean_feats[key] = num

        if not clean_feats:
            skipped += 1
            continue

        flows.append(
            NetworkFlowRequest(
                features=clean_feats,
                source_ip=src_ip,
                dest_ip=dst_ip,
            )
        )

    if not flows:
        raise ValueError("No valid numeric flow features could be parsed from file")

    return flows, total_rows, skipped


async def analyze_and_persist_flows(
    engine: Any,
    flows: list[NetworkFlowRequest],
    db: AsyncSession,
    log_alerts: bool = True,
) -> tuple[list[DetectionResponse], dict[str, Any]]:
    """Run DetectionEngine on a batch of flows and persist logs/alerts in a single transaction."""
    responses: list[DetectionResponse] = []
    pending_alerts: list[tuple[Alert, int]] = []

    by_attack_type: Counter[str] = Counter()
    by_severity: Counter[str] = Counter()
    by_action: Counter[str] = Counter()
    attacks_detected = 0

    for idx, payload in enumerate(flows):
        clean_features = extract_clean_features(payload)
        result = engine.predict(clean_features)
        now = datetime.utcnow()

        action = result.get("action") or ("DROP" if result["is_attack"] else "ALLOW")
        log = AnalysisLog(
            timestamp=now,
            is_attack=result["is_attack"],
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            anomaly_score=result.get("anomaly_score"),
            is_anomaly=result.get("is_anomaly"),
            action=action,
            source_ip=payload.source_ip,
            dest_ip=payload.dest_ip,
        )
        db.add(log)

        if result["is_attack"]:
            attacks_detected += 1
        by_attack_type[result["attack_type"]] += 1
        by_severity[result["severity_label"]] += 1
        by_action[action] += 1

        alert_obj: Optional[Alert] = None
        if result["should_alert"]:
            alert_obj = Alert(
                timestamp=now,
                attack_type=result["attack_type"],
                severity_score=result["severity_score"],
                severity_label=result["severity_label"],
                confidence=result["confidence"],
                anomaly_score=result.get("anomaly_score"),
                is_anomaly=result.get("is_anomaly"),
                is_attack=result["is_attack"],
                action=action,
                source_ip=payload.source_ip,
                dest_ip=payload.dest_ip,
                raw_result=_compact_raw_result(result, clean_features),
            )
            db.add(alert_obj)
            pending_alerts.append((alert_obj, idx))
            if log_alerts:
                logger.warning(
                    f"ALERT [{result['severity_label']}] "
                    f"{result['attack_type']} conf={result['confidence']:.3f}"
                )

        responses.append(
            DetectionResponse(
                **result,
                timestamp=now,
                alert_id=None,
            )
        )

    await db.flush()
    for alert_obj, resp_idx in pending_alerts:
        responses[resp_idx].alert_id = str(alert_obj.id)

    await db.commit()

    summary = {
        "total": len(flows),
        "attacks_detected": attacks_detected,
        "benign_count": len(flows) - attacks_detected,
        "alerts_created": len(pending_alerts),
        "by_attack_type": dict(by_attack_type),
        "by_severity": dict(by_severity),
        "by_action": dict(by_action),
    }
    return responses, summary
