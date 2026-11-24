import json
from datetime import datetime, timedelta
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import Alert, Incident
from src.api.models import AlertResponse, IncidentResponse
from src.ml.detection_engine import ATTACK_CATEGORY_MAP, SEVERITY_LABELS


def _parse_json_list(raw: Optional[str]) -> list[str]:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        return [str(x) for x in parsed] if isinstance(parsed, list) else []
    except Exception:
        return []


def serialize_alert(a: Alert) -> AlertResponse:
    return AlertResponse(
        id=a.id,
        timestamp=a.timestamp,
        attack_type=a.attack_type,
        attack_category=ATTACK_CATEGORY_MAP.get(a.attack_type, "Threat Detected"),
        severity_label=a.severity_label,
        severity_score=a.severity_score,
        confidence=a.confidence,
        anomaly_score=a.anomaly_score,
        is_anomaly=a.is_anomaly,
        action=a.action,
        source_ip=a.source_ip,
        dest_ip=a.dest_ip,
        is_acknowledged=bool(a.is_acknowledged),
        acknowledged_by=a.acknowledged_by,
        acknowledged_at=a.acknowledged_at,
        incident_id=a.incident_id,
        raw_result=a.raw_result,
    )


def serialize_incident(inc: Incident) -> IncidentResponse:
    return IncidentResponse(
        id=inc.id,
        title=inc.title,
        status=inc.status,
        severity_label=inc.severity_label,
        severity_score=inc.severity_score,
        primary_attack_type=inc.primary_attack_type,
        attack_types=_parse_json_list(inc.attack_types),
        source_ips=_parse_json_list(inc.source_ips),
        dest_ips=_parse_json_list(inc.dest_ips),
        alert_count=inc.alert_count,
        first_seen=inc.first_seen,
        last_seen=inc.last_seen,
        created_at=inc.created_at,
        updated_at=inc.updated_at,
        assigned_to=inc.assigned_to,
    )


def _merge_unique(existing: list[str], value: Optional[str]) -> list[str]:
    if not value:
        return existing
    if value not in existing:
        existing.append(value)
    return existing


def _incident_title(attack_type: str, source_ip: str, count: int) -> str:
    if source_ip and source_ip != "unattributed":
        return f"{attack_type} activity from {source_ip}"
    return f"{attack_type} alert cluster ({count} events)"


async def aggregate_alerts_into_incidents(
    db: AsyncSession,
    window_minutes: int = 60,
    include_acknowledged: bool = False,
) -> tuple[int, int, int, list[Incident]]:
    """Group unlinked alerts by (source_ip, attack_type) inside a rolling time window."""
    stmt = (
        select(Alert)
        .where(Alert.incident_id.is_(None))
        .order_by(Alert.timestamp.asc(), Alert.id.asc())
    )
    if not include_acknowledged:
        stmt = stmt.where(Alert.is_acknowledged.is_(False))

    unlinked_alerts = (await db.execute(stmt)).scalars().all()
    if not unlinked_alerts:
        return 0, 0, 0, []

    # Load open/investigating incidents to merge nearby recurring alerts cleanly
    active_incidents = (
        await db.execute(
            select(Incident)
            .where(Incident.status.in_(["open", "investigating"]))
            .order_by(Incident.last_seen.desc())
        )
    ).scalars().all()

    window_delta = timedelta(minutes=window_minutes)
    created_ids: set[int] = set()
    updated_ids: set[int] = set()
    touched: dict[int, Incident] = {}

    # Index active incidents by (primary_src, primary_attack_type)
    open_buckets: dict[tuple[str, str], list[Incident]] = {}
    for inc in active_incidents:
        srcs = _parse_json_list(inc.source_ips)
        key_src = srcs[0] if srcs else "unattributed"
        open_buckets.setdefault((key_src, inc.primary_attack_type), []).append(inc)

    now = datetime.utcnow()
    linked_count = 0

    for alert in unlinked_alerts:
        src_key = (alert.source_ip or "").strip() or "unattributed"
        atk_key = alert.attack_type
        alert_ts = alert.timestamp or now

        candidates = open_buckets.get((src_key, atk_key), [])
        matched: Optional[Incident] = None
        for cand in candidates:
            if abs((alert_ts - cand.last_seen).total_seconds()) <= window_delta.total_seconds():
                matched = cand
                break

        if matched is None:
            src_list = [src_key] if src_key != "unattributed" else []
            dst_list = [alert.dest_ip] if alert.dest_ip else []
            matched = Incident(
                title=_incident_title(atk_key, src_key, 1),
                status="open",
                severity_score=alert.severity_score,
                severity_label=SEVERITY_LABELS.get(alert.severity_score, alert.severity_label),
                primary_attack_type=atk_key,
                attack_types=json.dumps([atk_key]),
                source_ips=json.dumps(src_list),
                dest_ips=json.dumps(dst_list),
                alert_count=1,
                first_seen=alert_ts,
                last_seen=alert_ts,
                created_at=now,
                updated_at=now,
            )
            db.add(matched)
            await db.flush()
            created_ids.add(matched.id)
            open_buckets.setdefault((src_key, atk_key), []).append(matched)
        else:
            attacks = _merge_unique(_parse_json_list(matched.attack_types), atk_key)
            srcs = _merge_unique(
                _parse_json_list(matched.source_ips),
                None if src_key == "unattributed" else src_key,
            )
            dsts = _merge_unique(_parse_json_list(matched.dest_ips), alert.dest_ip)
            max_sev = max(matched.severity_score, alert.severity_score)

            matched.alert_count += 1
            matched.severity_score = max_sev
            matched.severity_label = SEVERITY_LABELS.get(max_sev, matched.severity_label)
            matched.attack_types = json.dumps(attacks)
            matched.source_ips = json.dumps(srcs)
            matched.dest_ips = json.dumps(dsts)
            if alert_ts < matched.first_seen:
                matched.first_seen = alert_ts
            if alert_ts > matched.last_seen:
                matched.last_seen = alert_ts
            if src_key == "unattributed":
                matched.title = _incident_title(atk_key, src_key, matched.alert_count)
            matched.updated_at = now
            if matched.id not in created_ids:
                updated_ids.add(matched.id)

        alert.incident_id = matched.id
        linked_count += 1
        touched[matched.id] = matched

    await db.commit()
    return len(created_ids), len(updated_ids), linked_count, list(touched.values())
