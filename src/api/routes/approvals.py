import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import AgentApprovalRecord, Alert, get_db
from src.api.models import AgentApprovalDecisionRequest, AgentApprovalResponse

router = APIRouter()


def _parse_alert_ids(raw: Optional[str]) -> list[int]:
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return [int(x) for x in data] if isinstance(data, list) else []
    except Exception:
        return []


def _serialize_approval(rec: AgentApprovalRecord) -> AgentApprovalResponse:
    return AgentApprovalResponse(
        id=rec.id,
        agent=rec.agent,
        action=rec.action,
        target=rec.target,
        severity=rec.severity,
        rationale=rec.rationale,
        evidence_alert_ids=_parse_alert_ids(rec.evidence_alert_ids),
        created_at=rec.created_at,
        status=rec.status,
        proposed_by=rec.proposed_by,
        audit_comment=rec.audit_comment,
        decided_at=rec.decided_at,
        decided_by=rec.decided_by,
    )


def _choose_mitigation(attack_type: str, source_ip: Optional[str]) -> tuple[str, str, str]:
    atk = (attack_type or "").upper()
    if any(k in atk for k in ("EXFIL", "BOT", "INFIL", "RANSOM", "C2")):
        return (
            "Endpoint Quarantine Agent",
            "ISOLATE_HOST",
            f"Contain internal/endpoint host showing {attack_type} indicators",
        )
    if any(k in atk for k in ("BRUTE", "PATATOR", "SCAN")):
        return (
            "Perimeter Rate Limiter",
            "RATE_LIMIT",
            f"Throttle automated {attack_type} bursts from {source_ip or 'source'}",
        )
    return (
        "Threat Containment Sentinel",
        "BLOCK_IP",
        f"Block high-severity {attack_type} traffic originating from {source_ip or 'external host'}",
    )


async def _sync_from_alerts(db: AsyncSession, limit_new: int = 8) -> int:
    """Create persistent human-approval proposals from unacknowledged Critical/High alerts."""
    existing_rows = (await db.execute(select(AgentApprovalRecord))).scalars().all()
    existing_keys = {(r.action, r.target) for r in existing_rows}

    high_alerts = (
        await db.execute(
            select(Alert)
            .where(
                Alert.is_acknowledged.is_(False),
                Alert.severity_label.in_(["Critical", "High"]),
                Alert.source_ip.is_not(None),
            )
            .order_by(desc(Alert.severity_score), desc(Alert.timestamp))
            .limit(100)
        )
    ).scalars().all()

    grouped: dict[tuple[str, str], list[Alert]] = {}
    for a in high_alerts:
        src = (a.source_ip or "").strip()
        if not src:
            continue
        grouped.setdefault((src, a.attack_type), []).append(a)

    created = 0
    now = datetime.utcnow()
    next_seq = len(existing_rows) + 1

    for (src_ip, atk_type), group in grouped.items():
        if created >= limit_new:
            break
        agent_name, action_code, summary_prefix = _choose_mitigation(atk_type, src_ip)
        if (action_code, src_ip) in existing_keys:
            continue

        top_alert = group[0]
        rec = AgentApprovalRecord(
            id=f"appr-{next_seq:03d}",
            agent=agent_name,
            action=action_code,
            target=src_ip,
            severity=top_alert.severity_label,
            rationale=(
                f"{summary_prefix}. Observed {len(group)} unacknowledged alert(s) "
                f"(max confidence {max(x.confidence for x in group)*100:.1f}%)."
            ),
            evidence_alert_ids=json.dumps([x.id for x in group[:10]]),
            created_at=top_alert.timestamp or now,
            status="pending_human_approval",
            proposed_by="KOPO Autonomous Triage Engine",
        )
        db.add(rec)
        existing_keys.add((action_code, src_ip))
        next_seq += 1
        created += 1

    if created > 0:
        await db.commit()
    return created


@router.get("/approvals", response_model=list[AgentApprovalResponse])
async def list_approvals(db: AsyncSession = Depends(get_db)):
    rows = (
        await db.execute(
            select(AgentApprovalRecord).order_by(desc(AgentApprovalRecord.created_at))
        )
    ).scalars().all()
    if not rows:
        await _sync_from_alerts(db)
        rows = (
            await db.execute(
                select(AgentApprovalRecord).order_by(desc(AgentApprovalRecord.created_at))
            )
        ).scalars().all()
    return [_serialize_approval(r) for r in rows]


@router.post("/approvals/sync")
async def sync_approvals(db: AsyncSession = Depends(get_db)):
    created = await _sync_from_alerts(db)
    return {"created": created}


@router.post("/approvals/{approval_id}/decide", response_model=AgentApprovalResponse)
async def decide_approval(
    approval_id: str,
    payload: AgentApprovalDecisionRequest,
    db: AsyncSession = Depends(get_db),
):
    rec = (
        await db.execute(
            select(AgentApprovalRecord).where(AgentApprovalRecord.id == approval_id)
        )
    ).scalar_one_or_none()
    if rec is None:
        raise HTTPException(status_code=404, detail=f"Approval '{approval_id}' not found")

    rec.status = payload.decision
    rec.audit_comment = payload.comment.strip() or None
    rec.decided_by = payload.analyst.strip()
    rec.decided_at = datetime.utcnow()
    await db.commit()
    await db.refresh(rec)
    return _serialize_approval(rec)
