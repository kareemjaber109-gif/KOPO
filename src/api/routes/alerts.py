from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import desc, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import Alert, IncidentNote, get_db
from src.api.models import (
    AcknowledgeRequest,
    AlertDetailResponse,
    AlertListResponse,
    BulkAcknowledgeRequest,
    BulkAcknowledgeResponse,
    NoteCreateRequest,
    NoteResponse,
)
from src.api.services.incident_service import serialize_alert

router = APIRouter()


@router.get("/alerts", response_model=AlertListResponse)
async def get_alerts(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    hours: Optional[int] = None,
    incident_id: Optional[int] = None,
    search: Optional[str] = None,
    unacknowledged_only: bool = False,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Alert).order_by(desc(Alert.timestamp), desc(Alert.id))

    if severity:
        stmt = stmt.where(Alert.severity_label == severity)
    if attack_type:
        stmt = stmt.where(Alert.attack_type == attack_type)
    if hours:
        since = datetime.utcnow() - timedelta(hours=hours)
        stmt = stmt.where(Alert.timestamp >= since)
    if incident_id is not None:
        stmt = stmt.where(Alert.incident_id == incident_id)
    if unacknowledged_only:
        stmt = stmt.where(Alert.is_acknowledged.is_(False))
    if search and search.strip():
        q = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Alert.attack_type.ilike(q),
                Alert.severity_label.ilike(q),
                Alert.source_ip.ilike(q),
                Alert.dest_ip.ilike(q),
            )
        )

    total_stmt = select(func.count()).select_from(stmt.subquery())
    total = (await db.execute(total_stmt)).scalar() or 0
    paged = (await db.execute(stmt.offset(offset).limit(limit))).scalars().all()

    return AlertListResponse(
        total=total,
        alerts=[serialize_alert(a) for a in paged],
    )


@router.patch("/alerts/bulk-acknowledge", response_model=BulkAcknowledgeResponse)
async def bulk_acknowledge(
    payload: BulkAcknowledgeRequest,
    db: AsyncSession = Depends(get_db),
):
    ids = sorted(set(payload.alert_ids))
    now = datetime.utcnow()
    matching = (
        await db.execute(select(Alert.id).where(Alert.id.in_(ids)))
    ).scalars().all()
    if not matching:
        return BulkAcknowledgeResponse(updated_count=0, alert_ids=[])

    await db.execute(
        update(Alert)
        .where(Alert.id.in_(matching))
        .values(
            is_acknowledged=True,
            acknowledged_by=payload.analyst or "SOC Analyst",
            acknowledged_at=now,
        )
    )
    await db.commit()
    return BulkAcknowledgeResponse(updated_count=len(matching), alert_ids=list(matching))


@router.get("/alerts/{alert_id}", response_model=AlertDetailResponse)
async def get_alert_detail(alert_id: int, db: AsyncSession = Depends(get_db)):
    alert = (
        await db.execute(select(Alert).where(Alert.id == alert_id))
    ).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    notes = (
        await db.execute(
            select(IncidentNote)
            .where(IncidentNote.alert_id == alert_id)
            .order_by(desc(IncidentNote.created_at))
        )
    ).scalars().all()

    base = serialize_alert(alert)
    return AlertDetailResponse(
        **base.model_dump(),
        notes=[
            NoteResponse(
                id=n.id,
                incident_id=n.incident_id,
                alert_id=n.alert_id,
                author=n.author,
                note=n.note,
                created_at=n.created_at,
            )
            for n in notes
        ],
    )


@router.patch("/alerts/{alert_id}/acknowledge")
async def acknowledge(
    alert_id: int,
    payload: Optional[AcknowledgeRequest] = Body(default=None),
    db: AsyncSession = Depends(get_db),
):
    exists = (
        await db.execute(select(Alert.id).where(Alert.id == alert_id))
    ).scalar_one_or_none()
    if exists is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    now = datetime.utcnow()
    analyst = (payload.analyst if payload and payload.analyst else "SOC Analyst")
    await db.execute(
        update(Alert)
        .where(Alert.id == alert_id)
        .values(
            is_acknowledged=True,
            acknowledged_by=analyst,
            acknowledged_at=now,
        )
    )
    await db.commit()
    return {
        "id": alert_id,
        "acknowledged": True,
        "acknowledged_by": analyst,
        "acknowledged_at": now.isoformat(),
    }


@router.get("/alerts/{alert_id}/notes", response_model=list[NoteResponse])
async def get_alert_notes(alert_id: int, db: AsyncSession = Depends(get_db)):
    exists = (
        await db.execute(select(Alert.id).where(Alert.id == alert_id))
    ).scalar_one_or_none()
    if exists is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    notes = (
        await db.execute(
            select(IncidentNote)
            .where(IncidentNote.alert_id == alert_id)
            .order_by(desc(IncidentNote.created_at))
        )
    ).scalars().all()
    return [
        NoteResponse(
            id=n.id,
            incident_id=n.incident_id,
            alert_id=n.alert_id,
            author=n.author,
            note=n.note,
            created_at=n.created_at,
        )
        for n in notes
    ]


@router.post("/alerts/{alert_id}/notes", response_model=NoteResponse)
async def add_alert_note(
    alert_id: int,
    payload: NoteCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    alert = (
        await db.execute(select(Alert).where(Alert.id == alert_id))
    ).scalar_one_or_none()
    if alert is None:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")

    note = IncidentNote(
        alert_id=alert_id,
        incident_id=alert.incident_id,
        author=payload.author.strip(),
        note=payload.note.strip(),
        created_at=datetime.utcnow(),
    )
    db.add(note)
    await db.commit()
    await db.refresh(note)
    return NoteResponse(
        id=note.id,
        incident_id=note.incident_id,
        alert_id=note.alert_id,
        author=note.author,
        note=note.note,
        created_at=note.created_at,
    )
