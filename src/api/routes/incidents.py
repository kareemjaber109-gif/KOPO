from datetime import datetime
from typing import Optional

from fastapi import APIRouter, Body, Depends, HTTPException, Query
from sqlalchemy import desc, func, or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import Alert, Incident, IncidentNote, get_db
from src.api.models import (
    IncidentAggregateRequest,
    IncidentAggregateResponse,
    IncidentDetailResponse,
    IncidentListResponse,
    IncidentUpdateRequest,
    NoteCreateRequest,
    NoteResponse,
)
from src.api.services.incident_service import (
    aggregate_alerts_into_incidents,
    serialize_alert,
    serialize_incident,
)

router = APIRouter()


@router.post("/incidents/aggregate", response_model=IncidentAggregateResponse)
async def aggregate_incidents(
    payload: Optional[IncidentAggregateRequest] = Body(default=None),
    db: AsyncSession = Depends(get_db),
):
    req = payload or IncidentAggregateRequest()
    created, updated, linked, touched = await aggregate_alerts_into_incidents(
        db,
        window_minutes=req.window_minutes,
        include_acknowledged=req.include_acknowledged,
    )
    return IncidentAggregateResponse(
        incidents_created=created,
        incidents_updated=updated,
        alerts_linked=linked,
        incidents=[serialize_incident(inc) for inc in touched],
    )


@router.get("/incidents", response_model=IncidentListResponse)
async def list_incidents(
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    status: Optional[str] = None,
    severity: Optional[str] = None,
    search: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Incident).order_by(desc(Incident.last_seen), desc(Incident.id))
    if status and status != "all":
        stmt = stmt.where(Incident.status == status)
    if severity:
        stmt = stmt.where(Incident.severity_label == severity)
    if search and search.strip():
        q = f"%{search.strip()}%"
        stmt = stmt.where(
            or_(
                Incident.title.ilike(q),
                Incident.primary_attack_type.ilike(q),
                Incident.source_ips.ilike(q),
                Incident.attack_types.ilike(q),
            )
        )

    total = (
        await db.execute(select(func.count()).select_from(stmt.subquery()))
    ).scalar() or 0
    rows = (await db.execute(stmt.offset(offset).limit(limit))).scalars().all()

    return IncidentListResponse(
        total=total,
        incidents=[serialize_incident(inc) for inc in rows],
    )


@router.get("/incidents/{incident_id}", response_model=IncidentDetailResponse)
async def get_incident(incident_id: int, db: AsyncSession = Depends(get_db)):
    inc = (
        await db.execute(select(Incident).where(Incident.id == incident_id))
    ).scalar_one_or_none()
    if inc is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    alerts = (
        await db.execute(
            select(Alert)
            .where(Alert.incident_id == incident_id)
            .order_by(desc(Alert.timestamp))
        )
    ).scalars().all()
    notes = (
        await db.execute(
            select(IncidentNote)
            .where(IncidentNote.incident_id == incident_id)
            .order_by(desc(IncidentNote.created_at))
        )
    ).scalars().all()

    base = serialize_incident(inc)
    return IncidentDetailResponse(
        **base.model_dump(),
        alerts=[serialize_alert(a) for a in alerts],
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


@router.patch("/incidents/{incident_id}", response_model=IncidentDetailResponse)
async def update_incident(
    incident_id: int,
    payload: IncidentUpdateRequest,
    db: AsyncSession = Depends(get_db),
):
    inc = (
        await db.execute(select(Incident).where(Incident.id == incident_id))
    ).scalar_one_or_none()
    if inc is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    now = datetime.utcnow()
    if payload.status is not None:
        inc.status = payload.status
    if payload.assigned_to is not None:
        inc.assigned_to = payload.assigned_to.strip() or None
    if payload.title is not None:
        inc.title = payload.title.strip()
    inc.updated_at = now

    if payload.acknowledge_alerts and inc.status in ("resolved", "false_positive"):
        await db.execute(
            update(Alert)
            .where(Alert.incident_id == incident_id, Alert.is_acknowledged.is_(False))
            .values(
                is_acknowledged=True,
                acknowledged_by=payload.analyst or "SOC Analyst",
                acknowledged_at=now,
            )
        )

    await db.commit()
    return await get_incident(incident_id, db)


@router.post("/incidents/{incident_id}/notes", response_model=NoteResponse)
async def add_incident_note(
    incident_id: int,
    payload: NoteCreateRequest,
    db: AsyncSession = Depends(get_db),
):
    inc = (
        await db.execute(select(Incident).where(Incident.id == incident_id))
    ).scalar_one_or_none()
    if inc is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id} not found")

    now = datetime.utcnow()
    note = IncidentNote(
        incident_id=incident_id,
        alert_id=None,
        author=payload.author.strip(),
        note=payload.note.strip(),
        created_at=now,
    )
    inc.updated_at = now
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
