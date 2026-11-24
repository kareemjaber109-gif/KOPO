from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import get_db
from src.api.models import (
    BatchDetectRequest,
    BatchDetectResponse,
    DetectionResponse,
    FlowUploadResponse,
    NetworkFlowRequest,
)
from src.api.services.detection_service import (
    analyze_and_persist_flows,
    parse_uploaded_flows,
)
from src.api.services.incident_service import aggregate_alerts_into_incidents
from src.utils.logger import logger

router = APIRouter()


def _require_ready_engine(request: Request):
    engine = request.app.state.engine
    if not engine.is_ready:
        origin = getattr(engine, "data_origin", "unloaded")
        run_id = getattr(engine, "active_run_id", "none")
        raise HTTPException(
            status_code=503,
            detail=(
                f"Detection engine not ready. Active model run '{run_id}' has origin '{origin}'. "
                "Production strict mode requires a certified real benchmark run."
            ),
        )
    return engine


@router.post("/detect", response_model=DetectionResponse)
async def detect(
    request: Request,
    payload: NetworkFlowRequest,
    db: AsyncSession = Depends(get_db),
):
    engine = _require_ready_engine(request)
    try:
        responses, _ = await analyze_and_persist_flows(engine, [payload], db)
        return responses[0]
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/detect/batch", response_model=BatchDetectResponse)
async def detect_batch(
    request: Request,
    payload: BatchDetectRequest,
    db: AsyncSession = Depends(get_db),
):
    engine = _require_ready_engine(request)
    try:
        responses, summary = await analyze_and_persist_flows(
            engine, payload.flows, db, log_alerts=False
        )
        incidents_created = 0
        if payload.aggregate_incidents and summary["alerts_created"] > 0:
            incidents_created, _, _, _ = await aggregate_alerts_into_incidents(db)
        return BatchDetectResponse(
            **summary,
            incidents_created=incidents_created,
            results=responses,
        )
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Batch prediction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/flows/upload", response_model=FlowUploadResponse)
async def upload_flows(
    request: Request,
    file: UploadFile = File(...),
    aggregate_incidents: bool = Form(default=False),
    db: AsyncSession = Depends(get_db),
):
    engine = _require_ready_engine(request)
    content = await file.read()
    try:
        flows, total_rows, skipped_rows = parse_uploaded_flows(
            file.filename or "flows.csv", content, max_rows=2000
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        responses, summary = await analyze_and_persist_flows(
            engine, flows, db, log_alerts=False
        )
        incidents_created = 0
        if aggregate_incidents and summary["alerts_created"] > 0:
            incidents_created, _, _, _ = await aggregate_alerts_into_incidents(db)
        return FlowUploadResponse(
            filename=file.filename or "uploaded_flows",
            total_rows=total_rows,
            processed=summary["total"],
            skipped_rows=skipped_rows,
            attacks_detected=summary["attacks_detected"],
            benign_count=summary["benign_count"],
            alerts_created=summary["alerts_created"],
            incidents_created=incidents_created,
            by_attack_type=summary["by_attack_type"],
            by_severity=summary["by_severity"],
            by_action=summary["by_action"],
            sample_results=responses[:25],
        )
    except Exception as e:
        logger.error(f"Flow upload processing error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
