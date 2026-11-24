from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from src.utils.config import settings
from src.utils.logger import logger
from src.api.database import init_db
from src.api.routes import alerts, approvals, detect, drift, incidents, stats


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up...")
    await init_db()
    from src.ml.detection_engine import DetectionEngine
    engine = DetectionEngine.get_instance()
    app.state.engine = engine
    if engine.is_ready:
        logger.success("Detection engine ready")
    else:
        logger.warning("Engine not ready — train models first")
    yield
    logger.info("Shutting down...")


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(detect.router,    prefix="/api", tags=["Detection"])
app.include_router(alerts.router,    prefix="/api", tags=["Alerts"])
app.include_router(incidents.router, prefix="/api", tags=["Incidents"])
app.include_router(stats.router,     prefix="/api", tags=["Stats"])
app.include_router(approvals.router, prefix="/api", tags=["Approvals"])
app.include_router(drift.router,     prefix="/api", tags=["Drift"])


@app.get("/api/health", tags=["System"])
async def health():
    from src.ml.detection_engine import DetectionEngine
    engine = DetectionEngine.get_instance()
    status = engine.status()
    return {
        "status":        "ok" if engine.is_ready else "degraded",
        "version":       settings.app_version,
        "model_origin":  getattr(engine, "data_origin", "unloaded"),
        "run_id":        getattr(engine, "active_run_id", "none"),
        "certified":     status.get("certified", False),
        "run_type":      status.get("run_type", "unknown"),
        "is_ready":      engine.is_ready,
        "engine":        status,
    }


@app.get("/", tags=["System"])
async def root():
    return {
        "name":    settings.app_name,
        "version": settings.app_version,
        "docs":    "/docs",
    }
