from datetime import datetime
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    select,
    text,
)
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from src.api.services.auth_service import hash_password
from src.utils.config import settings
from src.utils.logger import logger

engine = create_async_engine(
    settings.database_url,
    connect_args={"check_same_thread": False},
)

AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Incident(Base):
    __tablename__ = "incidents"

    id                  = Column(Integer, primary_key=True, autoincrement=True)
    title               = Column(String(200), nullable=False)
    status              = Column(String(32), nullable=False, default="open", index=True)
    severity_label      = Column(String(16), nullable=False, index=True)
    severity_score      = Column(Integer, nullable=False, default=3)
    primary_attack_type = Column(String(64), nullable=False, index=True)
    attack_types        = Column(Text, nullable=False, default="[]")
    source_ips          = Column(Text, nullable=False, default="[]")
    dest_ips            = Column(Text, nullable=False, default="[]")
    alert_count         = Column(Integer, nullable=False, default=0)
    first_seen          = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_seen           = Column(DateTime, nullable=False, default=datetime.utcnow, index=True)
    created_at          = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at          = Column(DateTime, nullable=False, default=datetime.utcnow)
    assigned_to         = Column(String(100), nullable=True)


class Alert(Base):
    __tablename__ = "alerts"

    id              = Column(Integer, primary_key=True, autoincrement=True)
    timestamp       = Column(DateTime, default=datetime.utcnow, index=True)
    attack_type     = Column(String(64), nullable=False)
    severity_score  = Column(Integer, nullable=False)
    severity_label  = Column(String(16), nullable=False)
    confidence      = Column(Float, nullable=False)
    anomaly_score   = Column(Float, nullable=True)
    is_anomaly      = Column(Boolean, nullable=True)
    is_attack       = Column(Boolean, default=True)
    action          = Column(String(16), nullable=True)
    source_ip       = Column(String(45), nullable=True)
    dest_ip         = Column(String(45), nullable=True)
    is_acknowledged = Column(Boolean, default=False)
    acknowledged_by = Column(String(100), nullable=True)
    acknowledged_at = Column(DateTime, nullable=True)
    incident_id     = Column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    raw_result      = Column(Text, nullable=True)


class AnalysisLog(Base):
    __tablename__ = "analysis_log"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    timestamp     = Column(DateTime, default=datetime.utcnow, index=True)
    is_attack     = Column(Boolean, nullable=False)
    attack_type   = Column(String(64), nullable=False)
    confidence    = Column(Float, nullable=False)
    anomaly_score = Column(Float, nullable=True)
    is_anomaly    = Column(Boolean, nullable=True)
    action        = Column(String(16), nullable=True)
    source_ip     = Column(String(45), nullable=True)
    dest_ip       = Column(String(45), nullable=True)


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id          = Column(Integer, primary_key=True, autoincrement=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=True, index=True)
    alert_id    = Column(Integer, ForeignKey("alerts.id", ondelete="CASCADE"), nullable=True, index=True)
    author      = Column(String(100), nullable=False, default="SOC Analyst")
    note        = Column(Text, nullable=False)
    created_at  = Column(DateTime, nullable=False, default=datetime.utcnow)


class AgentApprovalRecord(Base):
    __tablename__ = "agent_approvals"

    id                 = Column(String(64), primary_key=True)
    agent              = Column(String(100), nullable=False)
    action             = Column(String(32), nullable=False)
    target             = Column(String(128), nullable=False)
    severity           = Column(String(16), nullable=False)
    rationale          = Column(Text, nullable=False)
    evidence_alert_ids = Column(Text, nullable=False, default="[]")
    created_at         = Column(DateTime, nullable=False, default=datetime.utcnow)
    status             = Column(String(32), nullable=False, default="pending_human_approval", index=True)
    proposed_by        = Column(String(100), nullable=False)
    audit_comment      = Column(Text, nullable=True)
    decided_at         = Column(DateTime, nullable=True)
    decided_by         = Column(String(100), nullable=True)


class UserAccount(Base):
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, autoincrement=True)
    name          = Column(String(120), nullable=False)
    email         = Column(String(180), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=False)
    role          = Column(String(32), nullable=False, default="tier1")
    created_at    = Column(DateTime, nullable=False, default=datetime.utcnow)
    last_login_at = Column(DateTime, nullable=True)


_MIGRATION_COLUMNS = {
    "alerts": {
        "action": "VARCHAR(16)",
        "incident_id": "INTEGER",
        "acknowledged_by": "VARCHAR(100)",
        "acknowledged_at": "DATETIME",
        "anomaly_score": "FLOAT",
        "is_anomaly": "BOOLEAN",
    },
    "analysis_log": {
        "action": "VARCHAR(16)",
        "source_ip": "VARCHAR(45)",
        "dest_ip": "VARCHAR(45)",
        "anomaly_score": "FLOAT",
        "is_anomaly": "BOOLEAN",
    },
}


def _apply_sqlite_migrations(sync_conn):
    """Add any new columns to pre-existing SQLite tables without dropping data."""
    for table_name, columns in _MIGRATION_COLUMNS.items():
        rows = sync_conn.execute(text(f"PRAGMA table_info({table_name})")).fetchall()
        existing = {row[1] for row in rows}
        for col_name, col_type in columns.items():
            if col_name not in existing:
                sync_conn.execute(
                    text(f"ALTER TABLE {table_name} ADD COLUMN {col_name} {col_type}")
                )
                logger.info(f"Migrated SQLite table '{table_name}': added column '{col_name}'")

    # Ensure index exists for alerts.incident_id even on migrated databases
    sync_conn.execute(
        text("CREATE INDEX IF NOT EXISTS ix_alerts_incident_id ON alerts (incident_id)")
    )


_DEFAULT_ACCOUNTS = [
    ("Ahmed K. (Tier 2 Analyst)", "analyst@kopo.defense", "User@1234", "tier2"),
    ("Layla S. (Tier 1 Triage)", "triage@kopo.defense", "User@1234", "tier1"),
    ("Dr. Ziad (SOC Admin)", "admin@kopo.defense", "Admin@1234", "admin"),
]


async def _seed_default_users():
    async with AsyncSessionLocal() as session:
        changed = False
        for name, email, raw_pw, role in _DEFAULT_ACCOUNTS:
            exists = (
                await session.execute(select(UserAccount.id).where(UserAccount.email == email))
            ).scalar_one_or_none()
            if exists is None:
                session.add(
                    UserAccount(
                        name=name,
                        email=email,
                        password_hash=hash_password(raw_pw),
                        role=role,
                    )
                )
                changed = True
        if changed:
            await session.commit()


async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
        if conn.dialect.name == "sqlite":
            await conn.run_sync(_apply_sqlite_migrations)
    await _seed_default_users()
    logger.info("Database initialised")


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        yield session
