from datetime import datetime
from typing import Any, Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class NetworkFlowRequest(BaseModel):
    model_config = ConfigDict(extra="allow")

    features: Optional[dict[str, Any]] = Field(
        default=None,
        description="Feature name to float value",
        example={
            "SYN Flag Count": 1,
            "Flow Duration": 50000,
            "Total Fwd Packets": 10,
            "Flow Bytes/s": 1200,
            "FIN Flag Count": 1,
        },
    )
    source_ip: Optional[str] = None
    dest_ip: Optional[str] = None


class DetectionResponse(BaseModel):
    is_attack: bool
    attack_type: str
    attack_category: Optional[str] = "Normal Traffic"
    confidence: float
    severity_score: int
    severity_label: str
    action: Optional[str] = "ALLOW"
    should_alert: bool
    anomaly_score: Optional[float] = None
    is_anomaly: Optional[bool] = None
    ensemble_votes: dict
    model_results: dict
    timestamp: datetime
    alert_id: Optional[str] = None


class BatchDetectRequest(BaseModel):
    flows: list[NetworkFlowRequest] = Field(..., min_length=1, max_length=1000)
    aggregate_incidents: bool = False


class BatchDetectResponse(BaseModel):
    total: int
    attacks_detected: int
    benign_count: int
    alerts_created: int
    incidents_created: int = 0
    by_attack_type: dict[str, int]
    by_severity: dict[str, int]
    by_action: dict[str, int]
    results: list[DetectionResponse]


class FlowUploadResponse(BaseModel):
    filename: str
    total_rows: int
    processed: int
    skipped_rows: int
    attacks_detected: int
    benign_count: int
    alerts_created: int
    incidents_created: int = 0
    by_attack_type: dict[str, int]
    by_severity: dict[str, int]
    by_action: dict[str, int]
    sample_results: list[DetectionResponse]


class AlertResponse(BaseModel):
    id: int
    timestamp: datetime
    attack_type: str
    attack_category: Optional[str] = None
    severity_label: str
    severity_score: int
    confidence: float
    anomaly_score: Optional[float] = None
    is_anomaly: Optional[bool] = None
    action: Optional[str] = None
    source_ip: Optional[str]
    dest_ip: Optional[str]
    is_acknowledged: bool
    acknowledged_by: Optional[str] = None
    acknowledged_at: Optional[datetime] = None
    incident_id: Optional[int] = None
    raw_result: Optional[str] = None


class AlertListResponse(BaseModel):
    total: int
    alerts: list[AlertResponse]


class BulkAcknowledgeRequest(BaseModel):
    alert_ids: list[int] = Field(..., min_length=1, max_length=1000)
    analyst: Optional[str] = "SOC Analyst"


class BulkAcknowledgeResponse(BaseModel):
    updated_count: int
    alert_ids: list[int]


class AcknowledgeRequest(BaseModel):
    analyst: Optional[str] = "SOC Analyst"


class NoteCreateRequest(BaseModel):
    note: str = Field(..., min_length=1, max_length=4000)
    author: str = Field(default="SOC Analyst", min_length=1, max_length=100)


class NoteResponse(BaseModel):
    id: int
    incident_id: Optional[int] = None
    alert_id: Optional[int] = None
    author: str
    note: str
    created_at: datetime


class AlertDetailResponse(AlertResponse):
    notes: list[NoteResponse] = []


class IncidentResponse(BaseModel):
    id: int
    title: str
    status: Literal["open", "investigating", "resolved", "false_positive"]
    severity_label: str
    severity_score: int
    primary_attack_type: str
    attack_types: list[str]
    source_ips: list[str]
    dest_ips: list[str]
    alert_count: int
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    assigned_to: Optional[str] = None


class IncidentDetailResponse(IncidentResponse):
    alerts: list[AlertResponse] = []
    notes: list[NoteResponse] = []


class IncidentListResponse(BaseModel):
    total: int
    incidents: list[IncidentResponse]


class IncidentAggregateRequest(BaseModel):
    window_minutes: int = Field(default=60, ge=1, le=1440)
    include_acknowledged: bool = False


class IncidentAggregateResponse(BaseModel):
    incidents_created: int
    incidents_updated: int
    alerts_linked: int
    incidents: list[IncidentResponse]


class IncidentUpdateRequest(BaseModel):
    status: Optional[Literal["open", "investigating", "resolved", "false_positive"]] = None
    assigned_to: Optional[str] = Field(default=None, max_length=100)
    title: Optional[str] = Field(default=None, min_length=1, max_length=200)
    acknowledge_alerts: bool = False
    analyst: Optional[str] = "SOC Analyst"


class StatsResponse(BaseModel):
    total_analyzed: int
    total_alerts: int
    attack_rate: float
    by_attack_type: dict[str, int]
    by_severity: dict[str, int]
    recent_24h: int
    open_alerts: int = 0
    open_incidents: int = 0
    by_action: dict[str, int] = {}


class TimelineBucket(BaseModel):
    timestamp: str
    label: str
    total_analyzed: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    benign_flows: int


class TimelineResponse(BaseModel):
    hours: int
    bucket: str
    buckets: list[TimelineBucket]


class AgentApprovalResponse(BaseModel):
    id: str
    agent: str
    action: Literal["BLOCK_IP", "ISOLATE_HOST", "VIRUSTOTAL_SCAN", "RESET_CREDENTIALS", "RATE_LIMIT"]
    target: str
    severity: str
    rationale: str
    evidence_alert_ids: list[int]
    created_at: datetime
    status: Literal["pending_human_approval", "approved", "denied"]
    proposed_by: str
    audit_comment: Optional[str] = None
    decided_at: Optional[datetime] = None
    decided_by: Optional[str] = None


class AgentApprovalDecisionRequest(BaseModel):
    decision: Literal["approved", "denied"]
    comment: str = Field(default="", max_length=2000)
    analyst: str = Field(default="SOC Lead Analyst", min_length=1, max_length=100)


class DriftClusterResponse(BaseModel):
    id: str
    cluster_name: str
    sample_count: int
    reconstruction_error_mean: float
    divergent_features: list[str]
    representative_flow: dict[str, Any]
    first_detected: datetime
    last_detected: datetime
    severity: str
    alert_ids: list[int] = []


class AuthRegisterRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=120)
    email: str = Field(..., min_length=5, max_length=180)
    password: str = Field(..., min_length=6, max_length=128)
    confirm_password: Optional[str] = None
    role: Literal["tier1", "tier2", "admin"] = "tier1"
    portal: Literal["user", "admin"] = "user"
    invite_code: Optional[str] = None


class AuthLoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=180)
    password: str = Field(..., min_length=1, max_length=128)
    portal: Literal["user", "admin"] = "user"


class AuthUserResponse(BaseModel):
    id: int
    name: str
    email: str
    role: str
    created_at: datetime
    last_login_at: Optional[datetime] = None


class AuthResponse(BaseModel):
    user: AuthUserResponse
    token: str
    portal: Literal["user", "admin"]
