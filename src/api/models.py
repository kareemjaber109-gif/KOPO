from datetime import datetime
from typing import Any, Optional
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
        }
    )
    source_ip: Optional[str] = None
    dest_ip:   Optional[str] = None


class DetectionResponse(BaseModel):
    is_attack:       bool
    attack_type:     str
    attack_category: Optional[str] = "Normal Traffic"
    confidence:      float
    severity_score:  int
    severity_label:  str
    should_alert:    bool
    anomaly_score:   Optional[float] = None
    is_anomaly:      Optional[bool] = None
    ensemble_votes:  dict
    model_results:   dict
    timestamp:       datetime
    alert_id:        Optional[str] = None


class AlertResponse(BaseModel):
    id:              int
    timestamp:       datetime
    attack_type:     str
    attack_category: Optional[str] = None
    severity_label:  str
    severity_score:  int
    confidence:      float
    anomaly_score:   Optional[float] = None
    is_anomaly:      Optional[bool] = None
    source_ip:       Optional[str]
    dest_ip:         Optional[str]
    is_acknowledged: bool
    raw_result:      Optional[str] = None


class AlertListResponse(BaseModel):
    total:  int
    alerts: list[AlertResponse]


class StatsResponse(BaseModel):
    total_analyzed:  int
    total_alerts:    int
    attack_rate:     float
    by_attack_type:  dict[str, int]
    by_severity:     dict[str, int]
    recent_24h:      int