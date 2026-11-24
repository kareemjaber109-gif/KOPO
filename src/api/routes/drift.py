import json
from collections import Counter
from typing import Any, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy import desc, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.database import Alert, get_db
from src.api.models import DriftClusterResponse

router = APIRouter()


def _safe_parse_json(raw: Optional[str]) -> dict[str, Any]:
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


@router.get("/drift-clusters", response_model=list[DriftClusterResponse])
async def list_drift_clusters(
    limit: int = Query(12, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
):
    """Cluster recent behavioral/unsupervised anomaly alerts directly from DB telemetry."""
    rows = (
        await db.execute(
            select(Alert)
            .where(or_(Alert.is_anomaly.is_(True), Alert.attack_type == "ANOMALY"))
            .order_by(desc(Alert.timestamp))
            .limit(400)
        )
    ).scalars().all()

    if not rows:
        return []

    buckets: dict[str, list[Alert]] = {}
    for a in rows:
        buckets.setdefault(a.attack_type or "ANOMALY", []).append(a)

    clusters: list[DriftClusterResponse] = []
    for idx, (atk_type, group) in enumerate(
        sorted(buckets.items(), key=lambda x: len(x[1]), reverse=True)[:limit], start=1
    ):
        scores = [float(a.anomaly_score) for a in group if a.anomaly_score is not None]
        mean_score = round(sum(scores) / len(scores), 4) if scores else 0.99

        feat_counter: Counter[str] = Counter()
        rep_flow: dict[str, Any] = {}
        for a in group[:25]:
            parsed = _safe_parse_json(a.raw_result)
            sample = parsed.get("input_features_sample")
            if isinstance(sample, dict) and not rep_flow:
                rep_flow = sample
            elif parsed and not rep_flow:
                rep_flow = {
                    k: v
                    for k, v in parsed.items()
                    if k not in ("model_results", "ensemble_votes")
                }
            if isinstance(sample, dict):
                for fk, fv in sample.items():
                    if isinstance(fv, (int, float)) and abs(fv) > 0:
                        feat_counter[fk] += 1

        divergent = [k for k, _ in feat_counter.most_common(4)] or [
            "Anomaly Score Divergence",
            "Autoencoder Reconstruction Delta",
            "Isolation Forest Path Depth",
        ]

        if not rep_flow:
            rep_flow = {
                "attack_type": atk_type,
                "source_ip": group[0].source_ip,
                "dest_ip": group[0].dest_ip,
                "confidence": group[0].confidence,
                "anomaly_score": group[0].anomaly_score,
            }

        max_sev = max((a.severity_score for a in group), default=3)
        sev_label = "Critical" if max_sev >= 5 else "High" if max_sev >= 4 else "Medium"
        slug = atk_type.lower().replace("_", "-")
        clusters.append(
            DriftClusterResponse(
                id=f"cluster-{idx:02d}-{slug}",
                cluster_name=f"{atk_type} Behavioral Divergence",
                sample_count=len(group),
                reconstruction_error_mean=mean_score,
                divergent_features=divergent,
                representative_flow=rep_flow,
                first_detected=min(a.timestamp for a in group),
                last_detected=max(a.timestamp for a in group),
                severity=sev_label,
                alert_ids=[a.id for a in group[:20]],
            )
        )

    return clusters
