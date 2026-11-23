# KOPO IDS — Backend API TODO & Proposed Endpoints

This document tracks endpoints needed by the KOPO SOC Analyst Console that are either partially implemented or proposed for future backend milestones. In the meantime, the frontend handles these via the typed Mock Adapter (`src/lib/api/mockAdapter.ts`).

---

## 1. PROPOSED: Enhanced Alerts Query & Batch Acknowledge

### `PATCH /api/alerts/bulk-acknowledge`
- **Goal:** Allow SOC Tier 1/2 analysts to bulk-acknowledge or triage multiple alerts simultaneously.
- **Request Body:**
  ```json
  {
    "alert_ids": [101, 102, 103],
    "analyst_id": "analyst_soc_01",
    "note": "Bulk triage - confirmed false positive burst"
  }
  ```
- **Response:**
  ```json
  {
    "acknowledged_count": 3,
    "timestamp": "2026-11-23T10:00:00Z"
  }
  ```
- **Required SQL:**
  ```sql
  UPDATE alerts
  SET is_acknowledged = TRUE,
      raw_result = jsonb_set(
        COALESCE(raw_result, '{}'::jsonb),
        '{analyst_note}',
        to_jsonb('Bulk triage - confirmed false positive burst'::text)
      )
  WHERE id = ANY(:alert_ids);
  ```

---

## 2. PROPOSED: Related Alerts by IP Correlation

### `GET /api/alerts/related?ip={source_ip}&limit=10`
- **Goal:** Correlate ongoing attack campaigns from the same host across different flow protocols and destination ports.
- **Response:**
  ```json
  {
    "source_ip": "192.168.1.105",
    "total_alerts": 14,
    "first_seen": "2026-11-23T08:12:00Z",
    "last_seen": "2026-11-23T09:45:00Z",
    "alerts": [ ... ]
  }
  ```
- **Required SQL:**
  ```sql
  SELECT id, timestamp, attack_type, severity_label, confidence, dest_ip
  FROM alerts
  WHERE source_ip = :ip
  ORDER BY timestamp DESC
  LIMIT :limit;
  ```

---

## 3. PROPOSED: Agentic SOC Actions & Approval Queue

### `GET /api/agent/approvals`
- **Goal:** Surface high-impact remediation actions proposed by AI Agents (e.g. Cloudflare IP block, firewall drop, host isolation) requiring Human-in-the-Loop authorization.
- **Response:**
  ```json
  {
    "pending_approvals": [
      {
        "id": "appr_901",
        "agent": "Firewall Remediation Sentinel",
        "action": "BLOCK_IP",
        "target": "185.220.101.5",
        "severity": "Critical",
        "rationale": "Sustained SYN Flood and SQL Injection attempts (>16,000 pps)",
        "evidence_alert_ids": [452, 453, 454],
        "created_at": "2026-11-23T09:30:00Z",
        "status": "pending_human_approval"
      }
    ]
  }
  ```

### `POST /api/agent/approvals/{id}/decision`
- **Goal:** Record human approval or denial with mandatory analyst audit logging.
- **Request:**
  ```json
  {
    "decision": "APPROVED", // or "DENIED"
    "analyst_id": "tier2_ahmed",
    "comment": "Verified hostile external IP against abuse DB"
  }
  ```

---

## 4. PROPOSED: Unknown Anomaly & Distribution Drift API

### `GET /api/drift/anomalies`
- **Goal:** Fetch flows rejected by supervised classifiers as unclassified but flagged with high reconstruction error by Dual Deep Autoencoder (>0.985).
- **Response:**
  ```json
  {
    "total_unknown": 42,
    "drift_detected": true,
    "drift_score": 0.142,
    "clusters": [
      {
        "cluster_id": "cluster_zero_day_alpha",
        "sample_count": 18,
        "divergent_features": ["Flow IAT Min", "Packet Length Variance"],
        "representative_flow": { ... }
      }
    ]
  }
  ```

---

## 5. PROPOSED: Analyst Local/Server Notes

### `POST /api/alerts/{id}/notes`
- **Goal:** Store SOC analyst findings directly on the alert record for shift handovers and audit compliance.
