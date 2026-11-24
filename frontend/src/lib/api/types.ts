import { z } from 'zod'

// 1. Detection Response Schema
export const DetectionResponseSchema = z.object({
  is_attack: z.boolean(),
  attack_type: z.string(),
  attack_category: z.string().optional().default('Normal Traffic'),
  confidence: z.number(),
  severity_score: z.number(),
  severity_label: z.string(),
  action: z.string().optional().default('ALLOW'),
  should_alert: z.boolean(),
  anomaly_score: z.number().nullable().optional(),
  is_anomaly: z.boolean().nullable().optional(),
  ensemble_votes: z.record(z.string(), z.any()).optional().default({}),
  model_results: z.record(z.string(), z.any()).optional().default({}),
  timestamp: z.string().or(z.date()),
  alert_id: z.string().nullable().optional(),
})

export type DetectionResponse = z.infer<typeof DetectionResponseSchema>

// 1b. Batch Detection & Upload Schemas
export const BatchDetectResponseSchema = z.object({
  total: z.number(),
  attacks_detected: z.number(),
  benign_count: z.number(),
  alerts_created: z.number(),
  incidents_created: z.number().optional().default(0),
  by_attack_type: z.record(z.string(), z.number()),
  by_severity: z.record(z.string(), z.number()),
  by_action: z.record(z.string(), z.number()),
  results: z.array(DetectionResponseSchema),
})

export type BatchDetectResponse = z.infer<typeof BatchDetectResponseSchema>

export const FlowUploadResponseSchema = z.object({
  filename: z.string(),
  total_rows: z.number(),
  processed: z.number(),
  skipped_rows: z.number(),
  attacks_detected: z.number(),
  benign_count: z.number(),
  alerts_created: z.number(),
  incidents_created: z.number().optional().default(0),
  by_attack_type: z.record(z.string(), z.number()),
  by_severity: z.record(z.string(), z.number()),
  by_action: z.record(z.string(), z.number()),
  sample_results: z.array(DetectionResponseSchema),
})

export type FlowUploadResponse = z.infer<typeof FlowUploadResponseSchema>

// 2. Alert Record Schema
export const AlertResponseSchema = z.object({
  id: z.number(),
  timestamp: z.string().or(z.date()),
  attack_type: z.string(),
  attack_category: z.string().optional().default('Threat Vector'),
  severity_label: z.string(),
  severity_score: z.number(),
  confidence: z.number(),
  anomaly_score: z.number().nullable().optional(),
  is_anomaly: z.boolean().nullable().optional(),
  action: z.string().nullable().optional(),
  source_ip: z.string().nullable().optional(),
  dest_ip: z.string().nullable().optional(),
  is_acknowledged: z.boolean(),
  acknowledged_by: z.string().nullable().optional(),
  acknowledged_at: z.string().or(z.date()).nullable().optional(),
  incident_id: z.number().nullable().optional(),
  raw_result: z.string().nullable().optional(),
})

export type AlertResponse = z.infer<typeof AlertResponseSchema>

// 3. Alert List Schema
export const AlertListResponseSchema = z.object({
  total: z.number(),
  alerts: z.array(AlertResponseSchema),
})

export type AlertListResponse = z.infer<typeof AlertListResponseSchema>

// 3b. Analyst Note Schema
export const NoteResponseSchema = z.object({
  id: z.number(),
  incident_id: z.number().nullable().optional(),
  alert_id: z.number().nullable().optional(),
  author: z.string(),
  note: z.string(),
  created_at: z.string().or(z.date()),
})

export type NoteResponse = z.infer<typeof NoteResponseSchema>

// 3c. Incident Schemas
export const IncidentResponseSchema = z.object({
  id: z.number(),
  title: z.string(),
  status: z.enum(['open', 'investigating', 'resolved', 'false_positive']),
  severity_label: z.string(),
  severity_score: z.number(),
  primary_attack_type: z.string(),
  attack_types: z.array(z.string()),
  source_ips: z.array(z.string()),
  dest_ips: z.array(z.string()),
  alert_count: z.number(),
  first_seen: z.string().or(z.date()),
  last_seen: z.string().or(z.date()),
  created_at: z.string().or(z.date()),
  updated_at: z.string().or(z.date()),
  assigned_to: z.string().nullable().optional(),
})

export type IncidentResponse = z.infer<typeof IncidentResponseSchema>

export const IncidentDetailResponseSchema = IncidentResponseSchema.extend({
  alerts: z.array(AlertResponseSchema).default([]),
  notes: z.array(NoteResponseSchema).default([]),
})

export type IncidentDetailResponse = z.infer<typeof IncidentDetailResponseSchema>

export const IncidentListResponseSchema = z.object({
  total: z.number(),
  incidents: z.array(IncidentResponseSchema),
})

export type IncidentListResponse = z.infer<typeof IncidentListResponseSchema>

// 4. Stats Summary & Timeline Schemas
export const StatsResponseSchema = z.object({
  total_analyzed: z.number(),
  total_alerts: z.number(),
  attack_rate: z.number(),
  by_attack_type: z.record(z.string(), z.number()),
  by_severity: z.record(z.string(), z.number()),
  recent_24h: z.number(),
  open_alerts: z.number().optional().default(0),
  open_incidents: z.number().optional().default(0),
  by_action: z.record(z.string(), z.number()).optional().default({}),
})

export type StatsResponse = z.infer<typeof StatsResponseSchema>

export const TimelineBucketSchema = z.object({
  timestamp: z.string(),
  label: z.string(),
  total_analyzed: z.number(),
  total_alerts: z.number(),
  critical_alerts: z.number(),
  high_alerts: z.number(),
  benign_flows: z.number(),
})

export const TimelineResponseSchema = z.object({
  hours: z.number(),
  bucket: z.string(),
  buckets: z.array(TimelineBucketSchema),
})

export type TimelineResponse = z.infer<typeof TimelineResponseSchema>

// 5. Health Response Schema
export const HealthResponseSchema = z.object({
  status: z.string(),
  version: z.string().optional(),
  model_origin: z.string().optional(),
  run_id: z.string().optional(),
  certified: z.boolean().optional(),
  run_type: z.string().optional(),
  is_ready: z.boolean().optional(),
  engine: z.record(z.string(), z.any()).optional(),
})

export type HealthResponse = z.infer<typeof HealthResponseSchema>

// 6. Agent Approval Schema
export const AgentApprovalSchema = z.object({
  id: z.string(),
  agent: z.string(),
  action: z.enum(['BLOCK_IP', 'ISOLATE_HOST', 'VIRUSTOTAL_SCAN', 'RESET_CREDENTIALS', 'RATE_LIMIT']),
  target: z.string(),
  severity: z.string(),
  rationale: z.string(),
  evidence_alert_ids: z.array(z.number()),
  created_at: z.string(),
  status: z.enum(['pending_human_approval', 'approved', 'denied']),
  proposed_by: z.string(),
  audit_comment: z.string().nullable().optional(),
  decided_at: z.string().nullable().optional(),
  decided_by: z.string().nullable().optional(),
})

export type AgentApproval = z.infer<typeof AgentApprovalSchema>

// 7. Unknown Anomaly / Drift Cluster Schema
export const DriftClusterSchema = z.object({
  id: z.string(),
  cluster_name: z.string(),
  sample_count: z.number(),
  reconstruction_error_mean: z.number(),
  divergent_features: z.array(z.string()),
  representative_flow: z.record(z.string(), z.any()),
  first_detected: z.string(),
  last_detected: z.string(),
  severity: z.string(),
  alert_ids: z.array(z.number()).optional().default([]),
})

export type DriftCluster = z.infer<typeof DriftClusterSchema>
