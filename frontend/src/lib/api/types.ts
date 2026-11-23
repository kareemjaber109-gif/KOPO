import { z } from 'zod'

// 1. Detection Response Schema
export const DetectionResponseSchema = z.object({
  is_attack: z.boolean(),
  attack_type: z.string(),
  attack_category: z.string().optional().default('Normal Traffic'),
  confidence: z.number(),
  severity_score: z.number(),
  severity_label: z.string(),
  should_alert: z.boolean(),
  anomaly_score: z.number().nullable().optional(),
  is_anomaly: z.boolean().nullable().optional(),
  ensemble_votes: z.record(z.any()).optional().default({}),
  model_results: z.record(z.any()).optional().default({}),
  timestamp: z.string().or(z.date()),
  alert_id: z.string().nullable().optional(),
})

export type DetectionResponse = z.infer<typeof DetectionResponseSchema>

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
  source_ip: z.string().nullable().optional(),
  dest_ip: z.string().nullable().optional(),
  is_acknowledged: z.boolean(),
  raw_result: z.string().nullable().optional(),
})

export type AlertResponse = z.infer<typeof AlertResponseSchema>

// 3. Alert List Schema
export const AlertListResponseSchema = z.object({
  total: z.number(),
  alerts: z.array(AlertResponseSchema),
})

export type AlertListResponse = z.infer<typeof AlertListResponseSchema>

// 4. Stats Summary Schema
export const StatsResponseSchema = z.object({
  total_analyzed: z.number(),
  total_alerts: z.number(),
  attack_rate: z.number(),
  by_attack_type: z.record(z.number()),
  by_severity: z.record(z.number()),
  recent_24h: z.number(),
})

export type StatsResponse = z.infer<typeof StatsResponseSchema>

// 5. Health Response Schema
export const HealthResponseSchema = z.object({
  status: z.string(),
  version: z.string().optional(),
  engine: z.record(z.any()).optional(),
})

export type HealthResponse = z.infer<typeof HealthResponseSchema>

// 6. Agent Approval Schema (Feature Flagged Mock)
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
  audit_comment: z.string().optional(),
  decided_at: z.string().optional(),
  decided_by: z.string().optional(),
})

export type AgentApproval = z.infer<typeof AgentApprovalSchema>

// 7. Unknown Anomaly / Drift Cluster Schema (Feature Flagged Mock)
export const DriftClusterSchema = z.object({
  id: z.string(),
  cluster_name: z.string(),
  sample_count: z.number(),
  reconstruction_error_mean: z.number(),
  divergent_features: z.array(z.string()),
  representative_flow: z.record(z.any()),
  first_detected: z.string(),
  last_detected: z.string(),
  severity: z.string(),
})

export type DriftCluster = z.infer<typeof DriftClusterSchema>
