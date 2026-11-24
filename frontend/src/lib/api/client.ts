import { z } from 'zod'
import {
  DetectionResponse, DetectionResponseSchema,
  BatchDetectResponse, BatchDetectResponseSchema,
  FlowUploadResponse, FlowUploadResponseSchema,
  AlertListResponse, AlertListResponseSchema,
  AlertResponse,
  IncidentResponse,
  IncidentListResponse, IncidentListResponseSchema,
  IncidentDetailResponse, IncidentDetailResponseSchema,
  NoteResponse, NoteResponseSchema,
  StatsResponse, StatsResponseSchema,
  TimelineResponse, TimelineResponseSchema,
  HealthResponse, HealthResponseSchema,
  AgentApproval, AgentApprovalSchema,
  DriftCluster, DriftClusterSchema,
} from './types'
import { SEEDED_ALERTS, SEEDED_AGENT_APPROVALS, SEEDED_DRIFT_CLUSTERS } from './mockData'

const IS_MOCK_ENV = import.meta.env.VITE_USE_MOCK === 'true'
const BASE = import.meta.env.VITE_API_BASE_URL || '/api'

class MockAdapter {
  private alertsList: AlertResponse[] = [...SEEDED_ALERTS]
  private approvals: AgentApproval[] = [...SEEDED_AGENT_APPROVALS]
  private driftClusters: DriftCluster[] = [...SEEDED_DRIFT_CLUSTERS]
  private alertNotes: Record<number, NoteResponse[]> = {}
  private incidentsList: IncidentResponse[] = []
  private incidentNotes: Record<number, NoteResponse[]> = {}

  async health(): Promise<HealthResponse> {
    return {
      status: 'ok',
      version: '1.2.0-mock',
      model_origin: 'real',
      run_id: 'run_clean_benchmark_v1',
      certified: false,
      run_type: 'research_baseline',
      is_ready: true,
      engine: {
        loaded: true,
        n_features: 69,
        class_names: ['BENIGN', 'Bot', 'BruteForce', 'DDoS', 'DoS', 'Infiltration', 'PortScan', 'WebAttack'],
      },
    }
  }

  async stats(): Promise<StatsResponse> {
    const total_alerts = this.alertsList.length
    const open_alerts = this.alertsList.filter(a => !a.is_acknowledged).length
    const by_severity: Record<string, number> = {}
    const by_attack_type: Record<string, number> = {}

    this.alertsList.forEach(a => {
      by_severity[a.severity_label] = (by_severity[a.severity_label] || 0) + 1
      by_attack_type[a.attack_type] = (by_attack_type[a.attack_type] || 0) + 1
    })

    return {
      total_analyzed: 42180,
      total_alerts,
      attack_rate: total_alerts / 42180,
      by_attack_type,
      by_severity,
      recent_24h: total_alerts,
      open_alerts,
      open_incidents: this.incidentsList.filter(i => i.status === 'open' || i.status === 'investigating').length,
      by_action: { DROP: total_alerts },
    }
  }

  async statsTimeline(hours = 24, bucket = '1h'): Promise<TimelineResponse> {
    const now = Date.now()
    const buckets = Array.from({ length: 12 }, (_, idx) => {
      const ts = new Date(now - (11 - idx) * 3600_000)
      return {
        timestamp: ts.toISOString(),
        label: ts.toTimeString().slice(0, 5),
        total_analyzed: 30 + idx * 4,
        total_alerts: (idx % 3) + 1,
        critical_alerts: idx % 4 === 0 ? 1 : 0,
        high_alerts: idx % 2,
        benign_flows: 28 + idx * 3,
      }
    })
    return { hours, bucket, buckets }
  }

  async alerts(params: Record<string, any> = {}): Promise<AlertListResponse> {
    let list = [...this.alertsList]
    if (params.severity) list = list.filter(a => a.severity_label === params.severity)
    if (params.attack_type) list = list.filter(a => a.attack_type === params.attack_type)
    if (params.incident_id != null) list = list.filter(a => a.incident_id === Number(params.incident_id))
    if (params.unacknowledged_only) list = list.filter(a => !a.is_acknowledged)
    if (params.search && String(params.search).trim()) {
      const q = String(params.search).toLowerCase()
      list = list.filter(a =>
        a.attack_type?.toLowerCase().includes(q) ||
        a.source_ip?.toLowerCase().includes(q) ||
        a.dest_ip?.toLowerCase().includes(q) ||
        a.severity_label?.toLowerCase().includes(q)
      )
    }
    const limit = Number(params.limit || 100)
    const offset = Number(params.offset || 0)
    return { total: list.length, alerts: list.slice(offset, offset + limit) }
  }

  async detect(body: { features: Record<string, any>; source_ip?: string; dest_ip?: string }): Promise<DetectionResponse> {
    const f = body.features || {}
    const fwd = Number(f['Total Fwd Packets'] || 1)
    const port = Number(f['Destination Port'] || 80)
    const syn = Number(f['SYN Flag Count'] || 0)

    let attack_type = 'BENIGN'
    let attack_category = 'Normal Traffic'
    let is_attack = false
    let confidence = 0.998
    let severity_label = 'None'
    let severity_score = 0

    if (fwd > 3000 && port === 80) {
      attack_type = 'HTTP_FLOOD'; attack_category = 'DoS Attacks'; is_attack = true
      confidence = 0.994; severity_label = 'Critical'; severity_score = 5
    } else if (syn > 1000) {
      attack_type = 'SYN_FLOOD'; attack_category = 'DDoS & Floods'; is_attack = true
      confidence = 0.999; severity_label = 'Critical'; severity_score = 5
    } else if (port === 22 && Number(f['Flow Duration'] || 0) > 10000000) {
      attack_type = 'BRUTE_FORCE_SSH'; attack_category = 'Brute Force'; is_attack = true
      confidence = 0.942; severity_label = 'High'; severity_score = 4
    } else if (fwd <= 5 && f['Fwd Packet Length Max'] === 0) {
      attack_type = 'PORT_SCAN'; attack_category = 'Recon & Scans'; is_attack = true
      confidence = 0.985; severity_label = 'Low'; severity_score = 2
    }

    const alert_id = is_attack ? String(Math.floor(Math.random() * 9000) + 1000) : null
    if (is_attack && alert_id) {
      this.alertsList.unshift({
        id: Number(alert_id),
        timestamp: new Date().toISOString(),
        attack_type,
        attack_category,
        severity_label,
        severity_score,
        confidence,
        anomaly_score: 0.98,
        is_anomaly: true,
        action: 'DROP',
        source_ip: body.source_ip || '185.220.101.5',
        dest_ip: body.dest_ip || '192.168.1.10',
        is_acknowledged: false,
        raw_result: JSON.stringify(f),
      })
    }

    return {
      is_attack,
      attack_type,
      attack_category,
      confidence,
      severity_score,
      severity_label,
      action: is_attack ? 'DROP' : 'ALLOW',
      should_alert: is_attack,
      anomaly_score: is_attack ? 0.98 : 0.02,
      is_anomaly: is_attack,
      timestamp: new Date().toISOString(),
      alert_id,
      ensemble_votes: { attack: is_attack ? 4 : 0, total: 4 },
      model_results: {
        rf: { label: is_attack ? 'ATTACK' : 'BENIGN', confidence, is_attack },
        xgb: { label: attack_type, confidence, is_attack },
      },
    }
  }

  async detectBatch(flows: any[]): Promise<BatchDetectResponse> {
    const results = []
    for (const fl of flows) results.push(await this.detect(fl))
    return {
      total: results.length,
      attacks_detected: results.filter(r => r.is_attack).length,
      benign_count: results.filter(r => !r.is_attack).length,
      alerts_created: results.filter(r => r.should_alert).length,
      incidents_created: 0,
      by_attack_type: {},
      by_severity: {},
      by_action: {},
      results,
    }
  }

  async uploadFlowsFile(file: File): Promise<FlowUploadResponse> {
    return {
      filename: file.name,
      total_rows: 0,
      processed: 0,
      skipped_rows: 0,
      attacks_detected: 0,
      benign_count: 0,
      alerts_created: 0,
      incidents_created: 0,
      by_attack_type: {},
      by_severity: {},
      by_action: {},
      sample_results: [],
    }
  }

  async acknowledge(id: number): Promise<{ success: boolean; id: number }> {
    const found = this.alertsList.find(a => a.id === id)
    if (found) found.is_acknowledged = true
    return { success: true, id }
  }

  async bulkAcknowledge(ids: number[]): Promise<{ updated_count: number; count: number; alert_ids: number[] }> {
    let count = 0
    this.alertsList.forEach(a => {
      if (ids.includes(a.id) && !a.is_acknowledged) {
        a.is_acknowledged = true
        count++
      }
    })
    return { updated_count: count, count, alert_ids: ids }
  }

  async getAlertNotes(alertId: number): Promise<NoteResponse[]> {
    return this.alertNotes[alertId] || []
  }

  async addAlertNote(alertId: number, note: string, author = 'SOC Analyst'): Promise<NoteResponse> {
    const entry: NoteResponse = {
      id: Date.now(),
      alert_id: alertId,
      incident_id: null,
      author,
      note,
      created_at: new Date().toISOString(),
    }
    this.alertNotes[alertId] = [entry, ...(this.alertNotes[alertId] || [])]
    return entry
  }

  async incidents(): Promise<IncidentListResponse> {
    return { total: this.incidentsList.length, incidents: this.incidentsList }
  }

  async incidentDetail(id: number): Promise<IncidentDetailResponse> {
    const inc = this.incidentsList.find(i => i.id === id)
    if (!inc) throw new Error('Incident not found')
    return {
      ...inc,
      alerts: this.alertsList.filter(a => a.incident_id === id),
      notes: this.incidentNotes[id] || [],
    }
  }

  async aggregateIncidents() {
    return { incidents_created: 0, incidents_updated: 0, alerts_linked: 0, incidents: [] }
  }

  async updateIncident(id: number, patch: any): Promise<IncidentDetailResponse> {
    const inc = this.incidentsList.find(i => i.id === id)
    if (!inc) throw new Error('Incident not found')
    Object.assign(inc, patch, { updated_at: new Date().toISOString() })
    return this.incidentDetail(id)
  }

  async addIncidentNote(id: number, note: string, author = 'SOC Analyst'): Promise<NoteResponse> {
    const entry: NoteResponse = {
      id: Date.now(),
      incident_id: id,
      alert_id: null,
      author,
      note,
      created_at: new Date().toISOString(),
    }
    this.incidentNotes[id] = [entry, ...(this.incidentNotes[id] || [])]
    return entry
  }

  async modelReport(): Promise<any> {
    return {
      active_run_id: 'run_clean_benchmark_v1',
      certified: false,
      run_type: 'research_baseline',
      audit_status: 'MOCK MODE',
      models: {
        xgboost: { status: 'trained', macro_f1: 0.9357, accuracy: 0.9693, recall: 0.8058, precision: 0.9921 },
        random_forest: { status: 'trained', macro_f1: 0.9357, accuracy: 0.9693, recall: 0.8058, precision: 0.9921 },
        lstm: { status: 'excluded_in_manifest' },
        isolation_forest: { status: 'trained', roc_auc: 0.8493 },
        anomaly_ensemble: { status: 'trained', roc_auc: 0.8361, threshold: 0.9872 },
      },
    }
  }

  async getApprovals(): Promise<AgentApproval[]> {
    return [...this.approvals]
  }

  async syncApprovals(): Promise<{ created: number }> {
    return { created: 0 }
  }

  async decideApproval(id: string, decision: 'approved' | 'denied', comment: string, analyst: string): Promise<AgentApproval> {
    const item = this.approvals.find(a => a.id === id)
    if (!item) throw new Error(`Approval ${id} not found`)
    item.status = decision
    item.audit_comment = comment
    item.decided_by = analyst
    item.decided_at = new Date().toISOString()
    return item
  }

  async getDriftClusters(): Promise<DriftCluster[]> {
    return [...this.driftClusters]
  }
}

class RealAdapter {
  private async request(path: string, options: RequestInit = {}) {
    const headers: Record<string, string> = options.body instanceof FormData
      ? {}
      : { 'Content-Type': 'application/json' }
    const res = await fetch(`${BASE}${path}`, {
      headers: { ...headers, ...(options.headers as Record<string, string> | undefined) },
      ...options,
    })
    if (!res.ok) {
      let msg = `HTTP ${res.status}: ${res.statusText}`
      try {
        const err = await res.json()
        if (err?.detail) msg = String(err.detail)
      } catch {
        // ignore parse failure
      }
      throw new Error(msg)
    }
    return res.json()
  }

  async health(): Promise<HealthResponse> {
    return HealthResponseSchema.parse(await this.request('/health'))
  }

  async stats(): Promise<StatsResponse> {
    return StatsResponseSchema.parse(await this.request('/stats'))
  }

  async statsTimeline(hours = 24, bucket = '1h'): Promise<TimelineResponse> {
    const qs = new URLSearchParams({ hours: String(hours), bucket }).toString()
    return TimelineResponseSchema.parse(await this.request(`/stats/timeline?${qs}`))
  }

  async alerts(params: Record<string, any> = {}): Promise<AlertListResponse> {
    const clean = Object.fromEntries(
      Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '')
    )
    const qs = new URLSearchParams(clean as Record<string, string>).toString()
    return AlertListResponseSchema.parse(await this.request(`/alerts${qs ? `?${qs}` : ''}`))
  }

  async detect(body: any): Promise<DetectionResponse> {
    return DetectionResponseSchema.parse(
      await this.request('/detect', { method: 'POST', body: JSON.stringify(body) })
    )
  }

  async detectBatch(flows: any[], aggregateIncidents = false): Promise<BatchDetectResponse> {
    return BatchDetectResponseSchema.parse(
      await this.request('/detect/batch', {
        method: 'POST',
        body: JSON.stringify({ flows, aggregate_incidents: aggregateIncidents }),
      })
    )
  }

  async uploadFlowsFile(file: File, aggregateIncidents = false): Promise<FlowUploadResponse> {
    const formData = new FormData()
    formData.append('file', file)
    formData.append('aggregate_incidents', String(aggregateIncidents))
    return FlowUploadResponseSchema.parse(
      await this.request('/flows/upload', { method: 'POST', body: formData })
    )
  }

  async acknowledge(id: number, analyst?: string): Promise<any> {
    return this.request(`/alerts/${id}/acknowledge`, {
      method: 'PATCH',
      body: JSON.stringify({ analyst: analyst || 'SOC Analyst' }),
    })
  }

  async bulkAcknowledge(ids: number[], analyst?: string): Promise<{ updated_count: number; count: number; alert_ids: number[] }> {
    const json = await this.request('/alerts/bulk-acknowledge', {
      method: 'PATCH',
      body: JSON.stringify({ alert_ids: ids, analyst: analyst || 'SOC Analyst' }),
    })
    return { ...json, count: json.updated_count }
  }

  async getAlertNotes(alertId: number): Promise<NoteResponse[]> {
    const json = await this.request(`/alerts/${alertId}/notes`)
    return z.array(NoteResponseSchema).parse(json)
  }

  async addAlertNote(alertId: number, note: string, author = 'SOC Analyst'): Promise<NoteResponse> {
    return NoteResponseSchema.parse(
      await this.request(`/alerts/${alertId}/notes`, {
        method: 'POST',
        body: JSON.stringify({ note, author }),
      })
    )
  }

  async incidents(params: Record<string, any> = {}): Promise<IncidentListResponse> {
    const clean = Object.fromEntries(
      Object.entries(params).filter(([, v]) => v !== undefined && v !== null && v !== '')
    )
    const qs = new URLSearchParams(clean as Record<string, string>).toString()
    return IncidentListResponseSchema.parse(await this.request(`/incidents${qs ? `?${qs}` : ''}`))
  }

  async incidentDetail(id: number): Promise<IncidentDetailResponse> {
    return IncidentDetailResponseSchema.parse(await this.request(`/incidents/${id}`))
  }

  async aggregateIncidents(windowMinutes = 60, includeAcknowledged = false) {
    return this.request('/incidents/aggregate', {
      method: 'POST',
      body: JSON.stringify({
        window_minutes: windowMinutes,
        include_acknowledged: includeAcknowledged,
      }),
    })
  }

  async updateIncident(id: number, patch: any): Promise<IncidentDetailResponse> {
    return IncidentDetailResponseSchema.parse(
      await this.request(`/incidents/${id}`, {
        method: 'PATCH',
        body: JSON.stringify(patch),
      })
    )
  }

  async addIncidentNote(id: number, note: string, author = 'SOC Analyst'): Promise<NoteResponse> {
    return NoteResponseSchema.parse(
      await this.request(`/incidents/${id}/notes`, {
        method: 'POST',
        body: JSON.stringify({ note, author }),
      })
    )
  }

  async modelReport(): Promise<any> {
    return this.request('/model-report')
  }

  async getApprovals(): Promise<AgentApproval[]> {
    const json = await this.request('/approvals')
    return z.array(AgentApprovalSchema).parse(json)
  }

  async syncApprovals(): Promise<{ created: number }> {
    return this.request('/approvals/sync', { method: 'POST' })
  }

  async decideApproval(id: string, decision: 'approved' | 'denied', comment: string, analyst: string): Promise<AgentApproval> {
    const json = await this.request(`/approvals/${id}/decide`, {
      method: 'POST',
      body: JSON.stringify({ decision, comment, analyst }),
    })
    return AgentApprovalSchema.parse(json)
  }

  async getDriftClusters(): Promise<DriftCluster[]> {
    const json = await this.request('/drift-clusters')
    return z.array(DriftClusterSchema).parse(json)
  }
}

const mockInstance = new MockAdapter()
const realInstance = new RealAdapter()

async function withFallback<T>(realFn: () => Promise<T>, mockFn: () => Promise<T>): Promise<T> {
  if (IS_MOCK_ENV) return mockFn()
  try {
    return await realFn()
  } catch {
    return mockFn()
  }
}

export const api = {
  isMock: IS_MOCK_ENV,

  health: () => withFallback(() => realInstance.health(), () => mockInstance.health()),
  stats: () => withFallback(() => realInstance.stats(), () => mockInstance.stats()),
  statsTimeline: (hours = 24, bucket = '1h') =>
    withFallback(() => realInstance.statsTimeline(hours, bucket), () => mockInstance.statsTimeline(hours, bucket)),
  alerts: (params: Record<string, any> = {}) =>
    withFallback(() => realInstance.alerts(params), () => mockInstance.alerts(params)),
  detect: (body: any) =>
    withFallback(() => realInstance.detect(body), () => mockInstance.detect(body)),
  detectBatch: (flows: any[], aggregateIncidents = false) =>
    withFallback(() => realInstance.detectBatch(flows, aggregateIncidents), () => mockInstance.detectBatch(flows)),
  uploadFlowsFile: (file: File, aggregateIncidents = false) =>
    withFallback(() => realInstance.uploadFlowsFile(file, aggregateIncidents), () => mockInstance.uploadFlowsFile(file)),
  acknowledge: (id: number, analyst?: string) =>
    withFallback(() => realInstance.acknowledge(id, analyst), () => mockInstance.acknowledge(id)),
  bulkAcknowledge: (ids: number[], analyst?: string) =>
    withFallback(() => realInstance.bulkAcknowledge(ids, analyst), () => mockInstance.bulkAcknowledge(ids)),
  getAlertNotes: (id: number) =>
    withFallback(() => realInstance.getAlertNotes(id), () => mockInstance.getAlertNotes(id)),
  addAlertNote: (id: number, note: string, author?: string) =>
    withFallback(() => realInstance.addAlertNote(id, note, author), () => mockInstance.addAlertNote(id, note, author)),
  incidents: (params: Record<string, any> = {}) =>
    withFallback(() => realInstance.incidents(params), () => mockInstance.incidents()),
  incidentDetail: (id: number) =>
    withFallback(() => realInstance.incidentDetail(id), () => mockInstance.incidentDetail(id)),
  aggregateIncidents: (windowMinutes = 60, includeAcknowledged = false) =>
    withFallback(
      () => realInstance.aggregateIncidents(windowMinutes, includeAcknowledged),
      () => mockInstance.aggregateIncidents()
    ),
  updateIncident: (id: number, patch: any) =>
    withFallback(() => realInstance.updateIncident(id, patch), () => mockInstance.updateIncident(id, patch)),
  addIncidentNote: (id: number, note: string, author?: string) =>
    withFallback(() => realInstance.addIncidentNote(id, note, author), () => mockInstance.addIncidentNote(id, note, author)),
  modelReport: () =>
    withFallback(() => realInstance.modelReport(), () => mockInstance.modelReport()),
  getApprovals: () =>
    withFallback(() => realInstance.getApprovals(), () => mockInstance.getApprovals()),
  syncApprovals: () =>
    withFallback(() => realInstance.syncApprovals(), () => mockInstance.syncApprovals()),
  decideApproval: (id: string, decision: 'approved' | 'denied', comment: string, analyst: string) =>
    withFallback(
      () => realInstance.decideApproval(id, decision, comment, analyst),
      () => mockInstance.decideApproval(id, decision, comment, analyst)
    ),
  getDriftClusters: () =>
    withFallback(() => realInstance.getDriftClusters(), () => mockInstance.getDriftClusters()),
}
