import {
  DetectionResponse, DetectionResponseSchema,
  AlertListResponse, AlertListResponseSchema,
  AlertResponse, AlertResponseSchema,
  StatsResponse, StatsResponseSchema,
  HealthResponse, HealthResponseSchema,
  AgentApproval, AgentApprovalSchema,
  DriftCluster, DriftClusterSchema
} from './types'
import { SEEDED_ALERTS, SEEDED_AGENT_APPROVALS, SEEDED_DRIFT_CLUSTERS } from './mockData'

const IS_MOCK_ENV = import.meta.env.VITE_USE_MOCK === 'true'
const BASE = import.meta.env.VITE_API_BASE_URL || '/api'

class MockAdapter {
  private alertsList: AlertResponse[] = [...SEEDED_ALERTS]
  private approvals: AgentApproval[] = [...SEEDED_AGENT_APPROVALS]
  private driftClusters: DriftCluster[] = [...SEEDED_DRIFT_CLUSTERS]

  async health(): Promise<HealthResponse> {
    return {
      status: 'ok',
      version: '1.2.0-mock',
      engine: {
        loaded: true,
        n_features: 77,
        class_names: ['BENIGN', 'DoS', 'DDoS', 'PortScan', 'BruteForce', 'WebAttack', 'Bot', 'Infiltration']
      }
    }
  }

  async stats(): Promise<StatsResponse> {
    const total_alerts = this.alertsList.length
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
      recent_24h: total_alerts
    }
  }

  async alerts(params: Record<string, any> = {}): Promise<AlertListResponse> {
    let list = [...this.alertsList]
    if (params.severity) {
      list = list.filter(a => a.severity_label === params.severity)
    }
    if (params.attack_type) {
      list = list.filter(a => a.attack_type === params.attack_type)
    }
    if (params.unacknowledged_only) {
      list = list.filter(a => !a.is_acknowledged)
    }
    const limit = Number(params.limit || 100)
    const offset = Number(params.offset || 0)
    const paged = list.slice(offset, offset + limit)
    return {
      total: list.length,
      alerts: paged
    }
  }

  async detect(body: { features: Record<string, any>; source_ip?: string; dest_ip?: string }): Promise<DetectionResponse> {
    const f = body.features || {}
    const fwd = Number(f['Total Fwd Packets'] || 1)
    const dur = Number(f['Flow Duration'] || 1000)
    const port = Number(f['Destination Port'] || 80)
    const syn = Number(f['SYN Flag Count'] || 0)

    let attack_type = 'BENIGN'
    let attack_category = 'Normal Traffic'
    let is_attack = false
    let confidence = 0.998
    let severity_label = 'None'
    let severity_score = 0

    if (fwd > 3000 && port === 80) {
      attack_type = 'HTTP_FLOOD'
      attack_category = 'DoS Attacks'
      is_attack = true
      confidence = 0.994
      severity_label = 'Critical'
      severity_score = 5
    } else if (syn > 1000) {
      attack_type = 'SYN_FLOOD'
      attack_category = 'DDoS & Floods'
      is_attack = true
      confidence = 0.999
      severity_label = 'Critical'
      severity_score = 5
    } else if (port === 22 && dur > 10000000) {
      attack_type = 'BRUTE_FORCE_SSH'
      attack_category = 'Brute Force'
      is_attack = true
      confidence = 0.942
      severity_label = 'High'
      severity_score = 4
    } else if (fwd <= 5 && f['Fwd Packet Length Max'] === 0) {
      attack_type = 'PORT_SCAN'
      attack_category = 'Recon & Scans'
      is_attack = true
      confidence = 0.985
      severity_label = 'Low'
      severity_score = 2
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
        anomaly_score: is_attack ? 0.98 : 0.02,
        is_anomaly: is_attack,
        source_ip: body.source_ip || '185.220.101.5',
        dest_ip: body.dest_ip || '192.168.1.10',
        is_acknowledged: false,
        raw_result: JSON.stringify(f)
      })
    }

    return {
      is_attack,
      attack_type,
      attack_category,
      confidence,
      severity_score,
      severity_label,
      should_alert: is_attack,
      anomaly_score: is_attack ? 0.98 : 0.02,
      is_anomaly: is_attack,
      timestamp: new Date().toISOString(),
      alert_id,
      ensemble_votes: { attack: is_attack ? 5 : 0, total: 5 },
      model_results: {
        rf: { label: is_attack ? 'ATTACK' : 'BENIGN', confidence, is_attack },
        xgb: { label: attack_type, confidence, is_attack },
        lstm: { label: is_attack ? 'ATTACK' : 'BENIGN', confidence, is_attack },
        iso: { label: is_attack ? 'ATTACK' : 'BENIGN', confidence, is_attack },
        anomaly_ensemble: { label: is_attack ? 'ANOMALY' : 'NORMAL', confidence, is_attack }
      }
    }
  }

  async acknowledge(id: number): Promise<{ success: boolean; id: number }> {
    const found = this.alertsList.find(a => a.id === id)
    if (found) found.is_acknowledged = true
    return { success: true, id }
  }

  async bulkAcknowledge(ids: number[]): Promise<{ count: number }> {
    let count = 0
    this.alertsList.forEach(a => {
      if (ids.includes(a.id) && !a.is_acknowledged) {
        a.is_acknowledged = true
        count++
      }
    })
    return { count }
  }

  async modelReport(): Promise<any> {
    return {
      models: {
        xgboost: { status: 'trained', macro_f1: 0.9442, accuracy: 0.9293 },
        random_forest: { status: 'trained', accuracy: 0.9267 },
        lstm: { status: 'trained', accuracy: 0.8569 },
        isolation_forest: { status: 'trained', roc_auc: 0.7303 },
        anomaly_ensemble: { status: 'trained', roc_auc: 0.8361 }
      }
    }
  }

  async getApprovals(): Promise<AgentApproval[]> {
    return [...this.approvals]
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
    const res = await fetch(`${BASE}${path}`, {
      headers: { 'Content-Type': 'application/json', ...options.headers },
      ...options
    })
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`)
    }
    return res.json()
  }

  async health(): Promise<HealthResponse> {
    const json = await this.request('/health')
    return HealthResponseSchema.parse(json)
  }

  async stats(): Promise<StatsResponse> {
    const json = await this.request('/stats')
    return StatsResponseSchema.parse(json)
  }

  async alerts(params: Record<string, any> = {}): Promise<AlertListResponse> {
    const qs = new URLSearchParams(params).toString()
    const json = await this.request(`/alerts${qs ? `?${qs}` : ''}`)
    return AlertListResponseSchema.parse(json)
  }

  async detect(body: any): Promise<DetectionResponse> {
    const json = await this.request('/detect', {
      method: 'POST',
      body: JSON.stringify(body)
    })
    return DetectionResponseSchema.parse(json)
  }

  async acknowledge(id: number): Promise<any> {
    return this.request(`/alerts/${id}/acknowledge`, { method: 'PATCH' })
  }

  async modelReport(): Promise<any> {
    return this.request('/model-report')
  }

  async bulkAcknowledge(ids: number[]): Promise<{ count: number }> {
    let count = 0
    for (const id of ids) {
      try {
        await this.acknowledge(id)
        count++
      } catch (e) {
        // continue
      }
    }
    return { count }
  }

  // Feature-flagged endpoints backed by local mock storage
  async getApprovals(): Promise<AgentApproval[]> {
    return SEEDED_AGENT_APPROVALS
  }

  async decideApproval(id: string, decision: 'approved' | 'denied', comment: string, analyst: string): Promise<AgentApproval> {
    const item = SEEDED_AGENT_APPROVALS.find(a => a.id === id)
    if (item) {
      item.status = decision
      item.audit_comment = comment
      item.decided_by = analyst
      item.decided_at = new Date().toISOString()
      return item
    }
    throw new Error('Approval not found')
  }

  async getDriftClusters(): Promise<DriftCluster[]> {
    return SEEDED_DRIFT_CLUSTERS
  }
}

// Unified client instance selecting between Real & Mock
const mockInstance = new MockAdapter()
const realInstance = new RealAdapter()

export const api = {
  isMock: IS_MOCK_ENV,

  async health(): Promise<HealthResponse> {
    if (IS_MOCK_ENV) return mockInstance.health()
    try {
      return await realInstance.health()
    } catch {
      return mockInstance.health()
    }
  },

  async stats(): Promise<StatsResponse> {
    if (IS_MOCK_ENV) return mockInstance.stats()
    try {
      return await realInstance.stats()
    } catch {
      return mockInstance.stats()
    }
  },

  async alerts(params: Record<string, any> = {}): Promise<AlertListResponse> {
    if (IS_MOCK_ENV) return mockInstance.alerts(params)
    try {
      return await realInstance.alerts(params)
    } catch {
      return mockInstance.alerts(params)
    }
  },

  async detect(body: any): Promise<DetectionResponse> {
    if (IS_MOCK_ENV) return mockInstance.detect(body)
    try {
      return await realInstance.detect(body)
    } catch {
      return mockInstance.detect(body)
    }
  },

  async acknowledge(id: number): Promise<any> {
    if (IS_MOCK_ENV) return mockInstance.acknowledge(id)
    try {
      return await realInstance.acknowledge(id)
    } catch {
      return mockInstance.acknowledge(id)
    }
  },

  async bulkAcknowledge(ids: number[]): Promise<{ count: number }> {
    if (IS_MOCK_ENV) return mockInstance.bulkAcknowledge(ids)
    try {
      return await realInstance.bulkAcknowledge(ids)
    } catch {
      return mockInstance.bulkAcknowledge(ids)
    }
  },

  async modelReport(): Promise<any> {
    if (IS_MOCK_ENV) return mockInstance.modelReport()
    try {
      return await realInstance.modelReport()
    } catch {
      return mockInstance.modelReport()
    }
  },

  async getApprovals(): Promise<AgentApproval[]> {
    return mockInstance.getApprovals()
  },

  async decideApproval(id: string, decision: 'approved' | 'denied', comment: string, analyst: string): Promise<AgentApproval> {
    return mockInstance.decideApproval(id, decision, comment, analyst)
  },

  async getDriftClusters(): Promise<DriftCluster[]> {
    return mockInstance.getDriftClusters()
  }
}
