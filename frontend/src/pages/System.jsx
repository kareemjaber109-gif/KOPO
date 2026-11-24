import { useState, useEffect, useCallback } from 'react'
import {
  Server,
  Cpu,
  Layers,
  CheckCircle2,
  RefreshCw,
  Search,
  Terminal,
  AlertTriangle
} from 'lucide-react'
import { api } from '../lib/api/client'

const CANONICAL_69_FEATURES = [
  'Protocol', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
  'Fwd Packets Length Total', 'Bwd Packets Length Total', 'Fwd Packet Length Max',
  'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
  'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
  'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
  'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
  'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
  'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Fwd URG Flags',
  'Fwd Header Length', 'Bwd Header Length', 'Fwd Packets/s', 'Bwd Packets/s',
  'Packet Length Min', 'Packet Length Max', 'Packet Length Mean', 'Packet Length Std',
  'Packet Length Variance', 'FIN Flag Count', 'SYN Flag Count', 'RST Flag Count',
  'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 'CWE Flag Count',
  'ECE Flag Count', 'Down/Up Ratio', 'Avg Packet Size', 'Avg Fwd Segment Size',
  'Avg Bwd Segment Size', 'Subflow Fwd Packets', 'Subflow Fwd Bytes',
  'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init Fwd Win Bytes',
  'Init Bwd Win Bytes', 'Fwd Act Data Packets', 'Fwd Seg Size Min', 'Active Mean',
  'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max',
  'Idle Min'
]

const API_CATALOG = [
  { method: 'POST', path: '/api/detect', desc: 'Classify single flow, log analysis, persist alert' },
  { method: 'POST', path: '/api/detect/batch', desc: 'Batch inspect flow array with optional incident clustering' },
  { method: 'POST', path: '/api/flows/upload', desc: 'Upload CSV / JSON / JSONL flow capture for bulk scan' },
  { method: 'GET', path: '/api/alerts', desc: 'Query alerts with severity, type, incident & search filters' },
  { method: 'PATCH', path: '/api/alerts/bulk-acknowledge', desc: 'Acknowledge multiple selected alerts in one transaction' },
  { method: 'POST', path: '/api/alerts/{id}/notes', desc: 'Persist SOC analyst case notes per alert in SQLite' },
  { method: 'POST', path: '/api/incidents/aggregate', desc: 'Group unlinked alerts into correlated SOC incidents' },
  { method: 'GET', path: '/api/incidents', desc: 'List correlated incidents with status and search filters' },
  { method: 'PATCH', path: '/api/incidents/{id}', desc: 'Update incident workflow status, assignee & alerts' },
  { method: 'GET', path: '/api/stats/timeline', desc: 'Bucketed traffic & alert timeline metrics for dashboards' },
  { method: 'GET', path: '/api/approvals', desc: 'Human-in-the-loop containment actions backed by SQLite' },
  { method: 'GET', path: '/api/drift-clusters', desc: 'Unsupervised behavioral anomaly clusters from DB alerts' },
  { method: 'GET', path: '/api/model-report', desc: 'Live manifest metrics for 2017 benchmark & 2018 transfer' },
]

export default function System() {
  const [healthData, setHealthData] = useState(null)
  const [reportData, setReportData] = useState(null)
  const [latencyMs, setLatencyMs] = useState(null)
  const [loading, setLoading] = useState(true)
  const [featureSearch, setFeatureSearch] = useState('')
  const [lastCheckTime, setLastCheckTime] = useState(null)

  const checkSystem = useCallback(async () => {
    setLoading(true)
    const start = performance.now()
    try {
      const [h, rep] = await Promise.all([api.health(), api.modelReport()])
      const end = performance.now()
      setHealthData(h)
      setReportData(rep)
      setLatencyMs(Math.round(end - start))
      setLastCheckTime(new Date())
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    checkSystem()
    const timer = setInterval(checkSystem, 15000)
    return () => clearInterval(timer)
  }, [checkSystem])

  const featureSchema = CANONICAL_69_FEATURES
  const nFeatures = healthData?.engine?.n_features ?? reportData?.n_features ?? featureSchema.length
  const filteredFeatures = featureSchema.filter(f =>
    f.toLowerCase().includes(featureSearch.toLowerCase())
  )

  const loadedFlags = healthData?.engine?.models ?? {}
  const lstmExcluded = reportData?.models?.lstm?.status === 'excluded_in_manifest'
  const pipelineItems = [
    { name: 'Active Model Run', detail: `${healthData?.run_id || 'run_clean_benchmark_v1'} (${healthData?.run_type || 'research_baseline'})`, active: Boolean(healthData?.is_ready), warn: !healthData?.certified },
    { name: 'Random Forest Classifier', detail: `${(reportData?.class_names || []).length || 8} classes · ${nFeatures} features`, active: Boolean(loadedFlags.random_forest) },
    { name: 'XGBoost Multi-Classifier', detail: 'Gradient-boosted tree classifier + probability scoring', active: Boolean(loadedFlags.xgboost) },
    { name: 'PyTorch LSTM', detail: lstmExcluded ? 'Excluded in manifest (legacy weight fallback)' : 'Temporal sequence classifier', active: Boolean(loadedFlags.lstm), warn: lstmExcluded },
    { name: 'Dual Autoencoder + IF Ensemble', detail: `AnomalyPreprocessor (threshold=${reportData?.models?.anomaly_ensemble?.threshold?.toFixed?.(4) || '0.9872'})`, active: Boolean(loadedFlags.anomaly_ensemble) },
  ]

  const isMock = api.isMock

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1600, margin: '0 auto' }}>
      {/* Top Header */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center',
        background: 'var(--header-gradient)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
        padding: '18px 24px', marginBottom: 20, boxShadow: 'var(--card-shadow)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 'var(--radius-md)',
            background: 'rgba(0, 212, 255, 0.16)', border: '1px solid rgba(0, 212, 255, 0.35)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-cyan)'
          }}>
            <Server size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 20, fontWeight: 800, letterSpacing: '0.04em', color: 'var(--text-primary)' }}>
                KOPO // SYSTEM & ENGINE DIAGNOSTICS
              </span>
              <span style={{
                fontSize: 10, padding: '2px 8px', borderRadius: 12,
                background: healthData?.status === 'ok' ? 'rgba(57, 211, 83, 0.15)' : 'rgba(255, 71, 87, 0.15)',
                color: healthData?.status === 'ok' ? 'var(--accent-green)' : 'var(--accent-red)',
                fontWeight: 700, border: `1px solid ${healthData?.status === 'ok' ? 'rgba(57,211,83,0.3)' : 'rgba(255,71,87,0.3)'}`
              }}>
                ● {healthData?.status === 'ok' ? 'API OPERATIONAL' : 'SYSTEM DEGRADED'}
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              FastAPI Engine Telemetry · Run ID: <code>{healthData?.run_id || '—'}</code> · Origin: <code>{healthData?.model_origin || '—'}</code>
            </div>
          </div>
        </div>

        <button
          onClick={checkSystem}
          disabled={loading}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: 'var(--bg-elevated)', border: '1px solid var(--border)',
            color: 'var(--text-primary)', padding: '7px 14px', borderRadius: 'var(--radius-sm)',
            fontSize: 12, cursor: 'pointer', fontWeight: 600
          }}
        >
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          <span>Ping Engine</span>
        </button>
      </div>

      {/* KPI Strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 20 }}>
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>API Latency</div>
          <div style={{ fontSize: 24, fontWeight: 900, color: 'var(--accent-cyan)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
            {latencyMs != null ? `${latencyMs} ms` : '—'}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
            {lastCheckTime ? `Last ping: ${lastCheckTime.toLocaleTimeString()}` : 'Awaiting heartbeat'}
          </div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Backend Mode</div>
          <div style={{ fontSize: 20, fontWeight: 900, color: isMock ? 'var(--accent-amber)' : 'var(--accent-green)', marginTop: 6, fontFamily: 'var(--font-mono)' }}>
            {isMock ? 'MOCK ADAPTER' : 'LIVE FASTAPI'}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
            {healthData?.certified ? 'Certified Release' : 'Research Baseline (Uncertified)'}
          </div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Decision Threshold</div>
          <div style={{ fontSize: 24, fontWeight: 900, color: 'var(--threshold-alert)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
            {((reportData?.decision_threshold ?? 0.5) * 100).toFixed(0)}%
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>Manifest binary cut-off</div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Anomaly Threshold</div>
          <div style={{ fontSize: 24, fontWeight: 900, color: 'var(--threshold-high)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
            {reportData?.models?.anomaly_ensemble?.threshold?.toFixed?.(4) ?? '0.9872'}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>99th percentile benign baseline</div>
        </div>
      </div>

      {/* Main Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, alignItems: 'start' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '18px 20px' }}>
            <div style={{ fontSize: 12, color: 'var(--text-primary)', textTransform: 'uppercase', fontWeight: 800, marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Cpu size={14} color="var(--accent-cyan)" />
              <span>Loaded Machine Learning Pipelines</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {pipelineItems.map((m, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '12px 14px', borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg-elevated)', border: '1px solid var(--border)'
                  }}
                >
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>{m.name}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>{m.detail}</div>
                  </div>
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, fontWeight: 700,
                    color: m.warn ? 'var(--accent-amber)' : m.active ? 'var(--accent-green)' : 'var(--accent-red)'
                  }}>
                    {m.warn ? <AlertTriangle size={13} /> : <CheckCircle2 size={13} />}
                    <span>{m.active ? 'Loaded' : 'Inactive'}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '18px 20px' }}>
            <div style={{ fontSize: 12, color: 'var(--text-primary)', textTransform: 'uppercase', fontWeight: 800, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Terminal size={14} color="var(--accent-cyan)" />
              <span>Phase 2 FastAPI Endpoints Catalog</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {API_CATALOG.map((ep, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10,
                    padding: '9px 12px', borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg-elevated)', border: '1px solid var(--border)', fontSize: 11
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{
                      fontWeight: 800, fontFamily: 'var(--font-mono)', fontSize: 10, padding: '2px 6px', borderRadius: 4,
                      background: ep.method === 'POST' ? 'rgba(0,212,255,0.15)' : ep.method === 'PATCH' ? 'rgba(240,165,0,0.15)' : 'rgba(57,211,83,0.15)',
                      color: ep.method === 'POST' ? 'var(--accent-cyan)' : ep.method === 'PATCH' ? 'var(--accent-amber)' : 'var(--accent-green)'
                    }}>
                      {ep.method}
                    </span>
                    <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {ep.path}
                    </span>
                  </div>
                  <span style={{ color: 'var(--text-muted)', fontSize: 10, textAlign: 'right' }}>{ep.desc}</span>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Right Column: Canonical Feature Registry */}
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '18px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 12, color: 'var(--text-primary)', textTransform: 'uppercase', fontWeight: 800, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Layers size={14} color="var(--accent-cyan)" />
              <span>Canonical Feature Registry ({nFeatures} Dimensions)</span>
            </div>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
              {filteredFeatures.length} matching
            </span>
          </div>

          <div style={{ position: 'relative', marginBottom: 12 }}>
            <Search size={14} style={{ position: 'absolute', left: 10, top: 10, color: 'var(--text-muted)' }} />
            <input
              type="text"
              placeholder="Search feature names..."
              value={featureSearch}
              onChange={e => setFeatureSearch(e.target.value)}
              style={{
                width: '100%', padding: '8px 12px 8px 32px', background: 'var(--bg-elevated)',
                border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                color: 'var(--text-primary)', fontSize: 12, outline: 'none'
              }}
            />
          </div>

          <div style={{ maxHeight: 620, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4, paddingRight: 4 }}>
            {filteredFeatures.map((feat, idx) => (
              <div
                key={idx}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '7px 10px', borderRadius: 'var(--radius-sm)',
                  background: 'var(--bg-elevated)', border: '1px solid var(--border-subtle)',
                  fontSize: 11, fontFamily: 'var(--font-mono)'
                }}
              >
                <span style={{ color: 'var(--text-primary)' }}>{feat}</span>
                <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>float32</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
