import { useState, useEffect, useCallback } from 'react'
import {
  Server,
  Activity,
  Cpu,
  Shield,
  Layers,
  Database,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
  Search,
  ExternalLink,
  Code,
  Gauge,
  Sliders,
  Terminal,
  Zap
} from 'lucide-react'
import { api } from '../lib/api/client'

const KNOWN_77_FEATURES = [
  'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets',
  'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max',
  'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std',
  'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean',
  'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean',
  'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean',
  'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean',
  'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags',
  'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length',
  'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length',
  'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count',
  'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count',
  'URG Flag Count', 'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio',
  'Average Packet Size', 'Avg Fwd Segment Size', 'Avg Bwd Segment Size',
  'Fwd Header Length.1', 'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk',
  'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate',
  'Subflow Fwd Packets', 'Subflow Fwd Bytes', 'Subflow Bwd Packets', 'Subflow Bwd Bytes',
  'Init_Win_bytes_forward', 'Init_Win_bytes_backward', 'act_data_pkt_fwd',
  'min_seg_size_forward', 'Active Mean', 'Active Std', 'Active Max', 'Active Min',
  'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

export default function System() {
  const [healthData, setHealthData] = useState(null)
  const [latencyMs, setLatencyMs] = useState(null)
  const [loading, setLoading] = useState(true)
  const [featureSearch, setFeatureSearch] = useState('')
  const [lastCheckTime, setLastCheckTime] = useState(null)

  const checkSystem = useCallback(async () => {
    setLoading(true)
    const start = performance.now()
    try {
      const data = await api.health()
      const end = performance.now()
      setHealthData(data)
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

  const filteredFeatures = KNOWN_77_FEATURES.filter(f =>
    f.toLowerCase().includes(featureSearch.toLowerCase())
  )

  const isMock = api.isMock

  return (
    <div style={{ padding: '24px 32px', maxWidth: 1600, margin: '0 auto' }}>
      
      {/* Top Header */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: 'var(--header-gradient)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)',
        padding: '18px 24px',
        marginBottom: 20,
        boxShadow: 'var(--card-shadow)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 'var(--radius-md)',
            background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.25) 0%, rgba(189, 147, 249, 0.15) 100%)',
            border: '1px solid rgba(0, 212, 255, 0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-cyan)',
            boxShadow: '0 0 16px rgba(0, 212, 255, 0.2)'
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
              FastAPI Inference Engine Telemetry, Real-time Latency & Feature Registry
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

      {/* KPI System Strip */}
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
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Backend Data Mode</div>
          <div style={{ fontSize: 20, fontWeight: 900, color: isMock ? 'var(--accent-amber)' : 'var(--accent-green)', marginTop: 6, fontFamily: 'var(--font-mono)' }}>
            {isMock ? 'MOCK ADAPTER' : 'LIVE FASTAPI'}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
            {isMock ? 'VITE_USE_MOCK active' : 'Connected to :8000'}
          </div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Min Alert Confidence</div>
          <div style={{ fontSize: 24, fontWeight: 900, color: 'var(--threshold-alert)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
            75.0%
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>Threshold for SOC triage alert</div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>High Severity Threshold</div>
          <div style={{ fontSize: 24, fontWeight: 900, color: 'var(--threshold-high)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
            92.0%
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>Triggers Critical escalation</div>
        </div>

      </div>

      {/* Main Grid: Architecture Status on Left | Feature Inspector on Right */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 20, alignItems: 'start' }}>
        
        {/* Left Column: Ensemble Model Diagnostics & API Endpoints */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
          
          {/* Loaded Models */}
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '18px 20px' }}>
            <div style={{ fontSize: 12, color: 'var(--text-primary)', textTransform: 'uppercase', fontWeight: 800, marginBottom: 14, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Cpu size={14} color="var(--accent-cyan)" />
              <span>Loaded Machine Learning Pipelines</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {[
                { name: 'RobustScaler Preprocessor', detail: '77-feature normalization pipeline with median & IQR', loaded: true },
                { name: 'Random Forest (Binary Gate)', detail: '150 estimator ensemble for benign vs threat distinction', loaded: true },
                { name: 'XGBoost (34-Class Multi-Classifier)', detail: 'Multi-class tree boosting for granular cyber attack classification', loaded: true },
                { name: 'PyTorch LSTM Sequential', detail: 'Bidirectional temporal recurrence network for sequence anomalies', loaded: true },
                { name: 'Isolation Forest (Depth Anomaly)', detail: 'Unsupervised tree isolation scoring statistical rarity', loaded: true },
                { name: 'Dual Autoencoder + IF Anomaly Ensemble', detail: 'Deep autoencoder reconstruction error paired with isolation forest', loaded: true },
              ].map((m, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '12px 14px', borderRadius: 'var(--radius-sm)',
                    background: 'var(--bg-elevated)', border: '1px solid var(--border)'
                  }}
                >
                  <div>
                    <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)' }}>
                      {m.name}
                    </div>
                    <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
                      {m.detail}
                    </div>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, color: 'var(--accent-green)', fontSize: 11, fontWeight: 700 }}>
                    <CheckCircle2 size={13} />
                    <span>Active</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* API Endpoints Catalog */}
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '18px 20px' }}>
            <div style={{ fontSize: 12, color: 'var(--text-primary)', textTransform: 'uppercase', fontWeight: 800, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Terminal size={14} color="var(--accent-cyan)" />
              <span>FastAPI Endpoints Catalog</span>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {[
                { method: 'POST', path: '/api/detect', desc: 'Classifies network flow JSON vector, logs analysis, saves alert' },
                { method: 'GET', path: '/api/alerts', desc: 'Lists alerts with filters for severity, type, and status' },
                { method: 'PATCH', path: '/api/alerts/{id}/acknowledge', desc: 'Acknowledges active alert by ID' },
                { method: 'GET', path: '/api/stats', desc: '24h alert counts, severity breakdowns, and attack ratios' },
                { method: 'GET', path: '/api/health', desc: 'Engine readiness, model status, and feature schema' },
                { method: 'GET', path: '/api/model-report', desc: 'Model evaluation metrics (F1, Accuracy, ROC-AUC)' },
              ].map((ep, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                    padding: '10px 12px', borderRadius: 'var(--radius-sm)',
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
                  <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>
                    {ep.desc}
                  </span>
                </div>
              ))}
            </div>
          </div>

        </div>

        {/* Right Column: 77 Features Registry */}
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '18px 20px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div style={{ fontSize: 12, color: 'var(--text-primary)', textTransform: 'uppercase', fontWeight: 800, display: 'flex', alignItems: 'center', gap: 8 }}>
              <Layers size={14} color="var(--accent-cyan)" />
              <span>Feature Registry (77 Dimensions)</span>
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

          <div style={{ maxHeight: 600, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 4, paddingRight: 4 }}>
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
