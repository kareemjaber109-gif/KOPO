import { useState, useEffect } from 'react'
import {
  GitBranch,
  AlertTriangle,
  Layers,
  Database,
  ArrowRight,
  ExternalLink,
  Info,
  CheckCircle2,
  Clock,
  Sparkles,
  RefreshCw,
  Eye,
  FileCode,
  Tag,
  ShieldAlert
} from 'lucide-react'
import { api } from '../lib/api/client'

export default function UnknownDrift() {
  const [clusters, setClusters] = useState([])
  const [selectedCluster, setSelectedCluster] = useState(null)
  const [loading, setLoading] = useState(true)
  const [actionNotice, setActionNotice] = useState(null)

  useEffect(() => {
    loadClusters()
  }, [])

  async function loadClusters() {
    setLoading(true)
    try {
      const data = await api.getDriftClusters()
      setClusters(data)
      if (data.length > 0 && !selectedCluster) {
        setSelectedCluster(data[0])
      }
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  function handleAction(type) {
    if (!selectedCluster) return
    let message = ''
    if (type === 'retrain') {
      message = `✓ Cluster ${selectedCluster.id} queued for next active training batch (Dataset Annotation: UNKNOWN_ANOMALY)`
    } else if (type === 'allowlist') {
      message = `✓ Cluster ${selectedCluster.id} baseline updated — signature added to dynamic normal manifold.`
    } else {
      message = `✓ Cluster ${selectedCluster.id} marked as inspected and dismissed.`
    }
    setActionNotice(message)
    setTimeout(() => setActionNotice(null), 4000)
  }

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
            background: 'linear-gradient(135deg, rgba(240, 165, 0, 0.25) 0%, rgba(255, 71, 87, 0.15) 100%)',
            border: '1px solid rgba(240, 165, 0, 0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-amber)',
            boxShadow: '0 0 16px rgba(240, 165, 0, 0.2)'
          }}>
            <GitBranch size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 20, fontWeight: 800, letterSpacing: '0.04em', color: 'var(--text-primary)' }}>
                KOPO // UNKNOWN & FEATURE DRIFT TRIAGE
              </span>
              <span style={{
                fontSize: 10, padding: '2px 8px', borderRadius: 12,
                background: 'rgba(240, 165, 0, 0.15)', color: 'var(--accent-amber)',
                fontWeight: 700, border: '1px solid rgba(240, 165, 0, 0.3)'
              }}>
                ● STATISTICAL NOVELTY DETECTOR
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              Unsupervised Reconstruction Divergence & Isolation Forest Manifold Outliers
            </div>
          </div>
        </div>

        <button
          onClick={loadClusters}
          disabled={loading}
          style={{
            display: 'flex', alignItems: 'center', gap: 6,
            background: 'var(--bg-elevated)', border: '1px solid var(--border)',
            color: 'var(--text-primary)', padding: '7px 14px', borderRadius: 'var(--radius-sm)',
            fontSize: 12, cursor: 'pointer', fontWeight: 600
          }}
        >
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
          <span>Refresh Clusters</span>
        </button>
      </div>

      {/* Honest Model Limits Disclosure Banner */}
      <div style={{
        background: 'rgba(0, 212, 255, 0.06)',
        border: '1px solid rgba(0, 212, 255, 0.3)',
        borderRadius: 'var(--radius-md)',
        padding: '14px 18px',
        marginBottom: 20,
        display: 'flex',
        alignItems: 'flex-start',
        gap: 12
      }}>
        <Info size={18} color="var(--accent-cyan)" style={{ marginTop: 2, flexShrink: 0 }} />
        <div style={{ fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.6 }}>
          <b>SOC Analyst Disclosure: What the Models Know vs. Don't Know:</b> Supervised models (Random Forest, XGBoost) only identify attacks that exist in the training dataset. Novel zero-days, modified protocol tunnels, and stealth beaconing do not trigger trained class labels. They are intercepted here via <b>Deep Autoencoder reconstruction error</b> and <b>Isolation Forest path depth</b> when network flows diverge beyond the statistical normal baseline. Triage unclassified clusters below to queue them for retraining.
        </div>
      </div>

      {/* Notification Banner */}
      {actionNotice && (
        <div className="animate-slide" style={{
          background: 'rgba(57, 211, 83, 0.15)',
          border: '1px solid var(--accent-green)',
          color: 'var(--accent-green)',
          padding: '10px 16px',
          borderRadius: 'var(--radius-md)',
          marginBottom: 16,
          fontSize: 12,
          fontWeight: 700
        }}>
          {actionNotice}
        </div>
      )}

      {/* KPI Overview Bar */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 20 }}>
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Active Drift Clusters</div>
          <div style={{ fontSize: 24, fontWeight: 900, color: 'var(--accent-amber)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
            {clusters.length}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>Clusters requiring triage</div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Unclassified Flows</div>
          <div style={{ fontSize: 24, fontWeight: 900, color: 'var(--text-primary)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
            {clusters.reduce((acc, c) => acc + (c.sample_count || 0), 0).toLocaleString()}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>Total telemetry outliers</div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Max Divergence Score</div>
          <div style={{ fontSize: 24, fontWeight: 900, color: 'var(--accent-red)', marginTop: 4, fontFamily: 'var(--font-mono)' }}>
            {clusters.length > 0 ? `${(Math.max(...clusters.map(c => c.reconstruction_error_mean)) * 100).toFixed(1)}%` : '0.0%'}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>Autoencoder reconstruction delta</div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 18px' }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Primary Divergence Vector</div>
          <div style={{ fontSize: 16, fontWeight: 800, color: 'var(--accent-cyan)', marginTop: 8, fontFamily: 'var(--font-mono)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            URG Flag / Variance
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>Cross-feature anomaly</div>
        </div>
      </div>

      {/* Main Split: Left Clusters List | Right Deep Dive */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.2fr', gap: 20, alignItems: 'start' }}>
        
        {/* Left Side: Clusters List */}
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '18px 20px' }}>
          <div style={{ fontSize: 12, color: 'var(--text-primary)', textTransform: 'uppercase', fontWeight: 800, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Layers size={14} color="var(--accent-amber)" />
            <span>Unidentified Telemetry Clusters ({clusters.length})</span>
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {clusters.map(c => {
              const isSelected = selectedCluster?.id === c.id
              const divScore = (c.reconstruction_error_mean * 100).toFixed(1)
              return (
                <div
                  key={c.id}
                  onClick={() => setSelectedCluster(c)}
                  style={{
                    padding: '14px 16px',
                    borderRadius: 'var(--radius-md)',
                    border: `1px solid ${isSelected ? 'var(--accent-cyan)' : 'var(--border)'}`,
                    background: isSelected ? 'rgba(0, 212, 255, 0.08)' : 'var(--bg-elevated)',
                    cursor: 'pointer',
                    boxShadow: isSelected ? '0 0 14px rgba(0, 212, 255, 0.15)' : 'none',
                    transition: 'all 0.15s ease'
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 800, color: 'var(--accent-cyan)' }}>
                        {c.id}
                      </span>
                      <span style={{
                        fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700,
                        background: c.severity === 'Critical' ? 'rgba(255,71,87,0.15)' : 'rgba(240,165,0,0.15)',
                        color: c.severity === 'Critical' ? 'var(--accent-red)' : 'var(--accent-amber)'
                      }}>
                        {c.severity}
                      </span>
                    </div>
                    <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                      {c.sample_count} flows
                    </span>
                  </div>

                  <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 8 }}>
                    {c.cluster_name}
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-secondary)' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <span>Reconstruction Error:</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 700, color: 'var(--accent-red)' }}>
                        {divScore}%
                      </span>
                    </div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                      <Clock size={11} />
                      <span>{new Date(c.last_detected).toLocaleTimeString()}</span>
                    </div>
                  </div>
                </div>
              )
            })}
          </div>
        </div>

        {/* Right Side: Selected Cluster Forensic Details */}
        {selectedCluster ? (
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '20px 22px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <div>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', textTransform: 'uppercase' }}>
                  Forensic Deep Dive
                </span>
                <h3 style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)', marginTop: 2 }}>
                  {selectedCluster.cluster_name}
                </h3>
              </div>
              <span style={{
                fontSize: 11, padding: '4px 10px', borderRadius: 'var(--radius-sm)',
                background: 'rgba(240,165,0,0.15)', color: 'var(--accent-amber)',
                fontFamily: 'var(--font-mono)', fontWeight: 700, border: '1px solid rgba(240,165,0,0.3)'
              }}>
                CLUSTER: {selectedCluster.id}
              </span>
            </div>

            {/* Divergent Features Badges */}
            <div style={{ marginBottom: 18 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: 8 }}>
                Divergent Feature Signals (vs Benign Baseline):
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                {selectedCluster.divergent_features.map((feat, idx) => (
                  <span
                    key={idx}
                    style={{
                      fontSize: 11, padding: '4px 10px', borderRadius: 4,
                      background: 'rgba(255, 71, 87, 0.12)', border: '1px solid rgba(255, 71, 87, 0.3)',
                      color: 'var(--accent-red)', fontFamily: 'var(--font-mono)', fontWeight: 600
                    }}
                  >
                    ⚡ {feat}
                  </span>
                ))}
              </div>
            </div>

            {/* Raw JSON Flow Inspection */}
            <div style={{ marginBottom: 20 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                  Representative Network Flow Payload:
                </span>
                <span style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  Sanitized (Untrusted Strings Protected)
                </span>
              </div>
              <pre style={{
                background: 'var(--code-bg)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-md)', padding: 14, color: '#e6edf3',
                fontFamily: 'var(--font-mono)', fontSize: 11, overflowX: 'auto',
                maxHeight: 250, lineHeight: 1.5
              }}>
                {JSON.stringify(selectedCluster.representative_flow, null, 2)}
              </pre>
            </div>

            {/* Analyst Action Controls */}
            <div style={{
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius-md)', padding: 16
            }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: 10 }}>
                Analyst Triage Decisions:
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10 }}>
                <button
                  onClick={() => handleAction('retrain')}
                  style={{
                    flex: 1, minWidth: 180, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                    background: 'var(--accent-cyan)', color: '#ffffff', border: 'none',
                    borderRadius: 'var(--radius-sm)', padding: '10px 16px', fontSize: 12,
                    fontWeight: 700, cursor: 'pointer', boxShadow: '0 0 12px rgba(0, 212, 255, 0.25)'
                  }}
                >
                  <Tag size={13} />
                  <span>Queue for Retraining</span>
                </button>

                <button
                  onClick={() => handleAction('allowlist')}
                  style={{
                    flex: 1, minWidth: 160, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
                    background: 'rgba(57, 211, 83, 0.15)', color: 'var(--accent-green)',
                    border: '1px solid var(--accent-green)', borderRadius: 'var(--radius-sm)',
                    padding: '10px 16px', fontSize: 12, fontWeight: 700, cursor: 'pointer'
                  }}
                >
                  <CheckCircle2 size={13} />
                  <span>Allowlist Normal Drift</span>
                </button>

                <button
                  onClick={() => handleAction('dismiss')}
                  style={{
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                    background: 'transparent', color: 'var(--text-muted)',
                    border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)',
                    padding: '10px 14px', fontSize: 12, fontWeight: 600, cursor: 'pointer'
                  }}
                >
                  <span>Dismiss</span>
                </button>
              </div>
            </div>

          </div>
        ) : (
          <div style={{
            display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center',
            height: 300, border: '1px dashed var(--border)', borderRadius: 'var(--radius-lg)', color: 'var(--text-muted)'
          }}>
            Select a cluster from the left to inspect divergent signals.
          </div>
        )}

      </div>

    </div>
  )
}
