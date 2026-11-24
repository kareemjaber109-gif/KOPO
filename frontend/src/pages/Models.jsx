import { useCallback } from 'react'
import { Cpu, GitFork, Database, AlertTriangle, ShieldCheck } from 'lucide-react'
import { usePolling } from '../hooks/usePolling.js'
import { api } from '../lib/api/client.ts'

const MODEL_METADATA = {
  random_forest: {
    title: 'Random Forest',
    arch: 'Ensemble Classifier (Clean Benchmark)',
    role: 'Supervised Multi-Class & Benign Discrimination',
    color: '#00d4ff',
  },
  xgboost: {
    title: 'XGBoost',
    arch: 'Gradient-Boosted Decision Trees + Isotonic Calibration',
    role: 'High-Precision Multi-Class Attack Identifier',
    color: '#39d353',
  },
  lstm: {
    title: 'LSTM Sequential Network',
    arch: 'PyTorch Sequence Classifier',
    role: 'Temporal Flow Classifier',
    color: '#bd93f9',
  },
  isolation_forest: {
    title: 'Isolation Forest',
    arch: 'Unsupervised Isolation Tree Depth',
    role: 'Unsupervised Subspace Outlier Detector',
    color: '#ffb86c',
  },
  anomaly_ensemble: {
    title: 'Dual Anomaly Ensemble',
    arch: 'PyTorch Autoencoder + Isolation Forest (AnomalyPreprocessor)',
    role: 'Zero-Day Behavioral Anomaly Interceptor',
    color: '#ff79c6',
  },
}

function MetricBar({ value, color }) {
  return (
    <div style={{ height: 5, background: 'var(--bg-base)', borderRadius: 3, marginTop: 5, overflow: 'hidden' }}>
      <div style={{ height: '100%', width: `${Math.min(100, (value ?? 0) * 100)}%`, background: color, borderRadius: 3, transition: 'width 0.5s ease' }} />
    </div>
  )
}

function fmtPct(val) {
  return val != null ? `${(val * 100).toFixed(2)}%` : 'N/A'
}

export default function Models() {
  const fetchReport = useCallback(() => api.modelReport(), [])
  const { data } = usePolling(fetchReport, 60000)

  const models = data?.models ?? {}
  const classes = data?.class_names ?? []
  const bench17 = data?.benchmark_2017 ?? {}
  const ext18 = data?.external_2018 ?? {}
  const anomBench = data?.anomaly_benchmark ?? {}
  const perClass17 = bench17?.per_class ?? {}
  const perClass18 = ext18?.per_class ?? {}

  const certified = Boolean(data?.certified)
  const activeRunId = data?.active_run_id || 'loading...'
  const auditStatus = data?.audit_status || 'LOADING...'

  return (
    <div style={{ padding: '28px 32px', maxWidth: 1600, margin: '0 auto' }}>

      {/* Header */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 12,
        background: 'var(--header-gradient)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
        padding: '18px 24px', marginBottom: 18, boxShadow: 'var(--card-shadow)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 'var(--radius-md)',
            background: 'rgba(189, 147, 249, 0.12)', border: '1px solid rgba(189, 147, 249, 0.3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-purple)'
          }}>
            <Cpu size={22} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 20, fontWeight: 800, letterSpacing: '0.03em', color: 'var(--text-primary)' }}>
                KOPO // AI MODEL TELEMETRY & BENCHMARKS
              </span>
              <span style={{
                fontSize: 10, padding: '2px 8px', borderRadius: 12, fontWeight: 700,
                background: certified ? 'rgba(57,211,83,0.15)' : 'rgba(240,165,0,0.15)',
                color: certified ? 'var(--accent-green)' : 'var(--accent-amber)',
                border: `1px solid ${certified ? 'rgba(57,211,83,0.3)' : 'rgba(240,165,0,0.35)'}`
              }}>
                {auditStatus}
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              Active Run: <code style={{ color: 'var(--accent-cyan)' }}>{activeRunId}</code> · {data?.training_dataset || 'CIC-IDS2017 Clean Benchmark'} ({data?.n_features ?? '—'} Features)
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
          <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
            <Database size={13} color="var(--accent-cyan)" /> Dual Pipeline Architecture
          </span>
        </div>
      </div>

      {/* Honest Certification & Domain Shift Notice */}
      {!certified && (
        <div style={{
          background: 'rgba(240, 165, 0, 0.08)', border: '1px solid rgba(240, 165, 0, 0.35)',
          borderRadius: 'var(--radius-md)', padding: '12px 16px', marginBottom: 20,
          display: 'flex', alignItems: 'flex-start', gap: 10, fontSize: 12, color: 'var(--text-primary)'
        }}>
          <AlertTriangle size={16} color="var(--accent-amber)" style={{ flexShrink: 0, marginTop: 2 }} />
          <div>
            <b>Research Baseline Disclosure:</b> All metrics shown below are pulled directly from{' '}
            <code>manifest.json</code> and cross-dataset evaluation reports. In-distribution CIC-IDS2017 test recall is{' '}
            <b>{fmtPct(bench17?.metrics?.recall_tpr)}</b> at <b>{fmtPct(bench17?.metrics?.benign_fpr)}</b> Benign FPR, while out-of-distribution CSE-CIC-IDS2018 transfer drops to{' '}
            <b>{fmtPct(ext18?.metrics?.attack_recall_tpr)}</b> due to dataset/extractor domain shift.
          </div>
        </div>
      )}

      {/* Model Cards Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: 16, marginBottom: 24 }}>
        {['random_forest', 'xgboost', 'lstm', 'isolation_forest', 'anomaly_ensemble'].map(name => {
          const m = models[name] ?? {}
          const meta = MODEL_METADATA[name]
          const color = meta.color
          const isAnomaly = name === 'anomaly_ensemble' || name === 'isolation_forest'
          const isExcluded = m.status === 'excluded_in_manifest'
          const badgeText = isExcluded ? 'EXCLUDED IN MANIFEST' : m.status === 'trained' ? 'ACTIVE' : 'OFFLINE'

          return (
            <div
              key={name}
              style={{
                background: 'var(--bg-surface)', border: '1px solid var(--border)',
                borderTop: `3px solid ${color}`, borderRadius: 'var(--radius-lg)',
                padding: '18px 20px', boxShadow: 'var(--card-shadow)',
                display: 'flex', flexDirection: 'column', justifyContent: 'space-between'
              }}
            >
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 6 }}>
                  <div style={{ fontSize: 17, fontWeight: 800, color }}>{meta.title}</div>
                  <span style={{
                    fontSize: 9, padding: '2px 6px', borderRadius: 3, fontWeight: 700, fontFamily: 'var(--font-mono)',
                    background: isExcluded ? 'rgba(240,165,0,0.15)' : `${color}18`,
                    color: isExcluded ? 'var(--accent-amber)' : color
                  }}>
                    {badgeText}
                  </span>
                </div>

                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 4 }}>{meta.role}</div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', marginBottom: 14 }}>{meta.arch}</div>

                {name === 'lstm' ? (
                  <div style={{ fontSize: 11, color: 'var(--text-secondary)', background: 'var(--bg-elevated)', padding: '10px 12px', borderRadius: 'var(--radius-sm)' }}>
                    {m.note || 'Excluded from run_clean_benchmark_v1 until sequence flow model is built.'}
                    {m.loaded_legacy_fallback && (
                      <div style={{ marginTop: 6, color: 'var(--accent-amber)', fontSize: 10 }}>
                        Note: legacy lstm.pt fallback loaded only for backward engine schema compatibility.
                      </div>
                    )}
                  </div>
                ) : isAnomaly ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                        <span style={{ color: 'var(--text-secondary)' }}>ROC-AUC (UNSW+CICIDS Test)</span>
                        <span style={{ color, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{fmtPct(m.roc_auc)}</span>
                      </div>
                      <MetricBar value={m.roc_auc} color={color} />
                    </div>

                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                        <span style={{ color: 'var(--text-secondary)' }}>PR-AUC / Precision</span>
                        <span style={{ color: 'var(--accent-green)', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                          {fmtPct(m.pr_auc)} / {fmtPct(m.precision)}
                        </span>
                      </div>
                      <MetricBar value={m.precision} color="var(--accent-green)" />
                    </div>

                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', background: 'var(--bg-elevated)', padding: '6px 10px', borderRadius: 'var(--radius-sm)' }}>
                      {name === 'anomaly_ensemble' ? (
                        <>Threshold: <b style={{ color: 'var(--text-primary)' }}>{m.threshold?.toFixed(4) ?? '—'}</b> · 2018 FPR: <b>{fmtPct(m.ids2018_raw_fpr)}</b></>
                      ) : (
                        <>Benign FPR (Val/Test): <b style={{ color: 'var(--text-primary)' }}>{fmtPct(m.false_alarm_rate_fpr)}</b></>
                      )}
                    </div>
                  </div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                        <span style={{ color: 'var(--text-secondary)' }}>2017 Test Macro-F1 (Binary)</span>
                        <span style={{ color, fontWeight: 700, fontFamily: 'var(--font-mono)' }}>{fmtPct(m.macro_f1)}</span>
                      </div>
                      <MetricBar value={m.macro_f1} color={color} />
                    </div>

                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                        <span style={{ color: 'var(--text-secondary)' }}>2017 Test Recall / Precision</span>
                        <span style={{ color: 'var(--accent-green)', fontWeight: 700, fontFamily: 'var(--font-mono)' }}>
                          {fmtPct(m.recall)} / {fmtPct(m.precision)}
                        </span>
                      </div>
                      <MetricBar value={m.recall} color="var(--accent-green)" />
                    </div>

                    <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', background: 'var(--bg-elevated)', padding: '6px 10px', borderRadius: 'var(--radius-sm)' }}>
                      Scope: Joint RF+XGB+Isotonic · Benign FPR: <b style={{ color: 'var(--text-primary)' }}>{fmtPct(m.benign_fpr)}</b>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )
        })}
      </div>

      {/* Per-Class Cross-Dataset Table */}
      {Object.keys(perClass17).length > 0 && (
        <div style={{
          background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
          padding: '20px 22px', marginBottom: 24, boxShadow: 'var(--card-shadow)'
        }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase', fontWeight: 800, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 6 }}>
            <ShieldCheck size={14} color="var(--accent-cyan)" />
            <span>Per-Class Evaluation: CIC-IDS2017 Clean Test vs CSE-CIC-IDS2018 External Transfer</span>
          </div>
          <div style={{ overflowX: 'auto' }}>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 12 }}>
              <thead>
                <tr style={{ background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)' }}>
                  {['Class', '2017 Test Count', '2017 Recall / FPR', '2018 Transfer Count', '2018 Recall / FPR'].map(h => (
                    <th key={h} style={{ textAlign: 'left', padding: '9px 12px', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {Object.keys(perClass17).map(cname => {
                  const r17 = perClass17[cname] || {}
                  const r18 = perClass18[cname] || {}
                  return (
                    <tr key={cname} style={{ borderBottom: '1px solid var(--border)' }}>
                      <td style={{ padding: '8px 12px', fontWeight: 700, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)' }}>{cname}</td>
                      <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{(r17.count ?? 0).toLocaleString()}</td>
                      <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: cname === 'BENIGN' ? 'var(--accent-green)' : 'var(--accent-cyan)' }}>
                        {cname === 'BENIGN' ? `FPR ${fmtPct(r17.fpr)}` : fmtPct(r17.recall)}
                      </td>
                      <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>{(r18.count ?? 0).toLocaleString()}</td>
                      <td style={{ padding: '8px 12px', fontFamily: 'var(--font-mono)', color: cname === 'BENIGN' ? 'var(--accent-green)' : 'var(--accent-amber)' }}>
                        {cname === 'BENIGN' ? `FPR ${fmtPct(r18.fpr)}` : fmtPct(r18.recall)}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Architecture Visual Workflow */}
      <div style={{
        background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
        padding: '20px 22px', marginBottom: 24, boxShadow: 'var(--card-shadow)'
      }}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase', fontWeight: 700, marginBottom: 14, display: 'flex', alignItems: 'center', gap: 6 }}>
          <GitFork size={13} color="var(--accent-cyan)" /> DUAL-TIER INTRUSION DETECTION PIPELINE
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
          <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px' }}>
            <div style={{ fontSize: 10, color: 'var(--accent-cyan)', fontWeight: 700, textTransform: 'uppercase' }}>1. Flow Ingestion</div>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginTop: 4 }}>Canonical Normalizer</div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 6, lineHeight: 1.4 }}>
              Aligns {data?.n_features ?? 69} canonical features and applies AnomalyPreprocessor (median fill, signed log1p, clip, scale).
            </div>
          </div>

          <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px' }}>
            <div style={{ fontSize: 10, color: 'var(--accent-green)', fontWeight: 700, textTransform: 'uppercase' }}>2. Tier 1: Supervised</div>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginTop: 4 }}>RF + XGBoost</div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 6, lineHeight: 1.4 }}>
              Multi-class classification across {classes.length || 8} CIC-IDS2017 categories with calibrated confidence.
            </div>
          </div>

          <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px' }}>
            <div style={{ fontSize: 10, color: 'var(--accent-purple)', fontWeight: 700, textTransform: 'uppercase' }}>3. Tier 2: Unsupervised</div>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginTop: 4 }}>Autoencoder + IF</div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 6, lineHeight: 1.4 }}>
              Calibrated at {anomBench?.threshold?.toFixed(4) ?? '—'} (Val {fmtPct(anomBench?.calibration_val?.fpr_overall)} FPR; Raw 2018 {fmtPct(anomBench?.ids2018_raw?.fpr)} FPR).
            </div>
          </div>

          <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px' }}>
            <div style={{ fontSize: 10, color: 'var(--accent-red)', fontWeight: 700, textTransform: 'uppercase' }}>4. Consensus Arbiter</div>
            <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', marginTop: 4 }}>Action Routing & Alerts</div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 6, lineHeight: 1.4 }}>
              Assigns DROP / REVIEW / ALLOW actions, logs alerts, and correlates campaigns into Incidents.
            </div>
          </div>
        </div>
      </div>

      {/* Attack Classes Matrix */}
      <div style={{
        background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
        padding: '20px 22px', boxShadow: 'var(--card-shadow)'
      }}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase', fontWeight: 700, marginBottom: 14 }}>
          Trained Benchmark Attack Classes ({classes.length})
        </div>

        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
          {classes.map(c => {
            const isBenign = c === 'BENIGN'
            return (
              <span
                key={c}
                style={{
                  padding: '5px 14px', borderRadius: 'var(--radius-sm)', fontSize: 11,
                  background: isBenign ? 'rgba(57, 211, 83, 0.1)' : 'rgba(0, 212, 255, 0.08)',
                  border: `1px solid ${isBenign ? 'rgba(57, 211, 83, 0.3)' : 'rgba(0, 212, 255, 0.25)'}`,
                  color: isBenign ? 'var(--accent-green)' : 'var(--accent-cyan)',
                  fontFamily: 'var(--font-mono)', fontWeight: 600
                }}
              >
                {c}
              </span>
            )
          })}
        </div>
      </div>
    </div>
  )
}
