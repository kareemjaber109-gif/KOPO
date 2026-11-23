import { useState, useCallback, useMemo } from 'react'
import {
  Activity,
  AlertTriangle,
  Shield,
  Zap,
  ArrowUpRight,
  ShieldAlert,
  Clock,
  Cpu,
  Layers,
  CheckCircle2,
  Lock,
  Filter,
  BarChart2,
  Sliders,
  Radio
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  AreaChart, Area, Brush, ReferenceLine, CartesianGrid
} from 'recharts'
import { Link } from 'react-router-dom'
import { usePolling } from '../hooks/usePolling.js'
import StatCard from '../components/StatCard.jsx'
import { api } from '../lib/api/client.ts'
import { attackColor, formatTs, formatDate } from '../utils/helpers.js'

const PALETTE = ['#00d4ff', '#ff4757', '#f0a500', '#bd93f9', '#ff6b35', '#39d353', '#ff79c6']

export default function Overview() {
  const fetchStats = useCallback(() => api.stats(), [])
  const fetchAlerts = useCallback(() => api.alerts({ limit: 200 }), [])
  const fetchHealth = useCallback(() => api.health(), [])

  const { data: stats } = usePolling(fetchStats, 6000)
  const { data: alertsData } = usePolling(fetchAlerts, 6000)
  const { data: healthData } = usePolling(fetchHealth, 15000)

  const alerts = alertsData?.alerts ?? []

  // Interactive Time Brush Window State
  const [brushRange, setBrushRange] = useState(null)

  // 1. Filtered alerts based on time brush
  const filteredAlerts = useMemo(() => {
    if (!brushRange || !alerts.length) return alerts
    const { startIndex, endIndex } = brushRange
    return alerts.slice(startIndex, (endIndex || startIndex) + 1)
  }, [alerts, brushRange])

  // 2. Timeline chart data (Alerts over time)
  const timeSeriesData = useMemo(() => {
    if (!alerts.length) return []
    // Group alerts chronologically
    const sorted = [...alerts].sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    return sorted.map((a, idx) => ({
      index: idx,
      id: a.id,
      time: formatTs(a.timestamp),
      confidence: a.confidence,
      severity: a.severity_score,
      attack_type: a.attack_type,
      count: 1
    }))
  }, [alerts])

  // 3. Confidence Histogram with 0.75 and 0.92 threshold bins
  const histogramData = useMemo(() => {
    const bins = [
      { bin: '<0.75 (Sub-Alert)', range: [0, 0.75], count: 0, fill: '#64748b' },
      { bin: '0.75 - 0.85 (Alert Min)', range: [0.75, 0.85], count: 0, fill: 'var(--accent-amber)' },
      { bin: '0.85 - 0.92 (Medium)', range: [0.85, 0.92], count: 0, fill: '#ff793f' },
      { bin: '>=0.92 (High Severity)', range: [0.92, 1.01], count: 0, fill: 'var(--accent-red)' },
    ]

    filteredAlerts.forEach(a => {
      const c = a.confidence || 0
      for (const b of bins) {
        if (c >= b.range[0] && c < b.range[1]) {
          b.count++
          break
        }
      }
    })

    return bins
  }, [filteredAlerts])

  // 4. Attack distribution
  const pieData = useMemo(() => {
    const counts = {}
    filteredAlerts.forEach(a => {
      counts[a.attack_type] = (counts[a.attack_type] || 0) + 1
    })
    return Object.entries(counts).map(([name, value], i) => ({
      name,
      value,
      fill: attackColor(name) || PALETTE[i % PALETTE.length],
    }))
  }, [filteredAlerts])

  // Calculations for KPI Strip
  const openAlerts = alerts.filter(a => !a.is_acknowledged).length
  const ackedAlerts = alerts.filter(a => a.is_acknowledged).length
  const highSevAlerts = alerts.filter(a => a.severity_label === 'Critical' || a.severity_label === 'High').length
  const meanConfidence = alerts.length
    ? (alerts.reduce((acc, a) => acc + (a.confidence || 0), 0) / alerts.length * 100).toFixed(1)
    : '0.0'

  return (
    <div style={{ padding: '24px 30px', maxWidth: 1600, margin: '0 auto', flex: 1 }}>

      {/* Executive Command Banner */}
      <div style={{
        display: 'flex',
        flexWrap: 'wrap',
        justifyContent: 'space-between',
        alignItems: 'center',
        background: 'var(--header-gradient)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius-lg)',
        padding: '16px 22px',
        marginBottom: 20,
        boxShadow: 'var(--card-shadow)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 'var(--radius-md)',
            background: 'linear-gradient(135deg, rgba(57, 211, 83, 0.2) 0%, rgba(0, 212, 255, 0.2) 100%)',
            border: '1px solid rgba(57, 211, 83, 0.35)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-green)',
            boxShadow: '0 0 16px rgba(57, 211, 83, 0.2)'
          }}>
            <Shield size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 19, fontWeight: 900, letterSpacing: '0.04em', color: 'var(--text-primary)' }}>
                KOPO // SOC OPERATIONS OVERVIEW
              </span>
              <span style={{
                fontSize: 10, padding: '2px 8px', borderRadius: 12,
                background: 'rgba(57,211,83,0.15)', color: 'var(--accent-green)',
                fontWeight: 700, border: '1px solid rgba(57,211,83,0.3)', display: 'flex', alignItems: 'center', gap: 4
              }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-green)', animation: 'pulse-dot 1.5s infinite' }} />
                DEFCON 5 · GUARDED
              </span>
              {brushRange && (
                <span style={{
                  fontSize: 10, padding: '2px 8px', borderRadius: 12,
                  background: 'rgba(0,212,255,0.15)', color: 'var(--accent-cyan)',
                  fontWeight: 700, border: '1px solid rgba(0,212,255,0.3)'
                }}>
                  TIMELINE FILTER ACTIVE ({filteredAlerts.length} ALERTS)
                </span>
              )}
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              Active Multi-Model Network Intrusion Detection & Real-Time Incident Telemetry
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          {brushRange && (
            <button
              onClick={() => setBrushRange(null)}
              style={{
                background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                color: 'var(--text-secondary)', padding: '6px 12px', borderRadius: 'var(--radius-sm)',
                fontSize: 11, cursor: 'pointer', fontWeight: 600
              }}
            >
              Reset Brush Filter
            </button>
          )}

          <Link
            to="/detect"
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'rgba(0, 212, 255, 0.12)', border: '1px solid var(--accent-cyan)',
              color: 'var(--accent-cyan)', padding: '7px 16px', borderRadius: 'var(--radius-sm)',
              textDecoration: 'none', fontSize: 11, fontFamily: 'var(--font-mono)', fontWeight: 700,
              boxShadow: '0 0 12px rgba(0, 212, 255, 0.15)'
            }}
          >
            <Zap size={13} />
            Live Flow Studio
          </Link>
        </div>
      </div>

      {/* KPI Strip (5 Essential SOC Metrics) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 14, marginBottom: 20 }}>
        <StatCard
          label="Alerts (Last 24h)"
          value={stats?.recent_24h?.toLocaleString() ?? alerts.length}
          sub="Dispatched security incidents"
          color="var(--accent-cyan)"
          icon={Activity}
        />
        <StatCard
          label="Open vs Acknowledged"
          value={`${openAlerts} / ${ackedAlerts}`}
          sub="Active vs Resolved threats"
          color={openAlerts > 0 ? 'var(--accent-amber)' : 'var(--accent-green)'}
          icon={AlertTriangle}
        />
        <StatCard
          label="High-Severity Threats"
          value={highSevAlerts}
          sub="Critical & High escalations"
          color="var(--accent-red)"
          icon={ShieldAlert}
        />
        <StatCard
          label="Mean AI Confidence"
          value={`${meanConfidence}%`}
          sub="Model consensus certainty"
          color="var(--accent-purple)"
          icon={Cpu}
        />
        <StatCard
          label="Backend Health"
          value={healthData?.status === 'ok' ? 'HEALTHY' : 'DEGRADED'}
          sub={api.isMock ? 'Mock Mode Active' : 'Live FastAPI :8000'}
          color={healthData?.status === 'ok' ? 'var(--accent-green)' : 'var(--accent-amber)'}
          icon={Shield}
        />
      </div>

      {/* Timeline Alerts-Over-Time Chart with Brush Filter */}
      <div style={{
        background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
        padding: '18px 22px', marginBottom: 20, boxShadow: 'var(--card-shadow)'
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <BarChart2 size={15} color="var(--accent-cyan)" />
            <span style={{ fontSize: 11, color: 'var(--text-primary)', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 800 }}>
              ALERTS OVER TIME & BRUSH TIME-WINDOW FILTER
            </span>
          </div>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Drag the brush bar below to filter all metrics across the console
          </span>
        </div>

        {timeSeriesData.length > 0 ? (
          <ResponsiveContainer width="100%" height={160}>
            <AreaChart data={timeSeriesData} margin={{ top: 5, right: 15, left: -20, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
              <XAxis dataKey="time" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
              <Tooltip
                content={({ active, payload }) => {
                  if (!active || !payload?.length) return null
                  const p = payload[0].payload
                  return (
                    <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px', fontSize: 11 }}>
                      <div style={{ color: 'var(--text-muted)' }}>Incident #{p.id} · {p.time}</div>
                      <div style={{ color: 'var(--accent-cyan)', fontWeight: 800 }}>{p.attack_type}</div>
                      <div style={{ color: 'var(--text-secondary)' }}>Confidence: {(p.confidence * 100).toFixed(1)}%</div>
                    </div>
                  )
                }}
              />
              <Area type="monotone" dataKey="confidence" stroke="var(--accent-cyan)" fill="rgba(0, 212, 255, 0.15)" />
              <Brush
                dataKey="time"
                height={26}
                stroke="var(--accent-cyan)"
                fill="var(--bg-elevated)"
                onChange={e => setBrushRange(e)}
              />
            </AreaChart>
          </ResponsiveContainer>
        ) : (
          <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '30px 0', fontSize: 12 }}>
            Awaiting incident stream data...
          </div>
        )}
      </div>

      {/* Middle Grid: Confidence Histogram + Attack Distribution */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 1.3fr', gap: 18, marginBottom: 20 }}>

        {/* Confidence Histogram with 0.75 and 0.92 Markers */}
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '18px 22px', boxShadow: 'var(--card-shadow)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-primary)', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 800 }}>
                CONFIDENCE HISTOGRAM & THRESHOLD MARKERS
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                Thresholds: Min Alert (0.75) · High Severity (0.92)
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8, fontSize: 10, fontFamily: 'var(--font-mono)' }}>
              <span style={{ color: 'var(--accent-amber)' }}>● 0.75 Min</span>
              <span style={{ color: 'var(--accent-red)' }}>● 0.92 High</span>
            </div>
          </div>

          <ResponsiveContainer width="100%" height={190}>
            <BarChart data={histogramData} margin={{ top: 10, right: 10, left: -20, bottom: 5 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
              <XAxis dataKey="bin" tick={{ fill: 'var(--text-secondary)', fontSize: 10, fontFamily: 'var(--font-mono)' }} />
              <YAxis tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
              <Tooltip
                content={({ active, payload }) => {
                  if (!active || !payload?.length) return null
                  const p = payload[0].payload
                  return (
                    <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px', fontSize: 11 }}>
                      <div style={{ fontWeight: 800, color: p.fill }}>{p.bin}</div>
                      <div style={{ color: 'var(--text-primary)' }}>{p.count} Incidents</div>
                    </div>
                  )
                }}
              />
              <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                {histogramData.map((entry, index) => (
                  <rect key={index} fill={entry.fill} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Attack Vector Distribution */}
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '18px 22px', boxShadow: 'var(--card-shadow)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-primary)', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 800 }}>
                THREAT SIGNATURE DISTRIBUTION
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                Breakdown of categorized attack vectors
              </div>
            </div>
            <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', fontWeight: 700 }}>
              {pieData.length} Attack Vectors
            </span>
          </div>

          {pieData.length > 0 ? (
            <ResponsiveContainer width="100%" height={190}>
              <BarChart data={pieData} layout="vertical" margin={{ left: 15, right: 20, top: 5, bottom: 5 }}>
                <XAxis type="number" tick={{ fill: 'var(--text-muted)', fontSize: 10 }} />
                <YAxis dataKey="name" type="category" width={110} tick={{ fill: 'var(--text-secondary)', fontSize: 11, fontFamily: 'var(--font-mono)' }} />
                <Tooltip
                  content={({ active, payload, label }) => {
                    if (!active || !payload?.length) return null
                    return (
                      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 6, padding: '8px 12px', fontSize: 11 }}>
                        <div style={{ color: 'var(--text-muted)' }}>{label}</div>
                        <div style={{ color: 'var(--accent-cyan)', fontWeight: 800 }}>{payload[0].value} incidents</div>
                      </div>
                    )
                  }}
                />
                <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                  {pieData.map((entry, i) => (
                    <rect key={i} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div style={{ color: 'var(--text-muted)', textAlign: 'center', padding: '50px 0', fontSize: 12 }}>
              No threat data recorded for selected window
            </div>
          )}
        </div>
      </div>

      {/* Live Recent Dispatches Feed */}
      <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '18px 22px', boxShadow: 'var(--card-shadow)' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <Clock size={15} color="var(--accent-cyan)" />
            <span style={{ fontSize: 11, color: 'var(--text-primary)', letterSpacing: '0.06em', textTransform: 'uppercase', fontWeight: 800 }}>
              LIVE INCIDENT DISPATCH STREAM ({filteredAlerts.length} ALERTS)
            </span>
          </div>

          <Link
            to="/alerts"
            style={{
              display: 'flex', alignItems: 'center', gap: 4, fontSize: 11, color: 'var(--accent-cyan)',
              textDecoration: 'none', fontFamily: 'var(--font-mono)', fontWeight: 700
            }}
          >
            Open Full Alert Queue <ArrowUpRight size={13} />
          </Link>
        </div>

        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)' }}>
                {['ID', 'TIMESTAMP', 'THREAT VECTOR', 'SEVERITY', 'CONFIDENCE', 'SOURCE ➔ DESTINATION', 'STATUS'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '10px 14px', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', letterSpacing: '0.06em' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filteredAlerts.slice(0, 8).map(a => {
                const color = attackColor(a.attack_type)
                return (
                  <tr key={a.id} style={{ borderBottom: '1px solid var(--border)', transition: 'background 0.15s' }}>
                    <td style={{ padding: '10px 14px', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontWeight: 700 }}>
                      #{a.id}
                    </td>
                    <td style={{ padding: '10px 14px', fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>
                      {formatDate(a.timestamp)} {formatTs(a.timestamp)}
                    </td>
                    <td style={{ padding: '10px 14px', fontSize: 12, fontWeight: 800, color, fontFamily: 'var(--font-mono)' }}>
                      {a.attack_type}
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      <span style={{ fontSize: 10, padding: '2px 8px', borderRadius: 4, background: `${color}1c`, color, fontWeight: 700, border: `1px solid ${color}44` }}>
                        {a.severity_label}
                      </span>
                    </td>
                    <td style={{ padding: '10px 14px', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', fontWeight: 600 }}>
                      {((a.confidence || 0) * 100).toFixed(1)}%
                    </td>
                    <td style={{ padding: '10px 14px', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)' }}>
                      {a.source_ip || '185.220.101.5'} ➔ {a.dest_ip || '192.168.1.10'}
                    </td>
                    <td style={{ padding: '10px 14px' }}>
                      {a.is_acknowledged ? (
                        <span style={{ fontSize: 10, color: 'var(--accent-green)', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>RESOLVED</span>
                      ) : (
                        <span style={{ fontSize: 10, color: 'var(--accent-amber)', fontFamily: 'var(--font-mono)', fontWeight: 800, display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-amber)', animation: 'pulse-dot 1.5s infinite' }} />
                          ACTIVE
                        </span>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

    </div>
  )
}
