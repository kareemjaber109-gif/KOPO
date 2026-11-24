import { useState, useEffect, useCallback } from 'react'
import { useSearchParams, Link } from 'react-router-dom'
import {
  Layers,
  ShieldAlert,
  Clock,
  CheckCircle2,
  AlertTriangle,
  Search,
  RefreshCw,
  MessageSquarePlus,
  Send,
  ArrowUpRight,
  GitMerge,
  UserCheck
} from 'lucide-react'
import { api } from '../lib/api/client.ts'
import { attackColor, formatDate, formatTs } from '../utils/helpers.js'
import { useAuth } from '../features/auth/AuthContext.jsx'

const STATUS_META = {
  open: { label: 'OPEN', color: 'var(--accent-red)', bg: 'rgba(255,71,87,0.14)' },
  investigating: { label: 'INVESTIGATING', color: 'var(--accent-amber)', bg: 'rgba(240,165,0,0.14)' },
  resolved: { label: 'RESOLVED', color: 'var(--accent-green)', bg: 'rgba(57,211,83,0.14)' },
  false_positive: { label: 'FALSE POSITIVE', color: 'var(--text-muted)', bg: 'rgba(139,148,158,0.14)' },
}

export default function Incidents() {
  const [searchParams, setSearchParams] = useSearchParams()
  const { user } = useAuth()

  const activeId = searchParams.get('id') ? Number(searchParams.get('id')) : null
  const [statusFilter, setStatusFilter] = useState(searchParams.get('status') || 'all')
  const [search, setSearch] = useState('')
  const [windowMinutes, setWindowMinutes] = useState(60)
  const [incidents, setIncidents] = useState([])
  const [detail, setDetail] = useState(null)
  const [loading, setLoading] = useState(true)
  const [aggregating, setAggregating] = useState(false)
  const [noteInput, setNoteInput] = useState('')
  const [assigneeInput, setAssigneeInput] = useState('')
  const [toast, setToast] = useState(null)

  function showToast(msg) {
    setToast(msg)
    setTimeout(() => setToast(null), 3500)
  }

  const loadIncidents = useCallback(async () => {
    setLoading(true)
    try {
      const data = await api.incidents({
        limit: 100,
        status: statusFilter === 'all' ? undefined : statusFilter,
        search: search.trim() || undefined,
      })
      const list = data.incidents || []
      setIncidents(list)
      if (!activeId && list.length > 0 && !detail) {
        const d = await api.incidentDetail(list[0].id)
        setDetail(d)
        setAssigneeInput(d.assigned_to || '')
      }
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }, [statusFilter, search])

  useEffect(() => {
    loadIncidents()
  }, [loadIncidents])

  useEffect(() => {
    if (!activeId) return
    let cancelled = false
    api.incidentDetail(activeId)
      .then(d => {
        if (!cancelled) {
          setDetail(d)
          setAssigneeInput(d.assigned_to || '')
        }
      })
      .catch(e => console.error(e))
    return () => { cancelled = true }
  }, [activeId])

  async function selectIncident(id) {
    const next = new URLSearchParams(searchParams)
    next.set('id', String(id))
    setSearchParams(next)
    try {
      const d = await api.incidentDetail(id)
      setDetail(d)
      setAssigneeInput(d.assigned_to || '')
    } catch (e) {
      console.error(e)
    }
  }

  async function handleAggregate() {
    setAggregating(true)
    try {
      const res = await api.aggregateIncidents(windowMinutes, false)
      showToast(
        `Correlated ${res.alerts_linked} alerts into ${res.incidents_created} new and ${res.incidents_updated} existing incidents`
      )
      await loadIncidents()
    } catch (e) {
      showToast(`Aggregation failed: ${e.message}`)
    } finally {
      setAggregating(false)
    }
  }

  async function handleStatusChange(newStatus, ackAlerts = false) {
    if (!detail) return
    try {
      const analyst = user ? user.name : 'SOC Analyst'
      const updated = await api.updateIncident(detail.id, {
        status: newStatus,
        acknowledge_alerts: ackAlerts,
        analyst,
      })
      setDetail(updated)
      showToast(`Incident #${detail.id} updated to ${newStatus.toUpperCase()}`)
      await loadIncidents()
    } catch (e) {
      showToast(`Update failed: ${e.message}`)
    }
  }

  async function handleAssign() {
    if (!detail) return
    try {
      const updated = await api.updateIncident(detail.id, {
        assigned_to: assigneeInput.trim(),
      })
      setDetail(updated)
      showToast(`Assigned Incident #${detail.id} to ${assigneeInput.trim() || 'Unassigned'}`)
      await loadIncidents()
    } catch (e) {
      showToast(`Assignment failed: ${e.message}`)
    }
  }

  async function handleAddNote(e) {
    e.preventDefault()
    if (!detail || !noteInput.trim()) return
    try {
      const author = user ? `${user.name} (${user.role})` : 'SOC Analyst'
      await api.addIncidentNote(detail.id, noteInput.trim(), author)
      setNoteInput('')
      const refreshed = await api.incidentDetail(detail.id)
      setDetail(refreshed)
      showToast('Case note recorded in database')
    } catch (e) {
      showToast(`Note failed: ${e.message}`)
    }
  }

  const openCount = incidents.filter(i => i.status === 'open').length
  const invCount = incidents.filter(i => i.status === 'investigating').length
  const resolvedCount = incidents.filter(i => i.status === 'resolved' || i.status === 'false_positive').length
  const totalAlertsLinked = incidents.reduce((acc, i) => acc + (i.alert_count || 0), 0)

  return (
    <div style={{ padding: '24px 30px', maxWidth: 1600, margin: '0 auto', flex: 1 }}>
      {toast && (
        <div className="animate-fade" style={{
          position: 'fixed', top: 20, right: 30, zIndex: 9999,
          background: 'var(--bg-elevated)', border: '1px solid var(--accent-cyan)',
          boxShadow: 'var(--dropdown-shadow)', borderRadius: 'var(--radius-md)',
          padding: '12px 18px', color: 'var(--accent-cyan)', fontWeight: 700, fontSize: 12
        }}>
          {toast}
        </div>
      )}

      {/* Command Header */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 12,
        background: 'var(--header-gradient)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
        padding: '16px 22px', marginBottom: 18, boxShadow: 'var(--card-shadow)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 'var(--radius-md)',
            background: 'rgba(189, 147, 249, 0.16)', border: '1px solid rgba(189, 147, 249, 0.35)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-purple)'
          }}>
            <GitMerge size={23} />
          </div>
          <div>
            <div style={{ fontSize: 20, fontWeight: 900, letterSpacing: '0.04em', color: 'var(--text-primary)' }}>
              KOPO // CORRELATED INCIDENTS WORKSPACE
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              Alert Aggregation by Source Host, Threat Vector & Time Window · Case Workflow & Persistent Notes
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <select
            value={windowMinutes}
            onChange={e => setWindowMinutes(Number(e.target.value))}
            style={{
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', borderRadius: 'var(--radius-sm)',
              padding: '7px 10px', fontSize: 11, fontFamily: 'var(--font-mono)'
            }}
          >
            <option value={15}>Window: 15m</option>
            <option value={60}>Window: 1h</option>
            <option value={360}>Window: 6h</option>
            <option value={1440}>Window: 24h</option>
          </select>

          <button
            onClick={handleAggregate}
            disabled={aggregating}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'var(--accent-cyan)', color: '#000', border: 'none',
              borderRadius: 'var(--radius-sm)', padding: '8px 14px',
              fontSize: 12, fontWeight: 800, cursor: aggregating ? 'wait' : 'pointer'
            }}
          >
            <RefreshCw size={13} className={aggregating ? 'animate-spin' : ''} />
            <span>{aggregating ? 'Correlating...' : 'Aggregate Open Alerts'}</span>
          </button>
        </div>
      </div>

      {/* KPI Strip */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 18 }}>
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '12px 16px' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Open Incidents</div>
          <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--accent-red)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{openCount}</div>
        </div>
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '12px 16px' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Under Investigation</div>
          <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--accent-amber)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{invCount}</div>
        </div>
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '12px 16px' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Resolved / Dismissed</div>
          <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--accent-green)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{resolvedCount}</div>
        </div>
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '12px 16px' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Correlated Alerts</div>
          <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>{totalAlertsLinked}</div>
        </div>
      </div>

      {/* Filters Bar */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 10,
        background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)',
        padding: '10px 16px', marginBottom: 18
      }}>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {['all', 'open', 'investigating', 'resolved', 'false_positive'].map(st => (
            <button
              key={st}
              onClick={() => setStatusFilter(st)}
              style={{
                padding: '6px 12px', fontSize: 11, borderRadius: 'var(--radius-sm)', cursor: 'pointer', fontWeight: 700,
                border: `1px solid ${statusFilter === st ? 'var(--accent-cyan)' : 'var(--border)'}`,
                background: statusFilter === st ? 'rgba(0, 212, 255, 0.14)' : 'var(--bg-elevated)',
                color: statusFilter === st ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                textTransform: 'uppercase'
              }}
            >
              {st.replace('_', ' ')}
            </button>
          ))}
        </div>

        <div style={{ position: 'relative', width: 280 }}>
          <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Filter title, attack type, or IP..."
            style={{
              width: '100%', background: 'var(--bg-base)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius-sm)', padding: '6px 10px 6px 30px',
              color: 'var(--text-primary)', fontSize: 11, fontFamily: 'var(--font-mono)', outline: 'none'
            }}
          />
        </div>
      </div>

      {/* Split Layout: Incident List | Detail Workspace */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1.25fr', gap: 20, alignItems: 'start' }}>
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '16px 18px' }}>
          <div style={{ fontSize: 11, fontWeight: 800, textTransform: 'uppercase', color: 'var(--text-muted)', marginBottom: 12 }}>
            Incident Queue ({incidents.length})
          </div>

          {loading ? (
            <div style={{ padding: 30, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>Loading incidents...</div>
          ) : incidents.length === 0 ? (
            <div style={{ padding: 36, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12, border: '1px dashed var(--border)', borderRadius: 'var(--radius-md)' }}>
              No incidents found. Click <b>Aggregate Open Alerts</b> above to correlate alerts into incidents.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, maxHeight: 680, overflowY: 'auto' }}>
              {incidents.map(inc => {
                const st = STATUS_META[inc.status] || STATUS_META.open
                const color = attackColor(inc.primary_attack_type)
                const isSelected = detail?.id === inc.id
                return (
                  <div
                    key={inc.id}
                    onClick={() => selectIncident(inc.id)}
                    style={{
                      padding: '12px 14px', borderRadius: 'var(--radius-md)', cursor: 'pointer',
                      border: `1px solid ${isSelected ? 'var(--accent-cyan)' : 'var(--border)'}`,
                      background: isSelected ? 'rgba(0, 212, 255, 0.08)' : 'var(--bg-elevated)'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 800, color: 'var(--accent-cyan)' }}>INC-{inc.id}</span>
                        <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 800, background: st.bg, color: st.color }}>
                          {st.label}
                        </span>
                        <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700, background: `${color}1c`, color }}>
                          {inc.severity_label}
                        </span>
                      </div>
                      <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', fontWeight: 700 }}>
                        {inc.alert_count} alerts
                      </span>
                    </div>

                    <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 6 }}>
                      {inc.title}
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                      <span>{inc.source_ips?.length ? inc.source_ips.join(', ') : 'Multiple/Unattributed'}</span>
                      <span>{formatDate(inc.last_seen)} {formatTs(inc.last_seen)}</span>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Right Column: Detail Inspector */}
        {detail ? (
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '20px 22px', display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
              <div>
                <div style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
                  INCIDENT CASE #INC-{detail.id}
                </div>
                <h2 style={{ fontSize: 18, fontWeight: 900, color: 'var(--text-primary)', marginTop: 2 }}>
                  {detail.title}
                </h2>
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
                  Window: {formatDate(detail.first_seen)} {formatTs(detail.first_seen)} ➔ {formatTs(detail.last_seen)} UTC
                </div>
              </div>

              <span style={{
                fontSize: 11, padding: '4px 10px', borderRadius: 'var(--radius-sm)', fontWeight: 800,
                background: (STATUS_META[detail.status] || STATUS_META.open).bg,
                color: (STATUS_META[detail.status] || STATUS_META.open).color
              }}>
                {(STATUS_META[detail.status] || STATUS_META.open).label}
              </span>
            </div>

            {/* Workflow Controls */}
            <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: 14 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, marginBottom: 8 }}>
                Case Status Workflow & Assignment
              </div>
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 12 }}>
                {['open', 'investigating', 'resolved', 'false_positive'].map(st => (
                  <button
                    key={st}
                    onClick={() => handleStatusChange(st, st === 'resolved' || st === 'false_positive')}
                    style={{
                      padding: '6px 12px', fontSize: 11, fontWeight: 700, borderRadius: 'var(--radius-sm)', cursor: 'pointer',
                      border: `1px solid ${detail.status === st ? STATUS_META[st].color : 'var(--border)'}`,
                      background: detail.status === st ? STATUS_META[st].bg : 'var(--bg-surface)',
                      color: detail.status === st ? STATUS_META[st].color : 'var(--text-secondary)',
                      textTransform: 'uppercase'
                    }}
                  >
                    {st.replace('_', ' ')}
                  </button>
                ))}
              </div>

              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <UserCheck size={14} color="var(--accent-cyan)" />
                <input
                  type="text"
                  value={assigneeInput}
                  onChange={e => setAssigneeInput(e.target.value)}
                  placeholder="Assign analyst (e.g. analyst_sara)"
                  style={{
                    flex: 1, background: 'var(--bg-base)', border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm)', padding: '6px 10px', fontSize: 11,
                    color: 'var(--text-primary)', outline: 'none'
                  }}
                />
                <button
                  onClick={handleAssign}
                  style={{
                    background: 'var(--bg-surface)', border: '1px solid var(--accent-cyan)',
                    color: 'var(--accent-cyan)', padding: '6px 12px', borderRadius: 'var(--radius-sm)',
                    fontSize: 11, fontWeight: 700, cursor: 'pointer'
                  }}
                >
                  Save Assignee
                </button>
              </div>
            </div>

            {/* Linked Alerts */}
            <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: 14 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, marginBottom: 8 }}>
                Linked Alerts ({detail.alerts?.length || 0})
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 200, overflowY: 'auto' }}>
                {(detail.alerts || []).map(a => (
                  <Link
                    key={a.id}
                    to={`/alerts?id=${a.id}`}
                    style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      padding: '7px 10px', background: 'var(--bg-surface)', border: '1px solid var(--border)',
                      borderRadius: 'var(--radius-sm)', textDecoration: 'none', fontSize: 11
                    }}
                  >
                    <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', fontWeight: 700 }}>#{a.id}</span>
                    <span style={{ fontWeight: 700, color: attackColor(a.attack_type) }}>{a.attack_type}</span>
                    <span style={{ color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)' }}>{a.action || 'ALERT'}</span>
                    <span style={{ color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>{((a.confidence || 0) * 100).toFixed(1)}%</span>
                    <ArrowUpRight size={12} color="var(--accent-cyan)" />
                  </Link>
                ))}
              </div>
            </div>

            {/* DB-Persisted Incident Notes */}
            <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: 14 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, marginBottom: 8 }}>
                Investigation Log & Analyst Notes
              </div>

              <form onSubmit={handleAddNote} style={{ display: 'flex', gap: 8, marginBottom: 12 }}>
                <input
                  type="text"
                  value={noteInput}
                  onChange={e => setNoteInput(e.target.value)}
                  placeholder="Add investigation finding, containment step, or IOC..."
                  style={{
                    flex: 1, background: 'var(--bg-base)', border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm)', padding: '7px 10px', fontSize: 11,
                    color: 'var(--text-primary)', outline: 'none'
                  }}
                />
                <button
                  type="submit"
                  style={{
                    display: 'flex', alignItems: 'center', gap: 5,
                    background: 'var(--accent-cyan)', color: '#000', border: 'none',
                    borderRadius: 'var(--radius-sm)', padding: '7px 14px', fontSize: 11, fontWeight: 800, cursor: 'pointer'
                  }}
                >
                  <Send size={12} /> Add Note
                </button>
              </form>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 8, maxHeight: 200, overflowY: 'auto' }}>
                {(detail.notes || []).length === 0 ? (
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>No notes recorded yet for this incident.</div>
                ) : (
                  detail.notes.map(n => (
                    <div key={n.id} style={{ padding: '8px 10px', background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>
                        <b style={{ color: 'var(--accent-cyan)' }}>{n.author}</b>
                        <span>{formatDate(n.created_at)} {formatTs(n.created_at)}</span>
                      </div>
                      <div style={{ fontSize: 12, color: 'var(--text-primary)' }}>{n.note}</div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        ) : (
          <div style={{
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            height: 320, border: '1px dashed var(--border)', borderRadius: 'var(--radius-lg)',
            color: 'var(--text-muted)', fontSize: 12
          }}>
            Select an incident on the left to investigate linked alerts and notes.
          </div>
        )}
      </div>
    </div>
  )
}
