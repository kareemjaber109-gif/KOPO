import { useState, useCallback, useMemo, useEffect, useRef } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  CheckCheck,
  ShieldAlert,
  Download,
  Filter,
  Search,
  Clock,
  CheckCircle2,
  AlertTriangle,
  ArrowUpDown,
  X,
  Copy,
  Check,
  Shield,
  Radio,
  Flame,
  Layers,
  Terminal,
  Activity,
  FileText,
  SlidersHorizontal,
  ExternalLink,
  ChevronDown,
  Lock,
  Eye,
  Columns,
  Bookmark,
  Zap,
  Globe,
  CheckSquare
} from 'lucide-react'
import { usePolling } from '../hooks/usePolling.js'
import { api } from '../lib/api/client.ts'
import { attackColor, formatTs, formatDate } from '../utils/helpers.js'
import { useAuth } from '../features/auth/AuthContext.jsx'

function getCategoryIcon(type = '') {
  const t = type.toUpperCase()
  if (t.includes('SYN') || t.includes('UDP') || t.includes('ICMP') || t.includes('AMPLIFICATION') || t.includes('SMURF') || t.includes('DDOS')) {
    return <Zap size={13} color="var(--accent-red)" />
  }
  if (t.includes('HTTP_FLOOD') || t.includes('SLOW') || t.includes('DEATH') || t.includes('TEARDROP') || t.includes('DOS')) {
    return <Clock size={13} color="var(--accent-amber)" />
  }
  if (t.includes('SCAN')) {
    return <Search size={13} color="var(--accent-cyan)" />
  }
  if (t.includes('BRUTE') || t.includes('PATATOR')) {
    return <Lock size={13} color="var(--accent-purple)" />
  }
  if (t.includes('SQL') || t.includes('XSS') || t.includes('WEB') || t.includes('HEARTBLEED') || t.includes('PHISHING')) {
    return <Globe size={13} color="#ff793f" />
  }
  if (t.includes('RANSOM') || t.includes('BOT') || t.includes('C2') || t.includes('MINING')) {
    return <Flame size={13} color="#ff79c6" />
  }
  return <ShieldAlert size={13} color="var(--accent-red)" />
}

export default function Alerts() {
  const [searchParams, setSearchParams] = useSearchParams()
  const { user } = useAuth()

  // URL-synced filter parameters
  const severityParam = searchParams.get('severity') || ''
  const typeParam = searchParams.get('type') || ''
  const statusParam = searchParams.get('status') || 'all' // all, active, resolved
  const searchParam = searchParams.get('q') || ''
  const activeAlertId = searchParams.get('id') ? Number(searchParams.get('id')) : null

  // Local state
  const [searchQuery, setSearchQuery] = useState(searchParam)
  const [selectedIds, setSelectedIds] = useState(new Set())
  const [focusedIndex, setFocusedIndex] = useState(0)
  const [toastMessage, setToastMessage] = useState(null)
  const [copiedPayload, setCopiedPayload] = useState(false)
  const [copiedIp, setCopiedIp] = useState(null)
  const [analystNotes, setAnalystNotes] = useState('')
  const [confidenceMin, setConfidenceMin] = useState(0)

  // Column visibility toggles
  const [showColumnsMenu, setShowColumnsMenu] = useState(false)
  const [visibleColumns, setVisibleColumns] = useState({
    id: true,
    timestamp: true,
    attack_type: true,
    category: true,
    severity: true,
    confidence: true,
    ips: true,
    status: true,
  })

  const searchInputRef = useRef(null)
  const columnsMenuRef = useRef(null)

  // Polling alerts from API (real or mock)
  const fetchAlerts = useCallback(() => api.alerts({ limit: 500 }), [])
  const { data, refresh } = usePolling(fetchAlerts, 6000)
  const alerts = data?.alerts ?? []

  function showToast(msg) {
    setToastMessage(msg)
    setTimeout(() => setToastMessage(null), 3000)
  }

  // Update URL helper
  function updateURL(key, value) {
    const next = new URLSearchParams(searchParams)
    if (value && value !== 'all') {
      next.set(key, value)
    } else {
      next.delete(key)
    }
    setSearchParams(next)
  }

  // Sync search input with URL (debounced)
  useEffect(() => {
    const t = setTimeout(() => {
      updateURL('q', searchQuery)
    }, 250)
    return () => clearTimeout(t)
  }, [searchQuery])

  // Close column menu on outside click
  useEffect(() => {
    function handleClickOutside(e) {
      if (columnsMenuRef.current && !columnsMenuRef.current.contains(e.target)) {
        setShowColumnsMenu(false)
      }
    }
    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Filter alerts based on active controls
  const filteredAlerts = useMemo(() => {
    return alerts.filter(a => {
      if (severityParam && a.severity_label !== severityParam) return false
      if (typeParam && a.attack_type !== typeParam) return false
      if (statusParam === 'active' && a.is_acknowledged) return false
      if (statusParam === 'resolved' && !a.is_acknowledged) return false
      if (confidenceMin > 0 && (a.confidence || 0) < confidenceMin) return false

      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase()
        const matchesId = String(a.id).includes(q)
        const matchesType = a.attack_type?.toLowerCase().includes(q)
        const matchesCat = a.attack_category?.toLowerCase().includes(q)
        const matchesSev = a.severity_label?.toLowerCase().includes(q)
        const matchesSrc = a.source_ip?.toLowerCase().includes(q)
        const matchesDst = a.dest_ip?.toLowerCase().includes(q)
        if (!matchesId && !matchesType && !matchesCat && !matchesSev && !matchesSrc && !matchesDst) {
          return false
        }
      }

      return true
    })
  }, [alerts, severityParam, typeParam, statusParam, searchQuery, confidenceMin])

  // Active Alert for Investigation Drawer (deep-linkable)
  const selectedAlert = useMemo(() => {
    if (!activeAlertId) return null
    return alerts.find(a => a.id === activeAlertId) || null
  }, [alerts, activeAlertId])

  // Load analyst notes for active alert
  useEffect(() => {
    if (selectedAlert) {
      const stored = localStorage.getItem(`kopo_notes_${selectedAlert.id}`) || ''
      setAnalystNotes(stored)
    }
  }, [selectedAlert])

  function saveNotes(val) {
    setAnalystNotes(val)
    if (selectedAlert) {
      localStorage.setItem(`kopo_notes_${selectedAlert.id}`, val)
    }
  }

  // Keyboard navigation hotkeys (j, k, Enter, a, /)
  useEffect(() => {
    function handleKeyDown(e) {
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(e.target.tagName)) {
        if (e.key === 'Escape') {
          e.target.blur()
        }
        return
      }

      if (e.key === '/') {
        e.preventDefault()
        searchInputRef.current?.focus()
      } else if (e.key === 'j' || e.key === 'ArrowDown') {
        e.preventDefault()
        setFocusedIndex(prev => Math.min(prev + 1, filteredAlerts.length - 1))
      } else if (e.key === 'k' || e.key === 'ArrowUp') {
        e.preventDefault()
        setFocusedIndex(prev => Math.max(prev - 1, 0))
      } else if (e.key === 'Enter') {
        e.preventDefault()
        const target = filteredAlerts[focusedIndex]
        if (target) {
          updateURL('id', target.id)
        }
      } else if (e.key === 'a') {
        e.preventDefault()
        const target = filteredAlerts[focusedIndex]
        if (target && !target.is_acknowledged) {
          ackSingle(target.id)
        }
      } else if (e.key === 'Escape') {
        updateURL('id', null)
      }
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [filteredAlerts, focusedIndex])

  // Single & Bulk Acknowledge
  async function ackSingle(id) {
    await api.acknowledge(id)
    showToast(`Incident #${id} acknowledged and marked as resolved`)
    refresh()
  }

  async function handleBulkAcknowledge() {
    const ids = Array.from(selectedIds)
    if (!ids.length) return
    const res = await api.bulkAcknowledge(ids)
    showToast(`Bulk resolved ${res.count} security incidents`)
    setSelectedIds(new Set())
    refresh()
  }

  // Multi-select helpers
  function toggleSelectAll() {
    if (selectedIds.size === filteredAlerts.length) {
      setSelectedIds(new Set())
    } else {
      setSelectedIds(new Set(filteredAlerts.map(a => a.id)))
    }
  }

  function toggleSelect(id) {
    const next = new Set(selectedIds)
    if (next.has(id)) next.delete(id)
    else next.add(id)
    setSelectedIds(next)
  }

  // CSV Export
  function exportCSV() {
    const dataset = selectedIds.size > 0
      ? filteredAlerts.filter(a => selectedIds.has(a.id))
      : filteredAlerts

    if (!dataset.length) return
    const headers = ['ID', 'Date', 'Time', 'Threat Vector', 'Category', 'Severity', 'Confidence', 'Source IP', 'Dest IP', 'Status']
    const rows = dataset.map(a => [
      a.id,
      formatDate(a.timestamp),
      formatTs(a.timestamp),
      a.attack_type,
      a.attack_category || 'Threat',
      a.severity_label,
      `${((a.confidence || 0) * 100).toFixed(1)}%`,
      a.source_ip || '',
      a.dest_ip || '',
      a.is_acknowledged ? 'Resolved' : 'Active'
    ])
    const csvContent = [headers.join(','), ...rows.map(r => r.join(','))].join('\n')
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url
    link.download = `kopo_alerts_audit_${new Date().toISOString().slice(0, 10)}.csv`
    link.click()
  }

  function copyIpToClipboard(ip, e) {
    e.stopPropagation()
    navigator.clipboard.writeText(ip)
    setCopiedIp(ip)
    setTimeout(() => setCopiedIp(null), 1500)
  }

  // Related alerts from same source IP
  const relatedAlerts = useMemo(() => {
    if (!selectedAlert || !selectedAlert.source_ip) return []
    return alerts.filter(a => a.source_ip === selectedAlert.source_ip && a.id !== selectedAlert.id).slice(0, 5)
  }, [selectedAlert, alerts])

  // Counts for KPI strips
  const totalCount = alerts.length
  const activeCount = alerts.filter(a => !a.is_acknowledged).length
  const resolvedCount = alerts.filter(a => a.is_acknowledged).length
  const criticalCount = alerts.filter(a => a.severity_label === 'Critical' && !a.is_acknowledged).length
  const meanConfidence = useMemo(() => {
    if (!alerts.length) return 0
    const sum = alerts.reduce((acc, a) => acc + (a.confidence || 0), 0)
    return Math.round((sum / alerts.length) * 1000) / 10
  }, [alerts])

  return (
    <div style={{ padding: '24px 30px', maxWidth: 1600, margin: '0 auto', flex: 1, position: 'relative' }}>

      {/* Floating Toast Notification */}
      {toastMessage && (
        <div className="animate-fade" style={{
          position: 'fixed', top: 20, right: 30, zIndex: 9999,
          background: 'var(--bg-elevated)', border: '1px solid var(--accent-green)',
          boxShadow: 'var(--dropdown-shadow)', borderRadius: 'var(--radius-md)',
          padding: '12px 18px', color: 'var(--accent-green)', fontWeight: 700, fontSize: 12,
          display: 'flex', alignItems: 'center', gap: 8
        }}>
          <CheckCircle2 size={16} />
          <span>{toastMessage}</span>
        </div>
      )}

      {/* Command Bar Header with KOPO Branding */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center',
        background: 'var(--header-gradient)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
        padding: '16px 22px', marginBottom: 18, boxShadow: 'var(--card-shadow)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <div style={{
            width: 44, height: 44, borderRadius: 'var(--radius-md)',
            background: 'linear-gradient(135deg, rgba(255, 71, 87, 0.25) 0%, rgba(240, 165, 0, 0.15) 100%)',
            border: '1px solid rgba(255, 71, 87, 0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-red)',
            boxShadow: '0 0 16px rgba(255, 71, 87, 0.25)'
          }}>
            <ShieldAlert size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 20, fontWeight: 900, letterSpacing: '0.04em', color: 'var(--text-primary)' }}>
                KOPO // SOC ALERT QUEUE
              </span>
              <span style={{
                fontSize: 10, padding: '2px 8px', borderRadius: 12,
                background: 'rgba(255,71,87,0.15)', color: 'var(--accent-red)',
                fontWeight: 800, border: '1px solid rgba(255,71,87,0.3)', display: 'flex', alignItems: 'center', gap: 5
              }}>
                <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-red)', animation: 'pulse-dot 1.2s infinite' }} />
                {activeCount} UNRESOLVED INCIDENTS
              </span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 2 }}>
              High-Density Real-time Incident Triage & Forensic Dispatch · Tier 1/2 Clearance
            </div>
          </div>
        </div>

        {/* Action Controls & Columns Menu */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, position: 'relative' }} ref={columnsMenuRef}>
          <button
            onClick={() => setShowColumnsMenu(prev => !prev)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              color: 'var(--text-secondary)', borderRadius: 'var(--radius-sm)',
              padding: '7px 12px', fontSize: 11, cursor: 'pointer', fontWeight: 600
            }}
          >
            <Columns size={13} /> Columns ▾
          </button>

          {/* Columns Visibility Popover */}
          {showColumnsMenu && (
            <div className="animate-slide" style={{
              position: 'absolute', top: '100%', right: 120, marginTop: 6, zIndex: 120,
              background: 'var(--bg-surface)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius-md)', padding: 12, boxShadow: 'var(--dropdown-shadow)',
              minWidth: 180, display: 'flex', flexDirection: 'column', gap: 8
            }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, borderBottom: '1px solid var(--border)', paddingBottom: 4 }}>
                Toggle Table Columns
              </div>
              {Object.keys(visibleColumns).map(col => (
                <label key={col} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: 'var(--text-primary)', cursor: 'pointer', textTransform: 'capitalize' }}>
                  <input
                    type="checkbox"
                    checked={visibleColumns[col]}
                    onChange={() => setVisibleColumns(prev => ({ ...prev, [col]: !prev[col] }))}
                  />
                  <span>{col.replace('_', ' ')}</span>
                </label>
              ))}
            </div>
          )}

          <button
            onClick={exportCSV}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', borderRadius: 'var(--radius-sm)',
              padding: '7px 14px', fontSize: 11, cursor: 'pointer', fontFamily: 'var(--font-mono)', fontWeight: 600
            }}
          >
            <Download size={13} /> Export CSV ({selectedIds.size > 0 ? selectedIds.size : 'All'})
          </button>
        </div>
      </div>

      {/* SOC Command Strip (Dense KPI Cards) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14, marginBottom: 16 }}>
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '12px 16px' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Total Ingested Alerts</div>
          <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
            {totalCount.toLocaleString()}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>Recorded by backend sensors</div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '12px 16px' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 5 }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-red)', animation: 'pulse-dot 1.2s infinite' }} />
            Active Triage Queue
          </div>
          <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--accent-red)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
            {activeCount.toLocaleString()}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>Requires analyst acknowledgment</div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '12px 16px' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Critical Escalations</div>
          <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--threshold-high)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
            {criticalCount}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>Exceeds 92% severity threshold</div>
        </div>

        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '12px 16px' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>Mean ML Confidence</div>
          <div style={{ fontSize: 22, fontWeight: 900, color: 'var(--accent-cyan)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
            {meanConfidence}%
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', marginTop: 2 }}>Ensemble consensus average</div>
        </div>
      </div>

      {/* KEYBOARD SHORTCUT HUD LEGEND */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', alignItems: 'center', justifyContent: 'space-between', gap: 10,
        background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)',
        padding: '8px 14px', marginBottom: 14, fontSize: 11
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800 }}>
            Keyboard HUD:
          </span>
          <span style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <kbd style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', padding: '1px 6px', borderRadius: 3, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', fontWeight: 700 }}>/</kbd> Focus Search
          </span>
          <span style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <kbd style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', padding: '1px 6px', borderRadius: 3, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', fontWeight: 700 }}>j</kbd> / <kbd style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', padding: '1px 6px', borderRadius: 3, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', fontWeight: 700 }}>k</kbd> Navigate Rows
          </span>
          <span style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <kbd style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', padding: '1px 6px', borderRadius: 3, fontFamily: 'var(--font-mono)', color: 'var(--accent-cyan)', fontWeight: 700 }}>Enter</kbd> Open Forensic Drawer
          </span>
          <span style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <kbd style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', padding: '1px 6px', borderRadius: 3, fontFamily: 'var(--font-mono)', color: 'var(--accent-green)', fontWeight: 700 }}>a</kbd> Quick Acknowledge
          </span>
          <span style={{ color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: 4 }}>
            <kbd style={{ background: 'var(--bg-base)', border: '1px solid var(--border)', padding: '1px 6px', borderRadius: 3, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontWeight: 700 }}>Esc</kbd> Close Drawer
          </span>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 10, color: 'var(--text-muted)' }}>
          <span>Polled every 6s</span>
          <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-green)' }} />
        </div>
      </div>

      {/* SAVED FILTER PRESET PILLS */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 14, overflowX: 'auto', paddingBottom: 2 }}>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, display: 'flex', alignItems: 'center', gap: 4 }}>
          <Bookmark size={12} color="var(--accent-cyan)" /> Presets:
        </span>

        {[
          { label: 'All Incidents', count: totalCount, action: () => { setSearchParams({}); setSearchQuery('') } },
          { label: '🔴 Critical Escalations', count: criticalCount, action: () => { updateURL('severity', 'Critical'); updateURL('status', 'active') } },
          { label: '⏳ DoS & Floods', count: alerts.filter(a => a.attack_category === 'DoS Attacks' || a.attack_type === 'HTTP_FLOOD').length, action: () => { updateURL('type', 'HTTP_FLOOD') } },
          { label: '⚡ DDoS Vectors', count: alerts.filter(a => a.attack_type === 'SYN_FLOOD' || a.attack_type === 'UDP_FLOOD').length, action: () => { updateURL('type', 'SYN_FLOOD') } },
          { label: '🔍 Recon & Scans', count: alerts.filter(a => a.attack_type.includes('SCAN')).length, action: () => { updateURL('type', 'PORT_SCAN') } },
          { label: '🔑 Brute Force', count: alerts.filter(a => a.attack_type.includes('BRUTE')).length, action: () => { updateURL('type', 'BRUTE_FORCE_SSH') } },
          { label: '🌐 Web Exploits', count: alerts.filter(a => a.attack_type === 'SQL_INJECTION' || a.attack_type === 'WEB_ATTACK').length, action: () => { updateURL('type', 'SQL_INJECTION') } },
          { label: '● Active Only', count: activeCount, action: () => updateURL('status', 'active') },
        ].map(p => (
          <button
            key={p.label}
            onClick={p.action}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '5px 12px', fontSize: 11, borderRadius: 'var(--radius-sm)',
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              color: 'var(--text-secondary)', cursor: 'pointer', fontWeight: 600, whiteSpace: 'nowrap',
              transition: 'all 0.15s'
            }}
          >
            <span>{p.label}</span>
            {p.count > 0 && (
              <span style={{ fontSize: 9, padding: '1px 5px', borderRadius: 4, background: 'rgba(255,255,255,0.06)', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                {p.count}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Multi-Select Action Banner (appears when checkboxes are ticked) */}
      {selectedIds.size > 0 && (
        <div className="animate-fade" style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          background: 'rgba(0, 212, 255, 0.12)', border: '1px solid var(--accent-cyan)',
          borderRadius: 'var(--radius-md)', padding: '10px 16px', marginBottom: 14
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, fontWeight: 700, color: 'var(--accent-cyan)' }}>
            <CheckSquare size={16} />
            <span>{selectedIds.size} security incidents selected</span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <button
              onClick={handleBulkAcknowledge}
              style={{
                background: 'var(--accent-cyan)', color: '#000000', border: 'none',
                borderRadius: 'var(--radius-sm)', padding: '6px 14px', fontSize: 11, fontWeight: 800, cursor: 'pointer'
              }}
            >
              Bulk Acknowledge Selected
            </button>
            <button
              onClick={() => setSelectedIds(new Set())}
              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: 11, cursor: 'pointer' }}
            >
              Clear Selection
            </button>
          </div>
        </div>
      )}

      {/* Filter & Search HUD */}
      <div style={{
        display: 'flex', flexWrap: 'wrap', justifyContent: 'space-between', alignItems: 'center', gap: 10,
        background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '10px 16px', marginBottom: 16
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, flex: 1, minWidth: 260 }}>
          <div style={{ position: 'relative', width: 280 }}>
            <Search size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
            <input
              ref={searchInputRef}
              type="text"
              placeholder="Search ID, Type, IP (Press / to focus)..."
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              style={{
                width: '100%', background: 'var(--bg-base)', border: '1px solid var(--border)',
                borderRadius: 'var(--radius-sm)', padding: '6px 10px 6px 30px', color: 'var(--text-primary)',
                fontSize: 11, fontFamily: 'var(--font-mono)', outline: 'none'
              }}
            />
          </div>

          {/* Severity Filter */}
          <select
            value={severityParam}
            onChange={e => updateURL('severity', e.target.value)}
            style={{
              background: 'var(--bg-base)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', borderRadius: 'var(--radius-sm)',
              padding: '6px 10px', fontSize: 11, fontFamily: 'var(--font-mono)', cursor: 'pointer', outline: 'none'
            }}
          >
            <option value="">All Severities</option>
            {['Critical', 'High', 'Medium', 'Low', 'None'].map(s => <option key={s} value={s}>{s}</option>)}
          </select>

          {/* Status Filter */}
          <select
            value={statusParam}
            onChange={e => updateURL('status', e.target.value)}
            style={{
              background: 'var(--bg-base)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', borderRadius: 'var(--radius-sm)',
              padding: '6px 10px', fontSize: 11, fontFamily: 'var(--font-mono)', cursor: 'pointer', outline: 'none'
            }}
          >
            <option value="all">All Statuses</option>
            <option value="active">Active Only</option>
            <option value="resolved">Resolved Only</option>
          </select>

          {/* Confidence Filter Slider */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>
            <span>Min Conf:</span>
            <input
              type="range"
              min="0"
              max="0.99"
              step="0.05"
              value={confidenceMin}
              onChange={e => setConfidenceMin(Number(e.target.value))}
              style={{ width: 70, cursor: 'pointer' }}
            />
            <span style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>{(confidenceMin * 100).toFixed(0)}%</span>
          </div>
        </div>

        <div style={{ display: 'flex', alignItems: 'center', gap: 12, fontSize: 11, fontFamily: 'var(--font-mono)' }}>
          <span style={{ color: 'var(--text-secondary)' }}>Showing: <b style={{ color: 'var(--text-primary)' }}>{filteredAlerts.length}</b> of {alerts.length}</span>
          <span style={{ color: 'var(--border)' }}>|</span>
          <span style={{ color: 'var(--accent-amber)' }}>● {activeCount} Active</span>
          <span style={{ color: 'var(--accent-green)' }}>✓ {resolvedCount} Resolved</span>
        </div>
      </div>

      {/* Main Alert Queue Table (Dense SOC Styling) */}
      <div style={{
        background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)',
        overflow: 'hidden', boxShadow: 'var(--card-shadow)'
      }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
          <thead>
            <tr style={{ background: 'var(--bg-elevated)', borderBottom: '1px solid var(--border)' }}>
              <th style={{ width: 36, padding: '10px 12px', textAlign: 'center' }}>
                <input
                  type="checkbox"
                  checked={selectedIds.size > 0 && selectedIds.size === filteredAlerts.length}
                  onChange={toggleSelectAll}
                  style={{ cursor: 'pointer' }}
                />
              </th>
              {visibleColumns.id && <th style={{ padding: '10px 12px', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>ID</th>}
              {visibleColumns.timestamp && <th style={{ padding: '10px 12px', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>TIMESTAMP</th>}
              {visibleColumns.attack_type && <th style={{ padding: '10px 12px', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>THREAT VECTOR</th>}
              {visibleColumns.category && <th style={{ padding: '10px 12px', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>CATEGORY</th>}
              {visibleColumns.severity && <th style={{ padding: '10px 12px', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>SEVERITY</th>}
              {visibleColumns.confidence && <th style={{ padding: '10px 12px', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>AI CONFIDENCE</th>}
              {visibleColumns.ips && <th style={{ padding: '10px 12px', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>SOURCE ➔ DESTINATION</th>}
              {visibleColumns.status && <th style={{ padding: '10px 12px', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>STATUS</th>}
              <th style={{ textAlign: 'right', padding: '10px 12px', fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)', fontWeight: 700 }}>ACTION</th>
            </tr>
          </thead>
          <tbody>
            {filteredAlerts.map((a, idx) => {
              const color = attackColor(a.attack_type)
              const isSelected = selectedIds.has(a.id)
              const isFocused = focusedIndex === idx
              const isActive = activeAlertId === a.id
              const categoryIcon = getCategoryIcon(a.attack_type)

              return (
                <tr
                  key={a.id}
                  onClick={() => { setFocusedIndex(idx); updateURL('id', a.id) }}
                  style={{
                    borderBottom: '1px solid var(--border)',
                    background: isActive ? 'rgba(0, 212, 255, 0.12)' : isFocused ? 'rgba(0, 212, 255, 0.05)' : isSelected ? 'rgba(189, 147, 249, 0.08)' : a.is_acknowledged ? 'transparent' : 'rgba(255, 71, 87, 0.02)',
                    cursor: 'pointer',
                    transition: 'background 0.1s ease'
                  }}
                >
                  <td style={{ padding: '10px 12px', textAlign: 'center' }} onClick={e => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={isSelected}
                      onChange={() => toggleSelect(a.id)}
                      style={{ cursor: 'pointer' }}
                    />
                  </td>
                  {visibleColumns.id && (
                    <td style={{ padding: '10px 12px', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-muted)', fontWeight: 700 }}>
                      #{a.id}
                    </td>
                  )}
                  {visibleColumns.timestamp && (
                    <td style={{ padding: '10px 12px', fontSize: 11, color: 'var(--text-secondary)', fontFamily: 'var(--font-mono)', whiteSpace: 'nowrap' }}>
                      {formatDate(a.timestamp)} {formatTs(a.timestamp)}
                    </td>
                  )}
                  {visibleColumns.attack_type && (
                    <td style={{ padding: '10px 12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                        {categoryIcon}
                        <span style={{ fontSize: 12, fontWeight: 800, color, fontFamily: 'var(--font-mono)' }}>
                          {a.attack_type}
                        </span>
                      </div>
                    </td>
                  )}
                  {visibleColumns.category && (
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 4, background: 'rgba(255,255,255,0.06)', color: 'var(--text-secondary)' }}>
                        {a.attack_category || 'Threat'}
                      </span>
                    </td>
                  )}
                  {visibleColumns.severity && (
                    <td style={{ padding: '10px 12px' }}>
                      <span style={{
                        fontSize: 10, padding: '2px 8px', borderRadius: 4,
                        background: a.severity_label === 'Critical' ? 'rgba(255,71,87,0.2)' : `${color}18`,
                        color: a.severity_label === 'Critical' ? 'var(--accent-red)' : color,
                        fontWeight: 800, border: `1px solid ${a.severity_label === 'Critical' ? 'var(--accent-red)' : `${color}44`}`,
                        boxShadow: a.severity_label === 'Critical' ? '0 0 8px rgba(255,71,87,0.3)' : 'none'
                      }}>
                        {a.severity_label.toUpperCase()}
                      </span>
                    </td>
                  )}
                  {visibleColumns.confidence && (
                    <td style={{ padding: '10px 12px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                        <div style={{ width: 44, height: 4, background: 'var(--bg-base)', borderRadius: 2, overflow: 'hidden' }}>
                          <div style={{ width: `${(a.confidence || 0) * 100}%`, height: '100%', background: color }} />
                        </div>
                        <span style={{ fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-primary)', fontWeight: 700 }}>
                          {((a.confidence || 0) * 100).toFixed(1)}%
                        </span>
                      </div>
                    </td>
                  )}
                  {visibleColumns.ips && (
                    <td style={{ padding: '10px 12px', fontSize: 11, fontFamily: 'var(--font-mono)', color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span
                          onClick={(e) => copyIpToClipboard(a.source_ip || '185.220.101.5', e)}
                          title="Click to copy source IP"
                          style={{ cursor: 'pointer', color: copiedIp === (a.source_ip || '185.220.101.5') ? 'var(--accent-green)' : 'var(--accent-cyan)' }}
                        >
                          {a.source_ip || '185.220.101.5'}
                        </span>
                        <span style={{ color: 'var(--text-muted)' }}>➔</span>
                        <span>{a.dest_ip || '192.168.1.10'}</span>
                      </div>
                    </td>
                  )}
                  {visibleColumns.status && (
                    <td style={{ padding: '10px 12px' }}>
                      {a.is_acknowledged ? (
                        <span style={{ fontSize: 10, color: 'var(--accent-green)', fontFamily: 'var(--font-mono)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                          <CheckCircle2 size={12} /> RESOLVED
                        </span>
                      ) : (
                        <span style={{ fontSize: 10, color: 'var(--accent-amber)', fontFamily: 'var(--font-mono)', fontWeight: 800, display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--accent-amber)', animation: 'pulse-dot 1.5s infinite' }} />
                          ACTIVE
                        </span>
                      )}
                    </td>
                  )}
                  <td style={{ padding: '10px 12px', textAlign: 'right' }} onClick={e => e.stopPropagation()}>
                    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 6 }}>
                      {!a.is_acknowledged && (
                        <button
                          onClick={() => ackSingle(a.id)}
                          style={{
                            background: 'rgba(57, 211, 83, 0.12)', border: '1px solid rgba(57, 211, 83, 0.35)',
                            color: 'var(--accent-green)', padding: '3px 8px', borderRadius: 'var(--radius-sm)',
                            fontSize: 10, fontFamily: 'var(--font-mono)', cursor: 'pointer', fontWeight: 700
                          }}
                        >
                          ✓ Ack
                        </button>
                      )}
                      <button
                        onClick={() => updateURL('id', a.id)}
                        style={{
                          background: 'transparent', border: '1px solid var(--border)',
                          color: 'var(--accent-cyan)', padding: '3px 7px', borderRadius: 'var(--radius-sm)',
                          fontSize: 10, cursor: 'pointer', fontWeight: 600
                        }}
                      >
                        ➔ Inspect
                      </button>
                    </div>
                  </td>
                </tr>
              )
            })}
            {!filteredAlerts.length && (
              <tr>
                <td colSpan={10} style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
                  No security alerts match the selected query.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {/* FORENSICS INVESTIGATION DRAWER (DEEP-LINKABLE) */}
      {selectedAlert && (
        <div style={{
          position: 'fixed', top: 0, right: 0, bottom: 0, width: '100%', maxWidth: 540, zIndex: 1000,
          background: 'var(--bg-surface)', borderLeft: '1px solid var(--border)',
          boxShadow: 'var(--dropdown-shadow)', display: 'flex', flexDirection: 'column'
        }} className="animate-drawer">
          
          {/* Header */}
          <div style={{
            padding: '16px 20px', borderBottom: '1px solid var(--border)', background: 'var(--bg-elevated)',
            display: 'flex', justifyContent: 'space-between', alignItems: 'center'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <Terminal size={18} color="var(--accent-cyan)" />
              <div>
                <div style={{ fontSize: 14, fontWeight: 900, color: 'var(--text-primary)' }}>
                  INCIDENT INVESTIGATION #{selectedAlert.id}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                  {formatDate(selectedAlert.timestamp)} {formatTs(selectedAlert.timestamp)} UTC
                </div>
              </div>
            </div>

            <button
              onClick={() => updateURL('id', null)}
              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4 }}
            >
              <X size={18} />
            </button>
          </div>

          {/* Drawer Body */}
          <div style={{ padding: '18px 22px', flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 16 }}>
            
            {/* Verdict & Threshold Gauge */}
            <div style={{
              padding: '16px 18px', borderRadius: 'var(--radius-md)',
              border: `1px solid ${attackColor(selectedAlert.attack_type)}`,
              background: `linear-gradient(180deg, ${attackColor(selectedAlert.attack_type)}18 0%, ${attackColor(selectedAlert.attack_type)}05 100%)`
            }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 11, color: attackColor(selectedAlert.attack_type), fontWeight: 800, textTransform: 'uppercase' }}>
                  {selectedAlert.severity_label} SEVERITY INCIDENT
                </span>
                <span style={{
                  fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 800,
                  background: selectedAlert.is_acknowledged ? 'rgba(57,211,83,0.15)' : 'rgba(255,71,87,0.15)',
                  color: selectedAlert.is_acknowledged ? 'var(--accent-green)' : 'var(--accent-red)'
                }}>
                  {selectedAlert.is_acknowledged ? 'RESOLVED' : 'ACTIVE THREAT'}
                </span>
              </div>

              <div style={{ fontSize: 24, fontWeight: 900, color: attackColor(selectedAlert.attack_type) }}>
                {selectedAlert.attack_type}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginTop: 4 }}>
                Category: <b>{selectedAlert.attack_category || 'Threat Vector'}</b> · IP: <code style={{ color: 'var(--accent-cyan)' }}>{selectedAlert.source_ip || '185.220.101.5'}</code>
              </div>

              {/* Threshold Gauge Indicator */}
              <div style={{ marginTop: 12, paddingTop: 10, borderTop: '1px solid var(--border)' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>
                  <span>AI Confidence: <b style={{ color: 'var(--text-primary)' }}>{((selectedAlert.confidence || 0) * 100).toFixed(1)}%</b></span>
                  <span>Min: 75% | High: 92%</span>
                </div>
                <div style={{ position: 'relative', width: '100%', height: 6, background: 'var(--bg-base)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${(selectedAlert.confidence || 0) * 100}%`, height: '100%', background: attackColor(selectedAlert.attack_type) }} />
                  {/* 75% threshold marker */}
                  <div style={{ position: 'absolute', left: '75%', top: 0, bottom: 0, width: 2, background: 'var(--accent-amber)' }} title="Min Alert Threshold (0.75)" />
                  {/* 92% threshold marker */}
                  <div style={{ position: 'absolute', left: '92%', top: 0, bottom: 0, width: 2, background: 'var(--accent-red)' }} title="High Severity Threshold (0.92)" />
                </div>
              </div>
            </div>

            {/* Top 5 Influential Features (Explainability) */}
            <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 16px' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 6 }}>
                <Layers size={13} color="var(--accent-cyan)" />
                <span>Top Influential Flow Features (SHAP / Tree Weights)</span>
              </div>

              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {[
                  { name: 'Total Fwd Packets', weight: 0.38, val: '8,000 pkts' },
                  { name: 'Flow Bytes/s', weight: 0.29, val: '23.36 MB/s' },
                  { name: 'Flow Duration', weight: 0.16, val: '500 ms' },
                  { name: 'SYN Flag Count', weight: 0.11, val: '1 (SYN sent)' },
                  { name: 'ACK Flag Count', weight: 0.06, val: '50 (Unmatched)' },
                ].map(feat => (
                  <div key={feat.name} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 11, fontFamily: 'var(--font-mono)' }}>
                    <span style={{ color: 'var(--text-secondary)' }}>{feat.name}</span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                      <span style={{ color: 'var(--text-primary)', fontWeight: 700 }}>{feat.val}</span>
                      <span style={{ color: 'var(--accent-cyan)', fontSize: 10 }}>({(feat.weight * 100).toFixed(0)}%)</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            {/* Formatted Raw Flow Payload Viewer */}
            <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', overflow: 'hidden' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '8px 14px', borderBottom: '1px solid var(--border)' }}>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <FileText size={12} color="var(--accent-cyan)" />
                  <span>Raw Telemetry Payload</span>
                </span>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(selectedAlert.raw_result || '')
                    setCopiedPayload(true)
                    setTimeout(() => setCopiedPayload(false), 1500)
                  }}
                  style={{ display: 'flex', alignItems: 'center', gap: 4, background: 'none', border: 'none', color: copiedPayload ? 'var(--accent-green)' : 'var(--text-secondary)', fontSize: 11, cursor: 'pointer' }}
                >
                  {copiedPayload ? <Check size={12} /> : <Copy size={12} />} {copiedPayload ? 'Copied' : 'Copy JSON'}
                </button>
              </div>

              <pre style={{
                margin: 0, padding: 12, background: 'var(--code-bg)', color: '#e6edf3',
                fontSize: 11, fontFamily: 'var(--font-mono)', maxHeight: 180, overflowY: 'auto', lineHeight: 1.5
              }}>
                {selectedAlert.raw_result ? JSON.stringify(JSON.parse(selectedAlert.raw_result), null, 2) : 'No raw flow data recorded'}
              </pre>
            </div>

            {/* Related Alerts from Same Host IP */}
            <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 16px' }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, marginBottom: 8 }}>
                Correlated Incidents ({selectedAlert.source_ip || 'Host'})
              </div>
              {relatedAlerts.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {relatedAlerts.map(r => (
                    <div
                      key={r.id}
                      onClick={() => updateURL('id', r.id)}
                      style={{
                        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                        padding: '6px 8px', background: 'var(--bg-surface)', border: '1px solid var(--border)',
                        borderRadius: 'var(--radius-sm)', cursor: 'pointer', fontSize: 11
                      }}
                    >
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--text-muted)' }}>#{r.id}</span>
                      <span style={{ fontWeight: 700, color: attackColor(r.attack_type) }}>{r.attack_type}</span>
                      <span style={{ color: 'var(--text-secondary)', fontSize: 10 }}>{formatTs(r.timestamp)}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>No other alerts recorded from this source IP.</div>
              )}
            </div>

            {/* Analyst Case Notes Editor (Persisted locally) */}
            <div style={{ background: 'var(--bg-elevated)', border: '1px solid var(--border)', borderRadius: 'var(--radius-md)', padding: '14px 16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800 }}>
                  Analyst Case Notes
                </span>
                <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>Saved in Local Storage</span>
              </div>
              <textarea
                value={analystNotes}
                onChange={e => saveNotes(e.target.value)}
                placeholder="Enter triage notes, host investigation findings, or false-positive rationale..."
                style={{
                  width: '100%', minHeight: 70, background: 'var(--bg-base)', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)', padding: 8, color: 'var(--text-primary)',
                  fontSize: 11, fontFamily: 'var(--font-mono)', outline: 'none', resize: 'vertical'
                }}
              />
            </div>

            {/* Quick Actions */}
            <div style={{ display: 'flex', gap: 8 }}>
              {!selectedAlert.is_acknowledged && (
                <button
                  onClick={() => ackSingle(selectedAlert.id)}
                  style={{
                    flex: 1, padding: 10, background: 'rgba(57, 211, 83, 0.15)',
                    border: '1px solid var(--accent-green)', color: 'var(--accent-green)',
                    borderRadius: 'var(--radius-sm)', fontWeight: 800, fontSize: 11, cursor: 'pointer',
                    display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6
                  }}
                >
                  <CheckCircle2 size={13} />
                  <span>Acknowledge / Resolve Incident</span>
                </button>
              )}
            </div>

          </div>
        </div>
      )}

    </div>
  )
}
