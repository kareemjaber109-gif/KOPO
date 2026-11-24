import { useState, useEffect } from 'react'
import {
  CheckSquare,
  ShieldAlert,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock,
  UserCheck,
  Server,
  Terminal,
  ExternalLink,
  Search,
  Filter,
  Lock,
  RefreshCw,
  Eye,
  FileCheck
} from 'lucide-react'
import { api } from '../lib/api/client'
import { useAuth } from '../features/auth/AuthContext'

export default function AgentApprovals() {
  const { user } = useAuth()
  const [approvals, setApprovals] = useState([])
  const [filterStatus, setFilterStatus] = useState('pending_human_approval')
  const [loading, setLoading] = useState(true)
  const [selectedAction, setSelectedAction] = useState(null)
  const [modalAction, setModalAction] = useState(null) // { item, decision: 'approved' | 'denied' }
  const [decisionComment, setDecisionComment] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [successToast, setSuccessToast] = useState(null)

  useEffect(() => {
    loadApprovals()
  }, [])

  async function loadApprovals() {
    setLoading(true)
    try {
      const data = await api.getApprovals()
      setApprovals(data)
      if (data.length > 0 && !selectedAction) {
        setSelectedAction(data[0])
      }
    } catch (e) {
      console.error(e)
    } finally {
      setLoading(false)
    }
  }

  const filtered = approvals.filter(a => {
    if (filterStatus === 'all') return true
    return a.status === filterStatus
  })

  function openConfirmModal(item, decision) {
    setModalAction({ item, decision })
    setDecisionComment(decision === 'approved' ? 'Mitigation verified and approved for automated firewall enforcement.' : 'Action rejected — potential false positive or duplicate rule.')
  }

  async function handleConfirmDecision() {
    if (!modalAction) return
    setSubmitting(true)
    try {
      const analystName = user ? `${user.name} (${user.role})` : 'SOC Lead Analyst'
      await api.decideApproval(modalAction.item.id, modalAction.decision, decisionComment, analystName)
      
      setSuccessToast(`Action ${modalAction.item.id} successfully marked as ${modalAction.decision.toUpperCase()}.`)
      setTimeout(() => setSuccessToast(null), 4000)

      setModalAction(null)
      await loadApprovals()
    } catch (e) {
      alert(`Error updating approval: ${e.message}`)
    } finally {
      setSubmitting(false)
    }
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
            background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.25) 0%, rgba(57, 211, 83, 0.15) 100%)',
            border: '1px solid rgba(0, 212, 255, 0.4)',
            display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-cyan)',
            boxShadow: '0 0 16px rgba(0, 212, 255, 0.2)'
          }}>
            <CheckSquare size={24} />
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
              <span style={{ fontSize: 20, fontWeight: 800, letterSpacing: '0.04em', color: 'var(--text-primary)' }}>
                KOPO // AI AGENT ACTION APPROVAL QUEUE
              </span>
              <span style={{
                fontSize: 10, padding: '2px 8px', borderRadius: 12,
                background: 'rgba(0, 212, 255, 0.15)', color: 'var(--accent-cyan)',
                fontWeight: 700, border: '1px solid rgba(0, 212, 255, 0.3)'
              }}>
                ● HUMAN-IN-THE-LOOP CLEARANCE
              </span>
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 2 }}>
              Autonomous Mitigation Proposals Requiring Tier 2 / Lead Authorization
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: 8 }}>
          <button
            onClick={async () => { await api.syncApprovals(); await loadApprovals() }}
            disabled={loading}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'rgba(0, 212, 255, 0.12)', border: '1px solid var(--accent-cyan)',
              color: 'var(--accent-cyan)', padding: '7px 14px', borderRadius: 'var(--radius-sm)',
              fontSize: 12, cursor: 'pointer', fontWeight: 700
            }}
          >
            <span>Sync From Alerts</span>
          </button>
          <button
            onClick={loadApprovals}
            disabled={loading}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              color: 'var(--text-primary)', padding: '7px 14px', borderRadius: 'var(--radius-sm)',
              fontSize: 12, cursor: 'pointer', fontWeight: 600
            }}
          >
            <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            <span>Refresh Queue</span>
          </button>
        </div>
      </div>

      {/* Success Notification */}
      {successToast && (
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
          {successToast}
        </div>
      )}

      {/* Filter Tabs */}
      <div style={{ display: 'flex', gap: 8, marginBottom: 18 }}>
        {[
          { id: 'pending_human_approval', label: 'Pending Approval', count: approvals.filter(a => a.status === 'pending_human_approval').length },
          { id: 'approved', label: 'Approved & Enforced', count: approvals.filter(a => a.status === 'approved').length },
          { id: 'denied', label: 'Denied / Dismissed', count: approvals.filter(a => a.status === 'denied').length },
          { id: 'all', label: 'All Actions', count: approvals.length },
        ].map(tab => {
          const isActive = filterStatus === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setFilterStatus(tab.id)}
              style={{
                display: 'flex', alignItems: 'center', gap: 6,
                padding: '8px 16px', borderRadius: 'var(--radius-md)',
                border: `1px solid ${isActive ? 'var(--accent-cyan)' : 'var(--border)'}`,
                background: isActive ? 'rgba(0, 212, 255, 0.12)' : 'var(--bg-surface)',
                color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                fontSize: 12, fontWeight: isActive ? 700 : 500, cursor: 'pointer',
                transition: 'all 0.15s ease'
              }}
            >
              <span>{tab.label}</span>
              <span style={{
                fontSize: 10, padding: '1px 6px', borderRadius: 10,
                background: isActive ? 'var(--accent-cyan)' : 'var(--bg-elevated)',
                color: isActive ? '#000000' : 'var(--text-muted)',
                fontWeight: 800
              }}>
                {tab.count}
              </span>
            </button>
          )
        })}
      </div>

      {/* Main Grid: Approvals Table on Left | Action Drawer on Right */}
      <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: 20, alignItems: 'start' }}>
        
        {/* Approvals Table */}
        <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '18px 20px' }}>
          <div style={{ fontSize: 12, color: 'var(--text-primary)', textTransform: 'uppercase', fontWeight: 800, marginBottom: 12, display: 'flex', alignItems: 'center', gap: 8 }}>
            <Server size={14} color="var(--accent-cyan)" />
            <span>Mitigation Action Queue ({filtered.length})</span>
          </div>

          {filtered.length === 0 ? (
            <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', border: '1px dashed var(--border)', borderRadius: 'var(--radius-md)' }}>
              No actions currently matching this filter status.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
              {filtered.map(item => {
                const isSelected = selectedAction?.id === item.id
                const isPending = item.status === 'pending_human_approval'
                return (
                  <div
                    key={item.id}
                    onClick={() => setSelectedAction(item)}
                    style={{
                      padding: '14px 16px',
                      borderRadius: 'var(--radius-md)',
                      border: `1px solid ${isSelected ? 'var(--accent-cyan)' : 'var(--border)'}`,
                      background: isSelected ? 'rgba(0, 212, 255, 0.08)' : 'var(--bg-elevated)',
                      cursor: 'pointer',
                      transition: 'all 0.15s ease'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontFamily: 'var(--font-mono)', fontSize: 11, fontWeight: 800, color: 'var(--accent-cyan)' }}>
                          {item.id}
                        </span>
                        <span style={{
                          fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700,
                          background: item.action === 'BLOCK_IP' ? 'rgba(255,71,87,0.15)' : 'rgba(189,147,249,0.15)',
                          color: item.action === 'BLOCK_IP' ? 'var(--accent-red)' : 'var(--accent-purple)'
                        }}>
                          {item.action}
                        </span>
                        <span style={{
                          fontSize: 10, padding: '2px 7px', borderRadius: 4, fontWeight: 700,
                          background: item.status === 'approved' ? 'rgba(57,211,83,0.15)' : item.status === 'denied' ? 'rgba(255,71,87,0.15)' : 'rgba(240,165,0,0.15)',
                          color: item.status === 'approved' ? 'var(--accent-green)' : item.status === 'denied' ? 'var(--accent-red)' : 'var(--accent-amber)'
                        }}>
                          {item.status === 'pending_human_approval' ? 'AWAITING APPROVAL' : item.status.toUpperCase()}
                        </span>
                      </div>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {new Date(item.created_at).toLocaleTimeString()}
                      </span>
                    </div>

                    <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>Target:</span>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: 13, fontWeight: 800, color: 'var(--text-primary)' }}>
                        {item.target}
                      </span>
                    </div>

                    <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.4, marginBottom: 10 }}>
                      {item.rationale}
                    </div>

                    {/* Action Buttons if Pending */}
                    {isPending && (
                      <div style={{ display: 'flex', gap: 8, marginTop: 8, borderTop: '1px solid var(--border)', paddingTop: 10 }}>
                        <button
                          onClick={(e) => { e.stopPropagation(); openConfirmModal(item, 'approved') }}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 5, padding: '6px 12px', fontSize: 11,
                            background: 'rgba(57, 211, 83, 0.15)', border: '1px solid var(--accent-green)',
                            color: 'var(--accent-green)', borderRadius: 'var(--radius-sm)', cursor: 'pointer', fontWeight: 700
                          }}
                        >
                          <CheckCircle size={12} /> Approve Action
                        </button>
                        <button
                          onClick={(e) => { e.stopPropagation(); openConfirmModal(item, 'denied') }}
                          style={{
                            display: 'flex', alignItems: 'center', gap: 5, padding: '6px 12px', fontSize: 11,
                            background: 'rgba(255, 71, 87, 0.15)', border: '1px solid var(--accent-red)',
                            color: 'var(--accent-red)', borderRadius: 'var(--radius-sm)', cursor: 'pointer', fontWeight: 700
                          }}
                        >
                          <XCircle size={12} /> Deny Action
                        </button>
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Selected Action Details Drawer */}
        {selectedAction ? (
          <div style={{ background: 'var(--bg-surface)', border: '1px solid var(--border)', borderRadius: 'var(--radius-lg)', padding: '20px 22px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 800, marginBottom: 8 }}>
              Action Telemetry & Evidence
            </div>
            
            <div style={{ fontSize: 18, fontWeight: 900, color: 'var(--text-primary)', marginBottom: 14 }}>
              {selectedAction.action} ➔ {selectedAction.target}
            </div>

            <div style={{ background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', padding: 14, marginBottom: 14, border: '1px solid var(--border)' }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10, fontSize: 11 }}>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Proposing Agent:</span>
                  <div style={{ color: 'var(--accent-cyan)', fontWeight: 700, marginTop: 2 }}>{selectedAction.agent}</div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Severity Level:</span>
                  <div style={{ color: 'var(--accent-red)', fontWeight: 700, marginTop: 2 }}>{selectedAction.severity}</div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Trigger Timestamp:</span>
                  <div style={{ color: 'var(--text-primary)', fontFamily: 'var(--font-mono)', marginTop: 2 }}>
                    {new Date(selectedAction.created_at).toLocaleString()}
                  </div>
                </div>
                <div>
                  <span style={{ color: 'var(--text-muted)' }}>Linked Alert IDs:</span>
                  <div style={{ color: 'var(--accent-amber)', fontFamily: 'var(--font-mono)', fontWeight: 700, marginTop: 2 }}>
                    {selectedAction.evidence_alert_ids.map(id => `#${id}`).join(', ')}
                  </div>
                </div>
              </div>
            </div>

            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: 6 }}>
                AI Decision Rationale:
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6, background: 'var(--bg-elevated)', padding: 12, borderRadius: 'var(--radius-sm)', border: '1px solid var(--border)' }}>
                {selectedAction.rationale}
              </div>
            </div>

            {selectedAction.decided_by && (
              <div style={{ marginBottom: 16, background: 'rgba(0, 212, 255, 0.08)', padding: 12, borderRadius: 'var(--radius-sm)', border: '1px solid rgba(0, 212, 255, 0.3)' }}>
                <div style={{ fontSize: 11, color: 'var(--accent-cyan)', fontWeight: 700, marginBottom: 4, display: 'flex', alignItems: 'center', gap: 6 }}>
                  <UserCheck size={13} />
                  <span>Audit Trail Record</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-primary)' }}>
                  Decided by: <b>{selectedAction.decided_by}</b>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                  At: {selectedAction.decided_at ? new Date(selectedAction.decided_at).toLocaleString() : '—'}
                </div>
                {selectedAction.audit_comment && (
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginTop: 6, fontStyle: 'italic' }}>
                    "{selectedAction.audit_comment}"
                  </div>
                )}
              </div>
            )}

            {selectedAction.status === 'pending_human_approval' && (
              <div style={{ display: 'flex', gap: 10, marginTop: 20 }}>
                <button
                  onClick={() => openConfirmModal(selectedAction, 'approved')}
                  style={{
                    flex: 1, padding: '10px 16px', background: 'var(--accent-green)',
                    color: '#000000', border: 'none', borderRadius: 'var(--radius-sm)',
                    fontSize: 12, fontWeight: 800, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6
                  }}
                >
                  <CheckCircle size={14} /> Authorize Mitigation
                </button>
                <button
                  onClick={() => openConfirmModal(selectedAction, 'denied')}
                  style={{
                    flex: 1, padding: '10px 16px', background: 'rgba(255, 71, 87, 0.15)',
                    color: 'var(--accent-red)', border: '1px solid var(--accent-red)', borderRadius: 'var(--radius-sm)',
                    fontSize: 12, fontWeight: 800, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6
                  }}
                >
                  <XCircle size={14} /> Reject Proposal
                </button>
              </div>
            )}

          </div>
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: 250, border: '1px dashed var(--border)', borderRadius: 'var(--radius-lg)', color: 'var(--text-muted)' }}>
            Select an action from the list to review details.
          </div>
        )}

      </div>

      {/* Confirmation Modal */}
      {modalAction && (
        <div style={{
          position: 'fixed', inset: 0, zIndex: 1000,
          background: 'rgba(0,0,0,0.7)', backdropFilter: 'blur(4px)',
          display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20
        }}>
          <div className="animate-scale" style={{
            background: 'var(--bg-surface)', border: '1px solid var(--border)',
            borderRadius: 'var(--radius-lg)', width: '100%', maxWidth: 520,
            padding: 24, boxShadow: 'var(--dropdown-shadow)'
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <AlertTriangle size={22} color={modalAction.decision === 'approved' ? 'var(--accent-amber)' : 'var(--accent-red)'} />
              <h3 style={{ fontSize: 18, fontWeight: 800, color: 'var(--text-primary)' }}>
                Confirm {modalAction.decision === 'approved' ? 'Mitigation Authorization' : 'Action Rejection'}
              </h3>
            </div>

            <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.6, marginBottom: 16 }}>
              You are about to <b>{modalAction.decision.toUpperCase()}</b> action <b>{modalAction.item.action}</b> targeting <b>{modalAction.item.target}</b>.
              {modalAction.decision === 'approved' && (
                <div style={{ marginTop: 8, color: 'var(--accent-amber)', fontSize: 12 }}>
                  ⚠️ This will trigger automated perimeter firewall rules or endpoint isolation.
                </div>
              )}
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: 6 }}>
                Audit Log Reason / Comment:
              </label>
              <textarea
                value={decisionComment}
                onChange={e => setDecisionComment(e.target.value)}
                rows={3}
                style={{
                  width: '100%', background: 'var(--bg-elevated)', border: '1px solid var(--border)',
                  color: 'var(--text-primary)', borderRadius: 'var(--radius-sm)', padding: 10, fontSize: 12, outline: 'none'
                }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                onClick={() => setModalAction(null)}
                disabled={submitting}
                style={{
                  background: 'transparent', border: '1px solid var(--border)', color: 'var(--text-secondary)',
                  padding: '8px 16px', borderRadius: 'var(--radius-sm)', fontSize: 12, cursor: 'pointer'
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmDecision}
                disabled={submitting}
                style={{
                  background: modalAction.decision === 'approved' ? 'var(--accent-green)' : 'var(--accent-red)',
                  color: modalAction.decision === 'approved' ? '#000000' : '#ffffff',
                  border: 'none', padding: '8px 18px', borderRadius: 'var(--radius-sm)', fontSize: 12,
                  fontWeight: 800, cursor: 'pointer'
                }}
              >
                {submitting ? 'Applying...' : `Confirm ${modalAction.decision.toUpperCase()}`}
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}
