import { useState } from 'react'
import { Shield, Lock, Mail, User, Check, X, ShieldAlert, KeyRound, Sparkles } from 'lucide-react'
import { useAuth } from './AuthContext'

export default function AuthModal() {
  const { isAuthModalOpen, authMode, setAuthMode, closeAuth, login, signup, user } = useAuth()
  
  const [name, setName] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState('tier2')
  const [error, setError] = useState('')

  if (!isAuthModalOpen) return null

  function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (!email || !email.includes('@')) {
      setError('Please provide a valid SOC email address')
      return
    }
    if (!password || password.length < 4) {
      setError('Password must be at least 4 characters')
      return
    }

    if (authMode === 'signup') {
      if (!name.trim()) {
        setError('Please enter your full name / callsign')
        return
      }
      signup(name, email, password, role)
    } else {
      login(email, password, role, name)
    }
  }

  function demoFill(demoRole, demoName, demoEmail) {
    setName(demoName)
    setEmail(demoEmail)
    setPassword('demopass123')
    setRole(demoRole)
    if (authMode === 'signup') {
      signup(demoName, demoEmail, 'demopass123', demoRole)
    } else {
      login(demoEmail, 'demopass123', demoRole, demoName)
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      background: 'rgba(5, 8, 12, 0.78)', backdropFilter: 'blur(6px)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20
    }} onClick={closeAuth}>
      
      <div
        className="animate-scale"
        style={{
          width: '100%', maxWidth: 440,
          background: 'var(--bg-surface)', border: '1px solid var(--border)',
          borderRadius: 'var(--radius-lg)', boxShadow: 'var(--dropdown-shadow)',
          overflow: 'hidden'
        }}
        onClick={e => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div style={{
          display: 'flex', justifyContent: 'space-between', alignItems: 'center',
          padding: '16px 20px', borderBottom: '1px solid var(--border)', background: 'var(--bg-elevated)'
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{
              width: 32, height: 32, borderRadius: 'var(--radius-sm)',
              background: 'rgba(0, 212, 255, 0.15)', border: '1px solid rgba(0, 212, 255, 0.35)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', color: 'var(--accent-cyan)'
            }}>
              <Shield size={18} />
            </div>
            <div>
              <div style={{ fontSize: 13, fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '0.04em' }}>
                KOPO IDS // OPERATOR AUTH
              </div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                {authMode === 'login' ? 'Sign in to access SOC Sentinel console' : 'Register new analyst credential'}
              </div>
            </div>
          </div>

          <button onClick={closeAuth} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 4 }}>
            <X size={16} />
          </button>
        </div>

        {/* Tab Switcher: Sign In vs Sign Up */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--bg-elevated)' }}>
          <button
            onClick={() => { setAuthMode('login'); setError('') }}
            style={{
              flex: 1, padding: '10px', fontSize: 12, fontWeight: authMode === 'login' ? 800 : 500,
              background: authMode === 'login' ? 'var(--bg-surface)' : 'transparent',
              color: authMode === 'login' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              border: 'none', borderBottom: authMode === 'login' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
              cursor: 'pointer'
            }}
          >
            Sign In (Login)
          </button>
          <button
            onClick={() => { setAuthMode('signup'); setError('') }}
            style={{
              flex: 1, padding: '10px', fontSize: 12, fontWeight: authMode === 'signup' ? 800 : 500,
              background: authMode === 'signup' ? 'var(--bg-surface)' : 'transparent',
              color: authMode === 'signup' ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              border: 'none', borderBottom: authMode === 'signup' ? '2px solid var(--accent-cyan)' : '2px solid transparent',
              cursor: 'pointer'
            }}
          >
            Create Account (Sign Up)
          </button>
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 14 }}>
          
          {error && (
            <div style={{
              background: 'rgba(255, 71, 87, 0.12)', border: '1px solid var(--accent-red)',
              borderRadius: 'var(--radius-sm)', padding: '8px 12px', fontSize: 11, color: 'var(--accent-red)',
              display: 'flex', alignItems: 'center', gap: 6
            }}>
              <ShieldAlert size={14} />
              <span>{error}</span>
            </div>
          )}

          {authMode === 'signup' && (
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6 }}>
                Full Name / Callsign
              </label>
              <div style={{ position: 'relative' }}>
                <User size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input
                  type="text"
                  placeholder="e.g. Tariq Mansour"
                  value={name}
                  onChange={e => setName(e.target.value)}
                  style={{
                    width: '100%', background: 'var(--bg-base)', border: '1px solid var(--border)',
                    borderRadius: 'var(--radius-sm)', padding: '8px 12px 8px 30px', color: 'var(--text-primary)',
                    fontSize: 12, fontFamily: 'var(--font-mono)', outline: 'none'
                  }}
                />
              </div>
            </div>
          )}

          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6 }}>
              SOC Email Address
            </label>
            <div style={{ position: 'relative' }}>
              <Mail size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="email"
                placeholder="analyst@kopo.defense"
                value={email}
                onChange={e => setEmail(e.target.value)}
                style={{
                  width: '100%', background: 'var(--bg-base)', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)', padding: '8px 12px 8px 30px', color: 'var(--text-primary)',
                  fontSize: 12, fontFamily: 'var(--font-mono)', outline: 'none'
                }}
              />
            </div>
          </div>

          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6 }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <Lock size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input
                type="password"
                placeholder="••••••••"
                value={password}
                onChange={e => setPassword(e.target.value)}
                style={{
                  width: '100%', background: 'var(--bg-base)', border: '1px solid var(--border)',
                  borderRadius: 'var(--radius-sm)', padding: '8px 12px 8px 30px', color: 'var(--text-primary)',
                  fontSize: 12, fontFamily: 'var(--font-mono)', outline: 'none'
                }}
              />
            </div>
          </div>

          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6 }}>
              Analyst Role Clearance
            </label>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6 }}>
              {[
                { id: 'tier1', label: 'Tier 1 Triage', color: 'var(--accent-cyan)' },
                { id: 'tier2', label: 'Tier 2 Forensics', color: 'var(--accent-purple)' },
                { id: 'lead', label: 'SOC Lead', color: 'var(--accent-red)' },
              ].map(r => (
                <button
                  type="button"
                  key={r.id}
                  onClick={() => setRole(r.id)}
                  style={{
                    padding: '7px 4px', fontSize: 10, fontFamily: 'var(--font-mono)', fontWeight: role === r.id ? 800 : 500,
                    borderRadius: 'var(--radius-sm)', border: `1px solid ${role === r.id ? r.color : 'var(--border)'}`,
                    background: role === r.id ? `${r.color}20` : 'var(--bg-base)',
                    color: role === r.id ? r.color : 'var(--text-secondary)',
                    cursor: 'pointer'
                  }}
                >
                  {r.label}
                </button>
              ))}
            </div>
          </div>

          <button
            type="submit"
            style={{
              marginTop: 4, width: '100%', padding: '10px', background: 'var(--accent-cyan)',
              color: '#000000', border: 'none', borderRadius: 'var(--radius-sm)',
              fontSize: 12, fontWeight: 800, cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6
            }}
          >
            <KeyRound size={14} />
            <span>{authMode === 'login' ? 'Authenticate & Enter Console' : 'Complete Registration'}</span>
          </button>

          {/* Quick Demo Fill Buttons */}
          <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12, marginTop: 4 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Sparkles size={11} color="var(--accent-purple)" />
              <span>One-Click Demo Personas:</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6 }}>
              <button
                type="button"
                onClick={() => demoFill('tier1', 'Layla S. (Triage)', 'layla.triage@kopo.defense')}
                style={{
                  padding: '5px', fontSize: 9, background: 'var(--bg-base)', border: '1px solid var(--border)',
                  color: 'var(--text-secondary)', borderRadius: 'var(--radius-sm)', cursor: 'pointer'
                }}
              >
                Demo Tier 1
              </button>
              <button
                type="button"
                onClick={() => demoFill('tier2', 'Ahmed K. (Forensics)', 'ahmed.soc@kopo.defense')}
                style={{
                  padding: '5px', fontSize: 9, background: 'var(--bg-base)', border: '1px solid var(--border)',
                  color: 'var(--text-secondary)', borderRadius: 'var(--radius-sm)', cursor: 'pointer'
                }}
              >
                Demo Tier 2
              </button>
              <button
                type="button"
                onClick={() => demoFill('lead', 'Dr. Ziad (Lead)', 'ziad.lead@kopo.defense')}
                style={{
                  padding: '5px', fontSize: 9, background: 'var(--bg-base)', border: '1px solid var(--border)',
                  color: 'var(--text-secondary)', borderRadius: 'var(--radius-sm)', cursor: 'pointer'
                }}
              >
                Demo Lead
              </button>
            </div>
          </div>

        </form>

      </div>

    </div>
  )
}
