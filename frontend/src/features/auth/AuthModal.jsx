import { useState } from 'react'
import { Shield, Lock, Mail, User, X, ShieldAlert, KeyRound, Eye, EyeOff, Sparkles } from 'lucide-react'
import { useAuth } from './AuthContext'
import { Link } from 'react-router-dom'

export default function AuthModal() {
  const { isAuthModalOpen, authMode, setAuthMode, closeAuth, login, signup } = useAuth()

  const [name, setName]               = useState('')
  const [email, setEmail]             = useState('')
  const [password, setPassword]       = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [role, setRole]               = useState('tier2')
  const [error, setError]             = useState('')
  const [loading, setLoading]         = useState(false)
  const [showPass, setShowPass]       = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)

  if (!isAuthModalOpen) return null

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')

    if (!email || !email.includes('@')) {
      setError('Please provide a valid SOC email address')
      return
    }
    if (!password || password.length < 6) {
      setError('Password must be at least 6 characters')
      return
    }

    if (authMode === 'signup') {
      if (!name.trim()) {
        setError('Please enter your full name / callsign')
        return
      }
      if (password !== confirmPassword) {
        setError('Passwords do not match — please re-enter')
        return
      }
      setLoading(true)
      try {
        await signup({ name, email, password, confirmPassword, role, portal: 'user' })
      } catch (err) {
        setError(err?.detail || err?.message || 'Registration failed — check your credentials')
      } finally {
        setLoading(false)
      }
    } else {
      setLoading(true)
      try {
        await login({ email, password, portal: 'user' })
      } catch (err) {
        setError(err?.detail || err?.message || 'Invalid credentials — password or email is incorrect')
      } finally {
        setLoading(false)
      }
    }
  }

  // Demo personas: only fill the fields, do NOT auto-submit
  function demoFill(demoRole, demoName, demoEmail, demoPass) {
    setName(demoName)
    setEmail(demoEmail)
    setPassword(demoPass)
    setConfirmPassword(demoPass)
    setRole(demoRole)
    setError('')
  }

  const inputStyle = {
    width: '100%', background: 'var(--bg-base)', border: '1px solid var(--border)',
    borderRadius: 'var(--radius-sm)', padding: '8px 36px 8px 30px', color: 'var(--text-primary)',
    fontSize: 12, fontFamily: 'var(--font-mono)', outline: 'none',
    transition: 'border-color 0.2s',
  }

  return (
    <div
      style={{
        position: 'fixed', inset: 0, zIndex: 9999,
        background: 'rgba(5, 8, 12, 0.82)', backdropFilter: 'blur(8px)',
        display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 20
      }}
      onClick={closeAuth}
    >
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

        {/* Tab Switcher */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--bg-elevated)' }}>
          {['login', 'signup'].map(mode => (
            <button
              key={mode}
              onClick={() => { setAuthMode(mode); setError('') }}
              style={{
                flex: 1, padding: '10px', fontSize: 12, fontWeight: authMode === mode ? 800 : 500,
                background: authMode === mode ? 'var(--bg-surface)' : 'transparent',
                color: authMode === mode ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                border: 'none', borderBottom: authMode === mode ? '2px solid var(--accent-cyan)' : '2px solid transparent',
                cursor: 'pointer'
              }}
            >
              {mode === 'login' ? 'Sign In (Login)' : 'Create Account (Sign Up)'}
            </button>
          ))}
        </div>

        {/* Form Body */}
        <form onSubmit={handleSubmit} style={{ padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 14 }}>

          {/* Error Box */}
          {error && (
            <div className="animate-slide" style={{
              background: 'rgba(255, 71, 87, 0.12)', border: '1px solid var(--accent-red)',
              borderRadius: 'var(--radius-sm)', padding: '8px 12px', fontSize: 11, color: 'var(--accent-red)',
              display: 'flex', alignItems: 'center', gap: 6
            }}>
              <ShieldAlert size={14} />
              <span>{error}</span>
            </div>
          )}

          {/* Name field (signup only) */}
          {authMode === 'signup' && (
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6 }}>
                Full Name / Callsign
              </label>
              <div style={{ position: 'relative' }}>
                <User size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input type="text" placeholder="e.g. Tariq Mansour" value={name}
                  onChange={e => setName(e.target.value)}
                  style={{ ...inputStyle, paddingRight: 12 }} />
              </div>
            </div>
          )}

          {/* Email */}
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6 }}>
              SOC Email Address
            </label>
            <div style={{ position: 'relative' }}>
              <Mail size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input type="email" placeholder="analyst@kopo.defense" value={email}
                onChange={e => setEmail(e.target.value)}
                style={{ ...inputStyle, paddingRight: 12 }} />
            </div>
          </div>

          {/* Password */}
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6 }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <Lock size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
              <input type={showPass ? 'text' : 'password'} placeholder="••••••••" value={password}
                onChange={e => setPassword(e.target.value)} style={inputStyle} />
              <button type="button" onClick={() => setShowPass(p => !p)} style={{
                position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
                background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2
              }}>
                {showPass ? <EyeOff size={12} /> : <Eye size={12} />}
              </button>
            </div>
          </div>

          {/* Confirm Password (signup only) */}
          {authMode === 'signup' && (
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6 }}>
                Confirm Password
              </label>
              <div style={{ position: 'relative' }}>
                <Lock size={13} style={{ position: 'absolute', left: 10, top: '50%', transform: 'translateY(-50%)', color: 'var(--text-muted)' }} />
                <input type={showConfirm ? 'text' : 'password'} placeholder="••••••••" value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)} style={{
                    ...inputStyle,
                    borderColor: confirmPassword && confirmPassword !== password ? 'var(--accent-red)' : 'var(--border)'
                  }} />
                <button type="button" onClick={() => setShowConfirm(p => !p)} style={{
                  position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', padding: 2
                }}>
                  {showConfirm ? <EyeOff size={12} /> : <Eye size={12} />}
                </button>
              </div>
              {confirmPassword && confirmPassword !== password && (
                <div style={{ fontSize: 10, color: 'var(--accent-red)', marginTop: 4 }}>Passwords do not match</div>
              )}
            </div>
          )}

          {/* Role Selector */}
          <div>
            <label style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6 }}>
              Analyst Role Clearance
            </label>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
              {[
                { id: 'tier1', label: 'Tier 1 Triage', color: 'var(--accent-cyan)' },
                { id: 'tier2', label: 'Tier 2 Forensics', color: 'var(--accent-purple)' },
              ].map(r => (
                <button type="button" key={r.id} onClick={() => setRole(r.id)}
                  style={{
                    padding: '7px 4px', fontSize: 11, fontFamily: 'var(--font-mono)', fontWeight: role === r.id ? 800 : 500,
                    borderRadius: 'var(--radius-sm)', border: `1px solid ${role === r.id ? r.color : 'var(--border)'}`,
                    background: role === r.id ? `${r.color}20` : 'var(--bg-base)',
                    color: role === r.id ? r.color : 'var(--text-secondary)', cursor: 'pointer'
                  }}>
                  {r.label}
                </button>
              ))}
            </div>
            <div style={{ marginTop: 6, fontSize: 10, color: 'var(--text-muted)' }}>
              Admin / SOC Lead? Use the{' '}
              <Link to="/login/admin" onClick={closeAuth}
                style={{ color: 'var(--accent-red)', fontWeight: 700, textDecoration: 'none' }}>
                Admin Portal →
              </Link>
            </div>
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={loading}
            style={{
              marginTop: 4, width: '100%', padding: '10px',
              background: loading ? 'var(--bg-elevated)' : 'var(--accent-cyan)',
              color: loading ? 'var(--text-muted)' : '#000000',
              border: 'none', borderRadius: 'var(--radius-sm)',
              fontSize: 12, fontWeight: 800, cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              transition: 'background 0.2s, color 0.2s'
            }}
          >
            <KeyRound size={14} />
            <span>
              {loading
                ? (authMode === 'login' ? 'Authenticating...' : 'Registering...')
                : (authMode === 'login' ? 'Authenticate & Enter Console' : 'Complete Registration')}
            </span>
          </button>

          {/* Demo Personas (fill only) */}
          <div style={{ borderTop: '1px solid var(--border)', paddingTop: 12, marginTop: 2 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: 8, display: 'flex', alignItems: 'center', gap: 5 }}>
              <Sparkles size={11} color="var(--accent-purple)" />
              <span>Quick Demo Fill (then press login):</span>
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 6 }}>
              <button type="button"
                onClick={() => demoFill('tier1', 'Triage Analyst', 'triage@kopo.defense', 'User@1234')}
                style={{ padding: '5px', fontSize: 9, background: 'var(--bg-base)', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 'var(--radius-sm)', cursor: 'pointer' }}>
                Demo Tier 1
              </button>
              <button type="button"
                onClick={() => demoFill('tier2', 'SOC Analyst', 'analyst@kopo.defense', 'User@1234')}
                style={{ padding: '5px', fontSize: 9, background: 'var(--bg-base)', border: '1px solid var(--border)', color: 'var(--text-secondary)', borderRadius: 'var(--radius-sm)', cursor: 'pointer' }}>
                Demo Tier 2
              </button>
            </div>
          </div>

        </form>
      </div>
    </div>
  )
}
