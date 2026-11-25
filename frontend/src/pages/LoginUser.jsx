import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Shield, Lock, Mail, User, Eye, EyeOff, KeyRound, ShieldAlert } from 'lucide-react'
import { useAuth } from '../features/auth/AuthContext'

export default function LoginUser() {
  const { login, signup } = useAuth()
  const navigate = useNavigate()

  const [mode, setMode]               = useState('login')
  const [name, setName]               = useState('')
  const [email, setEmail]             = useState('')
  const [password, setPassword]       = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [role, setRole]               = useState('tier2')
  const [error, setError]             = useState('')
  const [loading, setLoading]         = useState(false)
  const [showPass, setShowPass]       = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)

  async function handleSubmit(e) {
    e.preventDefault()
    setError('')
    if (!email.includes('@')) { setError('Please enter a valid email address'); return }
    if (password.length < 6)  { setError('Password must be at least 6 characters'); return }

    setLoading(true)
    try {
      if (mode === 'signup') {
        if (!name.trim())             { setError('Full name is required'); setLoading(false); return }
        if (password !== confirmPassword) { setError('Passwords do not match'); setLoading(false); return }
        await signup({ name, email, password, confirmPassword, role, portal: 'user' })
      } else {
        await login({ email, password, portal: 'user' })
      }
      navigate('/')
    } catch (err) {
      setError(err?.detail || err?.message || 'Authentication failed — check your credentials')
    } finally {
      setLoading(false)
    }
  }

  const inputBase = {
    width: '100%', background: 'rgba(0,0,0,0.3)',
    border: '1px solid rgba(0,212,255,0.2)', borderRadius: 8,
    padding: '10px 36px 10px 36px', color: '#e6edf3',
    fontSize: 13, fontFamily: "'JetBrains Mono', monospace", outline: 'none',
    transition: 'border-color 0.2s',
  }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'radial-gradient(ellipse 80% 60% at 50% 10%, rgba(0,212,255,0.08) 0%, #080c10 60%)',
      fontFamily: "'Inter', sans-serif", padding: 20
    }}>
      {/* Background grid pattern */}
      <div style={{
        position: 'fixed', inset: 0, zIndex: 0,
        backgroundImage: 'linear-gradient(rgba(0,212,255,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(0,212,255,0.03) 1px, transparent 1px)',
        backgroundSize: '40px 40px', pointerEvents: 'none'
      }} />

      <div className="animate-scale" style={{
        position: 'relative', zIndex: 1,
        width: '100%', maxWidth: 420,
        background: 'rgba(13,17,23,0.95)', border: '1px solid rgba(0,212,255,0.2)',
        borderRadius: 16, boxShadow: '0 24px 64px rgba(0,0,0,0.6), 0 0 0 1px rgba(0,212,255,0.05)',
        overflow: 'hidden'
      }}>
        {/* Top accent bar */}
        <div style={{ height: 3, background: 'linear-gradient(90deg, transparent, #00d4ff, transparent)' }} />

        {/* Header */}
        <div style={{ padding: '28px 32px 20px', textAlign: 'center', borderBottom: '1px solid rgba(48,54,61,0.6)' }}>
          <div style={{
            width: 52, height: 52, borderRadius: 14,
            background: 'rgba(0,212,255,0.12)', border: '1px solid rgba(0,212,255,0.3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: '#00d4ff', margin: '0 auto 14px', boxShadow: '0 0 24px rgba(0,212,255,0.15)'
          }}>
            <Shield size={26} />
          </div>
          <div style={{ fontSize: 20, fontWeight: 900, color: '#e6edf3', letterSpacing: '0.04em' }}>
            KOPO SOC // OPERATOR
          </div>
          <div style={{ fontSize: 12, color: '#484f58', marginTop: 4 }}>
            Analyst Portal — Tier 1 / Tier 2 Access
          </div>
        </div>

        {/* Tab Switcher */}
        <div style={{ display: 'flex', background: 'rgba(22,27,34,0.8)' }}>
          {[['login', 'Sign In'], ['signup', 'Register']].map(([m, label]) => (
            <button key={m} onClick={() => { setMode(m); setError('') }}
              style={{
                flex: 1, padding: '11px', fontSize: 12, fontWeight: mode === m ? 800 : 500,
                background: mode === m ? 'rgba(0,212,255,0.08)' : 'transparent',
                color: mode === m ? '#00d4ff' : '#484f58',
                border: 'none', borderBottom: mode === m ? '2px solid #00d4ff' : '2px solid transparent',
                cursor: 'pointer', transition: 'all 0.2s'
              }}>
              {label}
            </button>
          ))}
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} style={{ padding: '24px 32px', display: 'flex', flexDirection: 'column', gap: 16 }}>

          {error && (
            <div className="animate-slide" style={{
              background: 'rgba(255,71,87,0.1)', border: '1px solid rgba(255,71,87,0.4)',
              borderRadius: 8, padding: '10px 14px', fontSize: 12, color: '#ff4757',
              display: 'flex', alignItems: 'center', gap: 8
            }}>
              <ShieldAlert size={14} />
              <span>{error}</span>
            </div>
          )}

          {mode === 'signup' && (
            <div>
              <label style={{ fontSize: 11, color: '#484f58', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6, letterSpacing: '0.08em' }}>
                Full Name / Callsign
              </label>
              <div style={{ position: 'relative' }}>
                <User size={13} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#484f58' }} />
                <input type="text" placeholder="e.g. Tariq Mansour" value={name}
                  onChange={e => setName(e.target.value)} style={{ ...inputBase, paddingRight: 12 }} />
              </div>
            </div>
          )}

          <div>
            <label style={{ fontSize: 11, color: '#484f58', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6, letterSpacing: '0.08em' }}>
              SOC Email
            </label>
            <div style={{ position: 'relative' }}>
              <Mail size={13} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#484f58' }} />
              <input type="email" placeholder="analyst@kopo.defense" value={email}
                onChange={e => setEmail(e.target.value)} style={{ ...inputBase, paddingRight: 12 }} />
            </div>
          </div>

          <div>
            <label style={{ fontSize: 11, color: '#484f58', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6, letterSpacing: '0.08em' }}>
              Password
            </label>
            <div style={{ position: 'relative' }}>
              <Lock size={13} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#484f58' }} />
              <input type={showPass ? 'text' : 'password'} placeholder="••••••••" value={password}
                onChange={e => setPassword(e.target.value)} style={inputBase} />
              <button type="button" onClick={() => setShowPass(p => !p)} style={{
                position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                background: 'none', border: 'none', cursor: 'pointer', color: '#484f58', padding: 2
              }}>
                {showPass ? <EyeOff size={13} /> : <Eye size={13} />}
              </button>
            </div>
          </div>

          {mode === 'signup' && (
            <div>
              <label style={{ fontSize: 11, color: '#484f58', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6, letterSpacing: '0.08em' }}>
                Confirm Password
              </label>
              <div style={{ position: 'relative' }}>
                <Lock size={13} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#484f58' }} />
                <input type={showConfirm ? 'text' : 'password'} placeholder="••••••••" value={confirmPassword}
                  onChange={e => setConfirmPassword(e.target.value)}
                  style={{ ...inputBase, borderColor: confirmPassword && confirmPassword !== password ? 'rgba(255,71,87,0.5)' : 'rgba(0,212,255,0.2)' }} />
                <button type="button" onClick={() => setShowConfirm(p => !p)} style={{
                  position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                  background: 'none', border: 'none', cursor: 'pointer', color: '#484f58', padding: 2
                }}>
                  {showConfirm ? <EyeOff size={13} /> : <Eye size={13} />}
                </button>
              </div>
            </div>
          )}

          {mode === 'signup' && (
            <div>
              <label style={{ fontSize: 11, color: '#484f58', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6, letterSpacing: '0.08em' }}>
                Role Level
              </label>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                {[{ id: 'tier1', label: '🔵 Tier 1 — Triage' }, { id: 'tier2', label: '🟣 Tier 2 — Forensics' }].map(r => (
                  <button type="button" key={r.id} onClick={() => setRole(r.id)}
                    style={{
                      padding: '8px', fontSize: 11, borderRadius: 8, cursor: 'pointer',
                      border: `1px solid ${role === r.id ? '#00d4ff' : 'rgba(48,54,61,0.8)'}`,
                      background: role === r.id ? 'rgba(0,212,255,0.1)' : 'rgba(0,0,0,0.3)',
                      color: role === r.id ? '#00d4ff' : '#8b949e', fontWeight: role === r.id ? 700 : 400,
                      transition: 'all 0.2s'
                    }}>
                    {r.label}
                  </button>
                ))}
              </div>
            </div>
          )}

          <button type="submit" disabled={loading}
            style={{
              width: '100%', padding: '12px',
              background: loading ? 'rgba(0,212,255,0.3)' : 'linear-gradient(135deg, #00d4ff, #0097b2)',
              color: '#000', border: 'none', borderRadius: 8,
              fontSize: 13, fontWeight: 800, cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              boxShadow: loading ? 'none' : '0 4px 20px rgba(0,212,255,0.3)',
              transition: 'all 0.2s', marginTop: 4
            }}>
            <KeyRound size={15} />
            {loading
              ? (mode === 'login' ? 'Authenticating...' : 'Registering...')
              : (mode === 'login' ? 'Authenticate & Enter Console' : 'Create Analyst Account')}
          </button>

          <div style={{ textAlign: 'center', fontSize: 11, color: '#484f58', paddingTop: 4 }}>
            Admin or SOC Lead?{' '}
            <Link to="/login/admin" style={{ color: '#ff4757', fontWeight: 700, textDecoration: 'none' }}>
              Use Admin Portal →
            </Link>
          </div>
        </form>
      </div>
    </div>
  )
}
