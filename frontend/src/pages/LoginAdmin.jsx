import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { ShieldCheck, Lock, Mail, User, Eye, EyeOff, KeyRound, ShieldAlert, Hash } from 'lucide-react'
import { useAuth } from '../features/auth/AuthContext'

export default function LoginAdmin() {
  const { login, signup } = useAuth()
  const navigate = useNavigate()

  const [mode, setMode]               = useState('login')
  const [name, setName]               = useState('')
  const [email, setEmail]             = useState('')
  const [password, setPassword]       = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [inviteCode, setInviteCode]   = useState('')
  const [error, setError]             = useState('')
  const [loading, setLoading]         = useState(false)
  const [showPass, setShowPass]       = useState(false)
  const [showConfirm, setShowConfirm] = useState(false)
  const [showInvite, setShowInvite]   = useState(false)

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
        if (!inviteCode.trim())       { setError('Admin invite code is required'); setLoading(false); return }
        await signup({ name, email, password, confirmPassword, role: 'admin', portal: 'admin', inviteCode })
      } else {
        await login({ email, password, portal: 'admin' })
      }
      navigate('/')
    } catch (err) {
      setError(err?.detail || err?.message || 'Authentication failed — invalid credentials or insufficient clearance')
    } finally {
      setLoading(false)
    }
  }

  const inputBase = {
    width: '100%', background: 'rgba(0,0,0,0.4)',
    border: '1px solid rgba(255,71,87,0.2)', borderRadius: 8,
    padding: '10px 36px 10px 36px', color: '#e6edf3',
    fontSize: 13, fontFamily: "'JetBrains Mono', monospace", outline: 'none',
    transition: 'border-color 0.2s',
  }

  return (
    <div style={{
      minHeight: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center',
      background: 'radial-gradient(ellipse 80% 60% at 50% 10%, rgba(255,71,87,0.07) 0%, #05080c 60%)',
      fontFamily: "'Inter', sans-serif", padding: 20
    }}>
      {/* Background grid */}
      <div style={{
        position: 'fixed', inset: 0, zIndex: 0,
        backgroundImage: 'linear-gradient(rgba(255,71,87,0.03) 1px, transparent 1px), linear-gradient(90deg, rgba(255,71,87,0.03) 1px, transparent 1px)',
        backgroundSize: '40px 40px', pointerEvents: 'none'
      }} />

      <div className="animate-scale" style={{
        position: 'relative', zIndex: 1,
        width: '100%', maxWidth: 420,
        background: 'rgba(10,13,18,0.97)', border: '1px solid rgba(255,71,87,0.25)',
        borderRadius: 16, boxShadow: '0 24px 64px rgba(0,0,0,0.7), 0 0 0 1px rgba(255,71,87,0.05)',
        overflow: 'hidden'
      }}>
        {/* Top accent bar — red */}
        <div style={{ height: 3, background: 'linear-gradient(90deg, transparent, #ff4757, transparent)' }} />

        {/* Warning strip */}
        <div style={{
          background: 'rgba(255,71,87,0.08)', borderBottom: '1px solid rgba(255,71,87,0.15)',
          padding: '7px 20px', display: 'flex', alignItems: 'center', justifyContent: 'center',
          gap: 8, fontSize: 10, fontWeight: 700, color: 'rgba(255,71,87,0.8)',
          letterSpacing: '0.08em'
        }}>
          ⚠ RESTRICTED ACCESS — ADMIN PORTAL ONLY
        </div>

        {/* Header */}
        <div style={{ padding: '24px 32px 18px', textAlign: 'center', borderBottom: '1px solid rgba(48,54,61,0.4)' }}>
          <div style={{
            width: 52, height: 52, borderRadius: 14,
            background: 'rgba(255,71,87,0.12)', border: '1px solid rgba(255,71,87,0.3)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
            color: '#ff4757', margin: '0 auto 14px', boxShadow: '0 0 24px rgba(255,71,87,0.15)'
          }}>
            <ShieldCheck size={26} />
          </div>
          <div style={{ fontSize: 20, fontWeight: 900, color: '#e6edf3', letterSpacing: '0.04em' }}>
            KOPO SOC // ADMIN
          </div>
          <div style={{ fontSize: 12, color: '#484f58', marginTop: 4 }}>
            Administrator &amp; SOC Lead Credential Vault
          </div>
        </div>

        {/* Tab Switcher */}
        <div style={{ display: 'flex', background: 'rgba(10,13,18,0.8)' }}>
          {[['login', 'Admin Sign In'], ['signup', 'Register Admin']].map(([m, label]) => (
            <button key={m} onClick={() => { setMode(m); setError('') }}
              style={{
                flex: 1, padding: '11px', fontSize: 12, fontWeight: mode === m ? 800 : 500,
                background: mode === m ? 'rgba(255,71,87,0.08)' : 'transparent',
                color: mode === m ? '#ff4757' : '#484f58',
                border: 'none', borderBottom: mode === m ? '2px solid #ff4757' : '2px solid transparent',
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
                Full Name / Designation
              </label>
              <div style={{ position: 'relative' }}>
                <User size={13} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#484f58' }} />
                <input type="text" placeholder="e.g. Dr. Ziad Al-Rashid" value={name}
                  onChange={e => setName(e.target.value)} style={{ ...inputBase, paddingRight: 12 }} />
              </div>
            </div>
          )}

          <div>
            <label style={{ fontSize: 11, color: '#484f58', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6, letterSpacing: '0.08em' }}>
              Admin Email
            </label>
            <div style={{ position: 'relative' }}>
              <Mail size={13} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#484f58' }} />
              <input type="email" placeholder="admin@kopo.defense" value={email}
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
            <>
              <div>
                <label style={{ fontSize: 11, color: '#484f58', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6, letterSpacing: '0.08em' }}>
                  Confirm Password
                </label>
                <div style={{ position: 'relative' }}>
                  <Lock size={13} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#484f58' }} />
                  <input type={showConfirm ? 'text' : 'password'} placeholder="••••••••" value={confirmPassword}
                    onChange={e => setConfirmPassword(e.target.value)}
                    style={{ ...inputBase, borderColor: confirmPassword && confirmPassword !== password ? 'rgba(255,71,87,0.6)' : 'rgba(255,71,87,0.2)' }} />
                  <button type="button" onClick={() => setShowConfirm(p => !p)} style={{
                    position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer', color: '#484f58', padding: 2
                  }}>
                    {showConfirm ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                </div>
              </div>

              <div>
                <label style={{ fontSize: 11, color: '#484f58', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: 6, letterSpacing: '0.08em' }}>
                  Admin Invite Code <span style={{ color: '#ff4757' }}>*</span>
                </label>
                <div style={{ position: 'relative' }}>
                  <Hash size={13} style={{ position: 'absolute', left: 12, top: '50%', transform: 'translateY(-50%)', color: '#484f58' }} />
                  <input type={showInvite ? 'text' : 'password'} placeholder="KOPO-ADMIN-XXXX" value={inviteCode}
                    onChange={e => setInviteCode(e.target.value)} style={inputBase} />
                  <button type="button" onClick={() => setShowInvite(p => !p)} style={{
                    position: 'absolute', right: 10, top: '50%', transform: 'translateY(-50%)',
                    background: 'none', border: 'none', cursor: 'pointer', color: '#484f58', padding: 2
                  }}>
                    {showInvite ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                </div>
                <div style={{ fontSize: 10, color: '#484f58', marginTop: 4 }}>
                  Provided by your SOC Director. Required for admin registration.
                </div>
              </div>
            </>
          )}

          <button type="submit" disabled={loading}
            style={{
              width: '100%', padding: '12px',
              background: loading ? 'rgba(255,71,87,0.3)' : 'linear-gradient(135deg, #ff4757, #c0392b)',
              color: '#fff', border: 'none', borderRadius: 8,
              fontSize: 13, fontWeight: 800, cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 8,
              boxShadow: loading ? 'none' : '0 4px 20px rgba(255,71,87,0.3)',
              transition: 'all 0.2s', marginTop: 4
            }}>
            <KeyRound size={15} />
            {loading
              ? (mode === 'login' ? 'Verifying...' : 'Registering...')
              : (mode === 'login' ? 'Enter Admin Console' : 'Create Admin Account')}
          </button>

          <div style={{ textAlign: 'center', fontSize: 11, color: '#484f58', paddingTop: 4 }}>
            Analyst / Operator?{' '}
            <Link to="/login/user" style={{ color: '#00d4ff', fontWeight: 700, textDecoration: 'none' }}>
              Use Operator Portal →
            </Link>
          </div>
        </form>
      </div>
    </div>
  )
}
