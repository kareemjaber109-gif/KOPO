import { NavLink } from 'react-router-dom'
import {
  Shield,
  Activity,
  Bell,
  Zap,
  BarChart2,
  Radio,
  Server,
  ShieldCheck,
  Sun,
  Moon,
  GitBranch,
  CheckSquare,
  Cpu,
  LogIn,
  LogOut,
  User,
  Sliders
} from 'lucide-react'
import { useAuth } from '../features/auth/AuthContext'
import { api } from '../lib/api/client'

const NAV = [
  { to: '/',          icon: Activity,    label: 'SOC Overview' },
  { to: '/alerts',    icon: Bell,        label: 'Alert Queue' },
  { to: '/detect',    icon: Zap,         label: 'Live Detection' },
  { to: '/models',    icon: BarChart2,   label: 'Models Telemetry' },
  { to: '/unknown',   icon: GitBranch,   label: 'Unknown & Drift' },
  { to: '/approvals', icon: CheckSquare, label: 'Agent Approvals' },
  { to: '/system',    icon: Server,      label: 'System & Health' },
]

export default function Sidebar({ engineReady, theme = 'dark', toggleTheme }) {
  const { user, openAuth, logout } = useAuth()

  return (
    <aside style={{
      width: 240, minHeight: '100vh',
      background: 'var(--bg-surface)',
      borderRight: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column', flexShrink: 0,
      boxShadow: 'var(--card-shadow)',
      transition: 'background-color 0.2s ease, border-color 0.2s ease'
    }}>
      {/* Brand Header with KOPO Logo */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12,
        padding: '20px 18px 16px',
        borderBottom: '1px solid var(--border)',
      }}>
        <div style={{
          width: 42, height: 42, borderRadius: 10,
          background: 'linear-gradient(135deg, rgba(0, 212, 255, 0.25) 0%, rgba(189, 147, 249, 0.15) 100%)',
          border: '1px solid rgba(0, 212, 255, 0.4)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          boxShadow: '0 0 20px rgba(0, 212, 255, 0.25)',
          position: 'relative',
          flexShrink: 0
        }}>
          <Shield size={22} color="var(--accent-cyan)" />
          <div style={{
            position: 'absolute', bottom: -2, right: -2, width: 8, height: 8,
            borderRadius: '50%', background: engineReady ? 'var(--accent-green)' : 'var(--accent-amber)',
            boxShadow: `0 0 8px ${engineReady ? 'var(--accent-green)' : 'var(--accent-amber)'}`
          }} />
        </div>
        <div>
          <div style={{
            fontSize: 20, fontWeight: 900, letterSpacing: '0.06em',
            color: 'var(--text-primary)', display: 'flex', alignItems: 'center', gap: 6,
            lineHeight: 1.1
          }}>
            <span>KOPO</span>
            <span style={{
              fontSize: 9, padding: '1px 5px', borderRadius: 4,
              background: 'rgba(0, 212, 255, 0.15)', color: 'var(--accent-cyan)',
              border: '1px solid rgba(0, 212, 255, 0.3)', fontWeight: 800
            }}>IDS</span>
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-secondary)', letterSpacing: '0.04em', fontWeight: 600, marginTop: 3 }}>
            ThreatNet Console v1.2
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, padding: '14px 10px', display: 'flex', flexDirection: 'column', gap: 3, overflowY: 'auto' }}>
        <div style={{ fontSize: 9, color: 'var(--text-muted)', letterSpacing: '0.1em', textTransform: 'uppercase', padding: '0 10px 6px', fontWeight: 700 }}>
          SOC Navigation
        </div>

        {NAV.map(({ to, icon: Icon, label }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            style={({ isActive }) => ({
              display: 'flex', alignItems: 'center', gap: 11,
              padding: '9px 12px', textDecoration: 'none', fontSize: 12, borderRadius: 'var(--radius-md)',
              color: isActive ? 'var(--accent-cyan)' : 'var(--text-secondary)',
              background: isActive ? 'rgba(0,212,255,0.08)' : 'transparent',
              border: `1px solid ${isActive ? 'rgba(0,212,255,0.25)' : 'transparent'}`,
              fontWeight: isActive ? 800 : 500,
              transition: 'all 0.15s',
            })}
          >
            <Icon size={15} color="currentColor" />
            <span style={{ flex: 1 }}>{label}</span>
          </NavLink>
        ))}

        {/* Theme Mode Switcher */}
        <div style={{ padding: '0 4px', marginTop: 12 }}>
          <button
            onClick={toggleTheme}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '8px 12px', background: 'var(--bg-elevated)', border: '1px solid var(--border)',
              borderRadius: 'var(--radius-md)', color: 'var(--text-primary)', cursor: 'pointer',
              fontSize: 11, fontWeight: 600, transition: 'all 0.15s'
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              {theme === 'dark' ? <Moon size={14} color="#bd93f9" /> : <Sun size={14} color="#f0a500" />}
              <span>{theme === 'dark' ? 'Dark Matrix Mode' : 'Soft Light Mode'}</span>
            </div>
            <span style={{ fontSize: 9, color: 'var(--text-muted)', textTransform: 'uppercase' }}>Toggle</span>
          </button>
        </div>
      </nav>

      {/* Operator Auth Profile Footer */}
      <div style={{
        padding: '14px 16px', borderTop: '1px solid var(--border)', background: 'var(--bg-elevated)',
        display: 'flex', flexDirection: 'column', gap: 8
      }}>
        {user ? (
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <User size={13} color="var(--accent-cyan)" />
                <span style={{ fontSize: 11, fontWeight: 800, color: 'var(--text-primary)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                  {user.name}
                </span>
              </div>
              <button
                onClick={logout}
                title="Sign out"
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: 2 }}
              >
                <LogOut size={13} />
              </button>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
              <span style={{
                fontSize: 9, fontFamily: 'var(--font-mono)', padding: '2px 6px', borderRadius: 4,
                background: user.role === 'lead' ? 'rgba(255,71,87,0.18)' : user.role === 'tier2' ? 'rgba(189,147,249,0.18)' : 'rgba(0,212,255,0.18)',
                color: user.role === 'lead' ? 'var(--accent-red)' : user.role === 'tier2' ? 'var(--accent-purple)' : 'var(--accent-cyan)',
                fontWeight: 800
              }}>
                {user.role === 'lead' ? '👑 SOC Lead' : user.role === 'tier2' ? '⚡ Tier 2 Analyst' : '🛡️ Tier 1 Triage'}
              </span>

              <button
                onClick={() => openAuth('login')}
                style={{ background: 'none', border: 'none', color: 'var(--accent-cyan)', fontSize: 10, cursor: 'pointer', fontWeight: 600 }}
              >
                Switch
              </button>
            </div>
          </div>
        ) : (
          <button
            onClick={() => openAuth('login')}
            style={{
              width: '100%', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
              background: 'rgba(0, 212, 255, 0.15)', border: '1px solid var(--accent-cyan)',
              color: 'var(--accent-cyan)', padding: '8px', borderRadius: 'var(--radius-sm)',
              fontSize: 11, fontWeight: 700, cursor: 'pointer'
            }}
          >
            <LogIn size={13} />
            <span>Sign In / Sign Up</span>
          </button>
        )}

        {/* Engine & Mock status pill */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
          <span>Backend: {engineReady ? 'Live :8000' : 'Offline'}</span>
          {api.isMock && (
            <span style={{ color: 'var(--accent-amber)', fontWeight: 700 }}>MOCK ACTIVE</span>
          )}
        </div>
      </div>
    </aside>
  )
}
