import { useState, useEffect, useCallback } from 'react'
import { BrowserRouter, Routes, Route } from 'react-router-dom'
import Sidebar from './components/Sidebar.jsx'
import Overview from './pages/Overview.jsx'
import Alerts from './pages/Alerts.jsx'
import Detect from './pages/Detect.jsx'
import Models from './pages/Models.jsx'
import UnknownDrift from './pages/UnknownDrift.jsx'
import AgentApprovals from './pages/AgentApprovals.jsx'
import System from './pages/System.jsx'
import { AuthProvider } from './features/auth/AuthContext.jsx'
import AuthModal from './features/auth/AuthModal.jsx'
import { api } from './lib/api/client.ts'
import { AlertTriangle } from 'lucide-react'

export default function App() {
  const [engineReady, setEngineReady] = useState(false)
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('kopo_theme') || 'dark'
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('kopo_theme', theme)
  }, [theme])

  const toggleTheme = useCallback(() => {
    setTheme(prev => (prev === 'dark' ? 'light' : 'dark'))
  }, [])

  const checkHealth = useCallback(async () => {
    try {
      const data = await api.health()
      setEngineReady(data.status === 'ok')
    } catch {
      setEngineReady(false)
    }
  }, [])

  useEffect(() => {
    checkHealth()
    const t = setInterval(checkHealth, 15000)
    return () => clearInterval(t)
  }, [checkHealth])

  const isMock = api.isMock

  return (
    <AuthProvider>
      <BrowserRouter>
        <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: 'var(--bg-base)' }}>
          <Sidebar engineReady={engineReady} theme={theme} toggleTheme={toggleTheme} />
          
          <main style={{ flex: 1, overflowY: 'auto', background: 'var(--bg-base)', position: 'relative' }}>
            {/* Top Mock Mode Indicator Banner */}
            {isMock && (
              <div style={{
                background: 'rgba(240, 165, 0, 0.15)',
                borderBottom: '1px solid rgba(240, 165, 0, 0.4)',
                color: 'var(--accent-amber)',
                padding: '6px 20px',
                fontSize: 11,
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 8,
                position: 'sticky',
                top: 0,
                zIndex: 50,
                backdropFilter: 'blur(4px)'
              }}>
                <AlertTriangle size={13} />
                <span>MOCK ADAPTER ACTIVE (VITE_USE_MOCK=true) · Running on realistic seeded telemetry dataset</span>
              </div>
            )}

            <Routes>
              <Route path="/"            element={<Overview />} />
              <Route path="/alerts"      element={<Alerts />} />
              <Route path="/alerts/:id"  element={<Alerts />} />
              <Route path="/detect"      element={<Detect />} />
              <Route path="/unknown"     element={<UnknownDrift />} />
              <Route path="/approvals"   element={<AgentApprovals />} />
              <Route path="/models"      element={<Models />} />
              <Route path="/system"      element={<System />} />
            </Routes>
          </main>
        </div>
        <AuthModal />
      </BrowserRouter>
    </AuthProvider>
  )
}
