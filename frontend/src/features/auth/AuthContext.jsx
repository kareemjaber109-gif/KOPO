import { createContext, useContext, useState, useEffect } from 'react'
import { api } from '../../lib/api/client.ts'

const AuthContext = createContext(null)

const DEFAULT_USER = {
  id: 'analyst_ahmed',
  name: 'Ahmed K. (Tier 2 Analyst)',
  email: 'analyst@kopo.defense',
  role: 'tier2', // 'tier1' | 'tier2' | 'admin'
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      if (localStorage.getItem('kopo_auth_logged_out') === 'true') {
        return null
      }
      const stored = localStorage.getItem('kopo_auth_user')
      return stored ? JSON.parse(stored) : DEFAULT_USER
    } catch {
      return DEFAULT_USER
    }
  })

  const [token, setToken] = useState(() => {
    try {
      return localStorage.getItem('kopo_auth_token') || null
    } catch {
      return null
    }
  })

  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false)
  const [authMode, setAuthMode] = useState('login') // 'login' | 'signup'

  useEffect(() => {
    try {
      if (user) {
        localStorage.setItem('kopo_auth_user', JSON.stringify(user))
        localStorage.removeItem('kopo_auth_logged_out')
      } else {
        localStorage.removeItem('kopo_auth_user')
      }
    } catch {
      // ignore storage errors
    }
  }, [user])

  useEffect(() => {
    try {
      if (token) {
        localStorage.setItem('kopo_auth_token', token)
      } else {
        localStorage.removeItem('kopo_auth_token')
      }
    } catch {
      // ignore storage errors
    }
  }, [token])

  // Verify existing bearer token with backend on startup if present
  useEffect(() => {
    if (!token) return
    let cancelled = false
    api.authMe(token)
      .then(freshUser => {
        if (!cancelled && freshUser) {
          setUser(freshUser)
        }
      })
      .catch(err => {
        if (!cancelled && err && typeof err.status === 'number' && err.status === 401) {
          setUser(null)
          setToken(null)
        }
      })
    return () => { cancelled = true }
  }, [])

  async function login({ email, password, portal = 'user' }) {
    const res = await api.authLogin({ email, password, portal })
    setUser(res.user)
    setToken(res.token)
    setIsAuthModalOpen(false)
    return res
  }

  async function signup({
    name,
    email,
    password,
    confirmPassword,
    role = 'tier1',
    portal = 'user',
    inviteCode,
  }) {
    const res = await api.authRegister({
      name,
      email,
      password,
      confirm_password: confirmPassword,
      role,
      portal,
      invite_code: inviteCode,
    })
    setUser(res.user)
    setToken(res.token)
    setIsAuthModalOpen(false)
    return res
  }

  function logout() {
    try {
      localStorage.setItem('kopo_auth_logged_out', 'true')
    } catch {
      // ignore
    }
    setUser(null)
    setToken(null)
  }

  function openAuth(mode = 'login') {
    setAuthMode(mode)
    setIsAuthModalOpen(true)
  }

  function closeAuth() {
    setIsAuthModalOpen(false)
  }

  const isAdmin = Boolean(user && (user.role === 'admin' || user.role === 'lead'))

  return (
    <AuthContext.Provider value={{
      user,
      token,
      isAdmin,
      login,
      signup,
      logout,
      isAuthModalOpen,
      authMode,
      setAuthMode,
      openAuth,
      closeAuth,
    }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
