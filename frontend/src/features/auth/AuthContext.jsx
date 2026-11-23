import { createContext, useContext, useState, useEffect } from 'react'

const AuthContext = createContext(null)

const DEFAULT_USER = {
  id: 'analyst_ahmed',
  name: 'Ahmed K. (Tier 2 Analyst)',
  email: 'ahmed.soc@kopo.defense',
  role: 'tier2', // 'tier1' | 'tier2' | 'lead'
}

export function AuthProvider({ children }) {
  const [user, setUser] = useState(() => {
    try {
      const stored = localStorage.getItem('kopo_auth_user')
      return stored ? JSON.parse(stored) : DEFAULT_USER
    } catch {
      return DEFAULT_USER
    }
  })

  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false)
  const [authMode, setAuthMode] = useState('login') // 'login' | 'signup'

  useEffect(() => {
    try {
      if (user) {
        localStorage.setItem('kopo_auth_user', JSON.stringify(user))
      } else {
        localStorage.removeItem('kopo_auth_user')
      }
    } catch {
      // ignore
    }
  }, [user])

  function login(email, password, role = 'tier2', name = '') {
    const newUser = {
      id: `usr_${Date.now()}`,
      name: name || (email.split('@')[0] || 'Analyst'),
      email,
      role
    }
    setUser(newUser)
    setIsAuthModalOpen(false)
    return newUser
  }

  function signup(name, email, password, role = 'tier1') {
    const newUser = {
      id: `usr_${Date.now()}`,
      name,
      email,
      role
    }
    setUser(newUser)
    setIsAuthModalOpen(false)
    return newUser
  }

  function logout() {
    setUser(null)
  }

  function openAuth(mode = 'login') {
    setAuthMode(mode)
    setIsAuthModalOpen(true)
  }

  function closeAuth() {
    setIsAuthModalOpen(false)
  }

  return (
    <AuthContext.Provider value={{
      user,
      login,
      signup,
      logout,
      isAuthModalOpen,
      authMode,
      setAuthMode,
      openAuth,
      closeAuth
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
