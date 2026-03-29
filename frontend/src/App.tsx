import { useState, useEffect } from 'react'
import { Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import CAs from './pages/CAs'
import Certificates from './pages/Certificates'
import CSRs from './pages/CSRs'
import Tools from './pages/Tools'
import Learn from './pages/Learn'
import AuditLog from './pages/AuditLog'
import Templates from './pages/Templates'
import Settings from './pages/Settings'
import Login from './pages/Login'
import Users from './pages/Users'

// Set up global fetch interceptor for auth
const originalFetch = window.fetch
window.fetch = function(input: RequestInfo | URL, init?: RequestInit) {
  const token = localStorage.getItem('token')
  if (token) {
    init = init || {}
    const headers = new Headers(init.headers || {})
    if (!headers.has('Authorization')) {
      headers.set('Authorization', `Bearer ${token}`)
    }
    init.headers = headers
  }
  return originalFetch(input, init).then(response => {
    if (response.status === 401 && !String(input).includes('/api/auth/')) {
      localStorage.removeItem('token')
      localStorage.removeItem('user')
      window.location.reload()
    }
    return response
  })
}

interface UserInfo {
  id: string
  username: string
  role: string
  full_name: string
}

function App() {
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem('theme')
    return saved || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
  })

  const [token, setToken] = useState(() => localStorage.getItem('token') || '')
  const [user, setUser] = useState<UserInfo | null>(() => {
    const saved = localStorage.getItem('user')
    return saved ? JSON.parse(saved) : null
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  const handleLogin = (newToken: string, userData: UserInfo) => {
    localStorage.setItem('token', newToken)
    localStorage.setItem('user', JSON.stringify(userData))
    setToken(newToken)
    setUser(userData)
  }

  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    setToken('')
    setUser(null)
  }

  if (!token) {
    return <Login onLogin={handleLogin} />
  }

  const isAdmin = user?.role === 'admin'

  return (
    <div>
      <nav className="nav">
        <NavLink to="/" className="nav-brand">EasyCA</NavLink>
        <div className="nav-links">
          <NavLink to="/" className={({ isActive }) => isActive ? 'active' : ''}>Dashboard</NavLink>
          <NavLink to="/cas" className={({ isActive }) => isActive ? 'active' : ''}>Certificate Authorities</NavLink>
          <NavLink to="/certificates" className={({ isActive }) => isActive ? 'active' : ''}>Certificates</NavLink>
          <NavLink to="/csrs" className={({ isActive }) => isActive ? 'active' : ''}>CSRs</NavLink>
          <NavLink to="/templates" className={({ isActive }) => isActive ? 'active' : ''}>Templates</NavLink>
          <NavLink to="/tools" className={({ isActive }) => isActive ? 'active' : ''}>Tools</NavLink>
          <NavLink to="/learn" className={({ isActive }) => isActive ? 'active' : ''}>Learn</NavLink>
          <NavLink to="/audit" className={({ isActive }) => isActive ? 'active' : ''}>Audit Log</NavLink>
          {isAdmin && <NavLink to="/users" className={({ isActive }) => isActive ? 'active' : ''}>Users</NavLink>}
          <NavLink to="/settings" className={({ isActive }) => isActive ? 'active' : ''}>Settings</NavLink>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', textAlign: 'right' }}>
            <div style={{ fontWeight: 500, color: 'var(--text)' }}>{user?.full_name || user?.username}</div>
            <div style={{ textTransform: 'capitalize' }}>{user?.role}</div>
          </div>
          <button
            onClick={handleLogout}
            className="btn btn-secondary btn-sm"
            style={{ fontSize: '0.75rem', padding: '0.25rem 0.75rem' }}
          >
            Logout
          </button>
          <div
            className="theme-switch"
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.5rem',
              background: 'var(--card-bg)',
              padding: '0.25rem',
              borderRadius: '20px',
              border: '1px solid var(--border)',
              cursor: 'pointer',
              userSelect: 'none',
            }}
            onClick={() => setTheme(t => t === 'dark' ? 'light' : 'dark')}
          >
            <span
              style={{
                padding: '0.375rem 0.75rem',
                borderRadius: '16px',
                fontSize: '0.75rem',
                fontWeight: 500,
                background: theme === 'light' ? 'var(--primary)' : 'transparent',
                color: theme === 'light' ? 'white' : 'var(--text-muted)',
                transition: 'all 0.2s ease',
              }}
            >
              Light
            </span>
            <span
              style={{
                padding: '0.375rem 0.75rem',
                borderRadius: '16px',
                fontSize: '0.75rem',
                fontWeight: 500,
                background: theme === 'dark' ? 'var(--primary)' : 'transparent',
                color: theme === 'dark' ? 'white' : 'var(--text-muted)',
                transition: 'all 0.2s ease',
              }}
            >
              Dark
            </span>
          </div>
        </div>
      </nav>
      <main className="container">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/cas" element={<CAs />} />
          <Route path="/certificates" element={<Certificates />} />
          <Route path="/csrs" element={<CSRs />} />
          <Route path="/templates" element={<Templates />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/learn" element={<Learn />} />
          <Route path="/audit" element={<AuditLog />} />
          {isAdmin && <Route path="/users" element={<Users />} />}
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
