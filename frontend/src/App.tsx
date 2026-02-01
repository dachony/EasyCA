import { useState, useEffect } from 'react'
import { Routes, Route, NavLink } from 'react-router-dom'
import Dashboard from './pages/Dashboard'
import CAs from './pages/CAs'
import Certificates from './pages/Certificates'
import CSRs from './pages/CSRs'
import Tools from './pages/Tools'
import Learn from './pages/Learn'
import AuditLog from './pages/AuditLog'
import Settings from './pages/Settings'

function App() {
  const [theme, setTheme] = useState(() => {
    const saved = localStorage.getItem('theme')
    return saved || (window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light')
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  return (
    <div>
      <nav className="nav">
        <NavLink to="/" className="nav-brand">EasyCA</NavLink>
        <div className="nav-links">
          <NavLink to="/" className={({ isActive }) => isActive ? 'active' : ''}>Dashboard</NavLink>
          <NavLink to="/cas" className={({ isActive }) => isActive ? 'active' : ''}>Certificate Authorities</NavLink>
          <NavLink to="/certificates" className={({ isActive }) => isActive ? 'active' : ''}>Certificates</NavLink>
          <NavLink to="/csrs" className={({ isActive }) => isActive ? 'active' : ''}>CSRs</NavLink>
          <NavLink to="/tools" className={({ isActive }) => isActive ? 'active' : ''}>Tools</NavLink>
          <NavLink to="/learn" className={({ isActive }) => isActive ? 'active' : ''}>Learn</NavLink>
          <NavLink to="/audit" className={({ isActive }) => isActive ? 'active' : ''}>Audit Log</NavLink>
          <NavLink to="/settings" className={({ isActive }) => isActive ? 'active' : ''}>Settings</NavLink>
        </div>
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
      </nav>
      <main className="container">
        <Routes>
          <Route path="/" element={<Dashboard />} />
          <Route path="/cas" element={<CAs />} />
          <Route path="/certificates" element={<Certificates />} />
          <Route path="/csrs" element={<CSRs />} />
          <Route path="/tools" element={<Tools />} />
          <Route path="/learn" element={<Learn />} />
          <Route path="/audit" element={<AuditLog />} />
          <Route path="/settings" element={<Settings />} />
        </Routes>
      </main>
    </div>
  )
}

export default App
