import { useState } from 'react'

interface LoginProps {
  onLogin: (token: string, user: any) => void
}

function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [isSetup, setIsSetup] = useState(false)
  const [fullName, setFullName] = useState('')
  const [email, setEmail] = useState('')

  // Check if setup is needed on mount
  useState(() => {
    fetch('/api/auth/check')
      .then(r => r.json())
      .then(data => {
        if (data.setup_required) {
          setIsSetup(true)
        }
      })
      .catch(() => {})
  })

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      if (isSetup) {
        // Register first admin
        const regRes = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password, full_name: fullName, email }),
        })
        if (!regRes.ok) {
          const data = await regRes.json()
          throw new Error(data.error || 'Registration failed')
        }
      }

      // Login
      const res = await fetch('/api/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, password }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Login failed')
      }

      const data = await res.json()
      onLogin(data.token, data.user)
    } catch (err: any) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg)',
    }}>
      <div className="card" style={{ width: '100%', maxWidth: '420px', padding: '2rem' }}>
        <div style={{ textAlign: 'center', marginBottom: '2rem' }}>
          <h1 style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>EasyCA</h1>
          <p style={{ color: 'var(--text-muted)' }}>
            {isSetup ? 'Create your admin account' : 'Sign in to your account'}
          </p>
        </div>

        {error && <div className="alert alert-danger" style={{ marginBottom: '1rem' }}>{error}</div>}

        <form onSubmit={handleSubmit}>
          {isSetup && (
            <>
              <div className="form-group">
                <label>Full Name</label>
                <input
                  className="form-control"
                  value={fullName}
                  onChange={e => setFullName(e.target.value)}
                  placeholder="Your name"
                />
              </div>
              <div className="form-group">
                <label>Email</label>
                <input
                  type="email"
                  className="form-control"
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                  placeholder="admin@example.com"
                />
              </div>
            </>
          )}
          <div className="form-group">
            <label>Username</label>
            <input
              className="form-control"
              value={username}
              onChange={e => setUsername(e.target.value)}
              required
              autoFocus
              placeholder={isSetup ? 'Choose a username' : 'Username'}
            />
          </div>
          <div className="form-group">
            <label>Password</label>
            <input
              type="password"
              className="form-control"
              value={password}
              onChange={e => setPassword(e.target.value)}
              required
              minLength={isSetup ? 8 : undefined}
              placeholder={isSetup ? 'Min 8 characters' : 'Password'}
            />
          </div>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={loading}
            style={{ width: '100%', marginTop: '1rem' }}
          >
            {loading ? 'Please wait...' : isSetup ? 'Create Account & Login' : 'Sign In'}
          </button>
        </form>

        {!isSetup && (
          <p style={{ textAlign: 'center', marginTop: '1.5rem', color: 'var(--text-muted)', fontSize: '0.85rem' }}>
            Default: admin / admin123
          </p>
        )}
      </div>
    </div>
  )
}

export default Login
