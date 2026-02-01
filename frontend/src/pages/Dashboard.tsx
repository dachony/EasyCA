import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

interface Stats {
  totalCAs: number
  rootCAs: number
  intermediateCAs: number
  totalCerts: number
  activeCerts: number
  revokedCerts: number
  expiringSoon: number
}

function Dashboard() {
  const [stats, setStats] = useState<Stats>({
    totalCAs: 0,
    rootCAs: 0,
    intermediateCAs: 0,
    totalCerts: 0,
    activeCerts: 0,
    revokedCerts: 0,
    expiringSoon: 0,
  })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      fetch('/api/ca').then(r => r.json()),
      fetch('/api/certificates').then(r => r.json()),
    ]).then(([cas, certs]) => {
      const now = new Date()
      const thirtyDays = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000)

      setStats({
        totalCAs: cas?.length || 0,
        rootCAs: cas?.filter((c: { type: string }) => c.type === 'root').length || 0,
        intermediateCAs: cas?.filter((c: { type: string }) => c.type === 'intermediate').length || 0,
        totalCerts: certs?.length || 0,
        activeCerts: certs?.filter((c: { revoked_at: string | null }) => !c.revoked_at).length || 0,
        revokedCerts: certs?.filter((c: { revoked_at: string | null }) => c.revoked_at).length || 0,
        expiringSoon: certs?.filter((c: { not_after: string; revoked_at: string | null }) =>
          !c.revoked_at && new Date(c.not_after) < thirtyDays
        ).length || 0,
      })
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  if (loading) {
    return <div className="empty-state">Loading...</div>
  }

  return (
    <div>
      <h1 style={{ marginBottom: '1.5rem' }}>Dashboard</h1>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem', marginBottom: '2rem' }}>
        <div className="card">
          <div style={{ fontSize: '2rem', fontWeight: '700', color: 'var(--primary)' }}>{stats.totalCAs}</div>
          <div style={{ color: 'var(--text-muted)' }}>Certificate Authorities</div>
          <div style={{ fontSize: '0.875rem', marginTop: '0.5rem' }}>
            {stats.rootCAs} Root, {stats.intermediateCAs} Intermediate
          </div>
        </div>

        <div className="card">
          <div style={{ fontSize: '2rem', fontWeight: '700', color: 'var(--success)' }}>{stats.activeCerts}</div>
          <div style={{ color: 'var(--text-muted)' }}>Active Certificates</div>
        </div>

        <div className="card">
          <div style={{ fontSize: '2rem', fontWeight: '700', color: 'var(--danger)' }}>{stats.revokedCerts}</div>
          <div style={{ color: 'var(--text-muted)' }}>Revoked Certificates</div>
        </div>

        <div className="card">
          <div style={{ fontSize: '2rem', fontWeight: '700', color: 'var(--warning)' }}>{stats.expiringSoon}</div>
          <div style={{ color: 'var(--text-muted)' }}>Expiring in 30 days</div>
        </div>
      </div>

      <div className="card">
        <h2 className="card-title" style={{ marginBottom: '1rem' }}>Quick Actions</h2>
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          <Link to="/cas" className="btn btn-primary">Create CA</Link>
          <Link to="/certificates" className="btn btn-primary">Issue Certificate</Link>
          <Link to="/audit" className="btn btn-secondary">View Audit Log</Link>
        </div>
      </div>
    </div>
  )
}

export default Dashboard
