import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'

interface CertData {
  id: string
  common_name: string
  type: string
  ca_id: string
  not_after: string
  revoked_at?: string
  created_at: string
}

interface CAData {
  id: string
  name: string
  type: string
  not_after: string
}

interface AuditEntry {
  id: number
  timestamp: string
  action: string
  entity_type?: string
  details?: string
}

function Dashboard() {
  const [cas, setCAs] = useState<CAData[]>([])
  const [certs, setCerts] = useState<CertData[]>([])
  const [audits, setAudits] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    Promise.all([
      fetch('/api/ca').then(r => r.json()),
      fetch('/api/certificates').then(r => r.json()),
      fetch('/api/audit?limit=10').then(r => r.json()),
    ]).then(([casData, certsData, auditData]) => {
      setCAs(casData || [])
      setCerts(certsData || [])
      setAudits(auditData || [])
      setLoading(false)
    }).catch(() => setLoading(false))
  }, [])

  if (loading) return <div className="empty-state">Loading...</div>

  const now = new Date()
  const thirtyDays = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000)

  const rootCAs = cas.filter(c => c.type === 'root').length
  const intCAs = cas.filter(c => c.type === 'intermediate').length
  const activeCerts = certs.filter(c => !c.revoked_at && new Date(c.not_after) >= now).length
  const revokedCerts = certs.filter(c => c.revoked_at).length
  const expiredCerts = certs.filter(c => !c.revoked_at && new Date(c.not_after) < now).length
  const expiringSoon = certs.filter(c => !c.revoked_at && new Date(c.not_after) >= now && new Date(c.not_after) < thirtyDays).length
  const serverCerts = certs.filter(c => c.type === 'server').length
  const clientCerts = certs.filter(c => c.type === 'client').length

  // Certificates per CA
  const certsPerCA = cas.map(ca => ({
    name: ca.name,
    count: certs.filter(c => c.ca_id === ca.id).length,
  })).sort((a, b) => b.count - a.count)

  // Expiry timeline (next 90 days)
  const expiryTimeline = certs
    .filter(c => !c.revoked_at && new Date(c.not_after) >= now && new Date(c.not_after) < new Date(now.getTime() + 90 * 24 * 60 * 60 * 1000))
    .sort((a, b) => new Date(a.not_after).getTime() - new Date(b.not_after).getTime())
    .slice(0, 8)

  const formatAction = (action: string) => action.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase())

  return (
    <div>
      <h1 style={{ marginBottom: '1.5rem' }}>Dashboard</h1>

      {/* Stats Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
        <div className="card">
          <div style={{ fontSize: '2rem', fontWeight: '700', color: 'var(--primary)' }}>{cas.length}</div>
          <div style={{ color: 'var(--text-muted)' }}>Certificate Authorities</div>
          <div style={{ fontSize: '0.85rem', marginTop: '0.25rem', color: 'var(--text-muted)' }}>
            {rootCAs} Root, {intCAs} Intermediate
          </div>
        </div>
        <div className="card">
          <div style={{ fontSize: '2rem', fontWeight: '700', color: 'var(--success)' }}>{activeCerts}</div>
          <div style={{ color: 'var(--text-muted)' }}>Active Certificates</div>
          <div style={{ fontSize: '0.85rem', marginTop: '0.25rem', color: 'var(--text-muted)' }}>
            {serverCerts} Server, {clientCerts} Client
          </div>
        </div>
        <div className="card">
          <div style={{ fontSize: '2rem', fontWeight: '700', color: 'var(--danger)' }}>{revokedCerts}</div>
          <div style={{ color: 'var(--text-muted)' }}>Revoked</div>
          <div style={{ fontSize: '0.85rem', marginTop: '0.25rem', color: 'var(--text-muted)' }}>
            {expiredCerts} Expired
          </div>
        </div>
        <div className="card">
          <div style={{ fontSize: '2rem', fontWeight: '700', color: expiringSoon > 0 ? 'var(--warning)' : 'var(--success)' }}>{expiringSoon}</div>
          <div style={{ color: 'var(--text-muted)' }}>Expiring in 30 days</div>
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.5rem' }}>
        {/* Expiry Timeline */}
        <div className="card">
          <h3 style={{ marginBottom: '0.75rem' }}>Expiry Timeline (90 days)</h3>
          {expiryTimeline.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>No certificates expiring soon</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {expiryTimeline.map(cert => {
                const daysLeft = Math.ceil((new Date(cert.not_after).getTime() - now.getTime()) / (1000 * 60 * 60 * 24))
                return (
                  <div key={cert.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.5rem', background: 'var(--bg)', borderRadius: '4px' }}>
                    <div>
                      <div style={{ fontWeight: 500, fontSize: '0.9rem' }}>{cert.common_name}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>{new Date(cert.not_after).toLocaleDateString()}</div>
                    </div>
                    <span className={`badge ${daysLeft <= 7 ? 'badge-danger' : daysLeft <= 30 ? 'badge-warning' : 'badge-info'}`}>
                      {daysLeft}d
                    </span>
                  </div>
                )
              })}
            </div>
          )}
        </div>

        {/* Certificates per CA */}
        <div className="card">
          <h3 style={{ marginBottom: '0.75rem' }}>Certificates per CA</h3>
          {certsPerCA.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>No CAs created yet</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {certsPerCA.map((item, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <div style={{ flex: 1, fontSize: '0.9rem' }}>{item.name}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', minWidth: '120px' }}>
                    <div style={{
                      height: '8px',
                      borderRadius: '4px',
                      background: 'var(--primary)',
                      width: `${Math.max(4, (item.count / Math.max(...certsPerCA.map(c => c.count), 1)) * 80)}px`,
                      transition: 'width 0.3s',
                    }} />
                    <span style={{ fontSize: '0.85rem', fontWeight: 500 }}>{item.count}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
        {/* Recent Activity */}
        <div className="card">
          <h3 style={{ marginBottom: '0.75rem' }}>Recent Activity</h3>
          {audits.length === 0 ? (
            <div style={{ color: 'var(--text-muted)', fontSize: '0.9rem' }}>No activity yet</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {audits.map(a => (
                <div key={a.id} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '0.375rem 0', borderBottom: '1px solid var(--border)' }}>
                  <div>
                    <span className={`badge ${a.action.includes('create') || a.action.includes('issue') ? 'badge-success' : a.action.includes('revoke') || a.action.includes('delete') ? 'badge-danger' : 'badge-info'}`} style={{ fontSize: '0.7rem' }}>
                      {formatAction(a.action)}
                    </span>
                    {a.details && <span style={{ fontSize: '0.8rem', color: 'var(--text-muted)', marginLeft: '0.5rem' }}>{a.details.substring(0, 40)}{a.details.length > 40 ? '...' : ''}</span>}
                  </div>
                  <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {new Date(a.timestamp).toLocaleString()}
                  </span>
                </div>
              ))}
            </div>
          )}
          <Link to="/audit" style={{ display: 'inline-block', marginTop: '0.75rem', fontSize: '0.85rem' }}>View all activity</Link>
        </div>

        {/* Quick Actions */}
        <div className="card">
          <h3 style={{ marginBottom: '0.75rem' }}>Quick Actions</h3>
          <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap' }}>
            <Link to="/cas" className="btn btn-primary">Create CA</Link>
            <Link to="/certificates" className="btn btn-primary">Issue Certificate</Link>
            <Link to="/templates" className="btn btn-secondary">Templates</Link>
            <Link to="/csrs" className="btn btn-secondary">CSRs</Link>
            <Link to="/tools" className="btn btn-secondary">Tools</Link>
            <Link to="/settings" className="btn btn-secondary">Settings</Link>
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard
