import { useState, useEffect } from 'react'

interface AuditEntry {
  id: number
  timestamp: string
  action: string
  entity_type?: string
  entity_id?: string
  user_id?: string
  details?: string
}

function AuditLog() {
  const [logs, setLogs] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/audit?limit=100')
      .then(r => r.json())
      .then(data => {
        setLogs(data || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }, [])

  const formatAction = (action: string) => {
    return action
      .replace(/_/g, ' ')
      .replace(/\b\w/g, l => l.toUpperCase())
  }

  return (
    <div>
      <h1 style={{ marginBottom: '1.5rem' }}>Audit Log</h1>

      {loading ? (
        <div className="empty-state">Loading...</div>
      ) : logs.length === 0 ? (
        <div className="card empty-state">
          <p>No audit entries yet.</p>
        </div>
      ) : (
        <div className="card">
          <table className="table">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Action</th>
                <th>Entity</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {logs.map(log => (
                <tr key={log.id}>
                  <td style={{ whiteSpace: 'nowrap' }}>
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td>
                    <span className={`badge ${
                      log.action.includes('create') ? 'badge-success' :
                      log.action.includes('revoke') ? 'badge-danger' :
                      'badge-info'
                    }`}>
                      {formatAction(log.action)}
                    </span>
                  </td>
                  <td>
                    {log.entity_type && (
                      <span style={{ textTransform: 'capitalize' }}>{log.entity_type}</span>
                    )}
                    {log.entity_id && (
                      <span style={{ color: 'var(--text-muted)', fontSize: '0.75rem', marginLeft: '0.5rem' }}>
                        {log.entity_id.substring(0, 8)}...
                      </span>
                    )}
                  </td>
                  <td style={{ color: 'var(--text-muted)' }}>{log.details}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

export default AuditLog
