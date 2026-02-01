import { useState, useEffect } from 'react'

interface SMTPConfig {
  host: string
  port: number
  username: string
  from_address: string
  tls_enabled: boolean
  enabled: boolean
}

interface NotificationSettings {
  expiry_warning_days: string
  notify_on_issuance: boolean
  notify_on_revocation: boolean
}

interface Recipient {
  id: string
  email: string
  certificate_id?: string
  ca_id?: string
  is_global: boolean
  created_at: string
}

interface NotificationLog {
  id: number
  certificate_id?: string
  ca_id?: string
  notification_type: string
  recipient_email: string
  days_until_expiry?: number
  sent_at: string
  status: string
  error_message?: string
}

interface CA {
  id: string
  name: string
}

interface Certificate {
  id: string
  common_name: string
}

interface DefaultSettings {
  key_algorithm: string
  signature_algorithm: string
  validity_days_ca: number
  validity_days_cert: number
  organization: string
  organizational_unit: string
  country: string
  state: string
  locality: string
}

interface TimeSettings {
  time_source: 'host' | 'ntp' | 'manual'
  ntp_server: string
  timezone: string
  manual_time: string
  last_synced_at: string
}

interface CurrentTime {
  current_time: string
  timezone: string
  source: string
  unix: number
}

type FormStatus = { type: 'success' | 'error', message: string } | null

function Settings() {
  const [activeTab, setActiveTab] = useState<'smtp' | 'notifications' | 'recipients' | 'log' | 'defaults' | 'time' | 'backup'>('smtp')
  const [loading, setLoading] = useState(true)

  // Per-form status messages
  const [smtpStatus, setSmtpStatus] = useState<FormStatus>(null)
  const [smtpTestStatus, setSmtpTestStatus] = useState<FormStatus>(null)
  const [notificationStatus, setNotificationStatus] = useState<FormStatus>(null)
  const [recipientStatus, setRecipientStatus] = useState<FormStatus>(null)
  const [defaultsStatus, setDefaultsStatus] = useState<FormStatus>(null)
  const [timeStatus, setTimeStatus] = useState<FormStatus>(null)
  const [backupStatus, setBackupStatus] = useState<FormStatus>(null)

  // Backup state
  const [exportPassword, setExportPassword] = useState('')
  const [importPassword, setImportPassword] = useState('')
  const [importFile, setImportFile] = useState<File | null>(null)
  const [importData, setImportData] = useState('')
  const [backupLoading, setBackupLoading] = useState(false)

  // SMTP State
  const [smtpConfig, setSMTPConfig] = useState<SMTPConfig>({
    host: '',
    port: 587,
    username: '',
    from_address: '',
    tls_enabled: true,
    enabled: false,
  })
  const [smtpPassword, setSMTPPassword] = useState('')
  const [testEmail, setTestEmail] = useState('')

  // Notification Settings State
  const [notificationSettings, setNotificationSettings] = useState<NotificationSettings>({
    expiry_warning_days: '30,14,7',
    notify_on_issuance: true,
    notify_on_revocation: true,
  })

  // Recipients State
  const [recipients, setRecipients] = useState<Recipient[]>([])
  const [showAddRecipient, setShowAddRecipient] = useState(false)
  const [newRecipient, setNewRecipient] = useState({
    email: '',
    is_global: true,
    certificate_id: '',
    ca_id: '',
  })
  const [cas, setCAs] = useState<CA[]>([])
  const [certificates, setCertificates] = useState<Certificate[]>([])

  // Log State
  const [logs, setLogs] = useState<NotificationLog[]>([])

  // Default Settings State
  const [defaultSettings, setDefaultSettings] = useState<DefaultSettings>({
    key_algorithm: 'rsa2048',
    signature_algorithm: 'sha256',
    validity_days_ca: 3650,
    validity_days_cert: 365,
    organization: '',
    organizational_unit: '',
    country: '',
    state: '',
    locality: '',
  })

  // Time Settings State
  const [timeSettings, setTimeSettings] = useState<TimeSettings>({
    time_source: 'host',
    ntp_server: 'pool.ntp.org',
    timezone: 'UTC',
    manual_time: '',
    last_synced_at: '',
  })
  const [currentTime, setCurrentTime] = useState<CurrentTime | null>(null)

  useEffect(() => {
    fetchData()
  }, [])

  const fetchData = async () => {
    setLoading(true)
    try {
      const [smtpRes, settingsRes, recipientsRes, logsRes, casRes, certsRes, defaultsRes, timeRes, currentTimeRes] = await Promise.all([
        fetch('/api/settings/smtp'),
        fetch('/api/settings/notifications'),
        fetch('/api/recipients'),
        fetch('/api/notifications/log?limit=100'),
        fetch('/api/ca'),
        fetch('/api/certificates'),
        fetch('/api/settings/defaults'),
        fetch('/api/settings/time'),
        fetch('/api/settings/time/current'),
      ])

      const smtpData = await smtpRes.json()
      if (smtpData) {
        setSMTPConfig({
          host: smtpData.host || '',
          port: smtpData.port || 587,
          username: smtpData.username || '',
          from_address: smtpData.from_address || '',
          tls_enabled: smtpData.tls_enabled ?? true,
          enabled: smtpData.enabled ?? false,
        })
      }

      const settingsData = await settingsRes.json()
      if (settingsData) {
        setNotificationSettings(settingsData)
      }

      const recipientsData = await recipientsRes.json()
      setRecipients(recipientsData || [])

      const logsData = await logsRes.json()
      setLogs(logsData || [])

      const casData = await casRes.json()
      setCAs(casData || [])

      const certsData = await certsRes.json()
      setCertificates(certsData || [])

      const defaultsData = await defaultsRes.json()
      if (defaultsData) {
        setDefaultSettings({
          key_algorithm: defaultsData.key_algorithm || 'rsa2048',
          signature_algorithm: defaultsData.signature_algorithm || 'sha256',
          validity_days_ca: defaultsData.validity_days_ca || 3650,
          validity_days_cert: defaultsData.validity_days_cert || 365,
          organization: defaultsData.organization || '',
          organizational_unit: defaultsData.organizational_unit || '',
          country: defaultsData.country || '',
          state: defaultsData.state || '',
          locality: defaultsData.locality || '',
        })
      }

      try {
        const timeData = await timeRes.json()
        if (timeData) {
          setTimeSettings({
            time_source: timeData.time_source || 'host',
            ntp_server: timeData.ntp_server || 'pool.ntp.org',
            timezone: timeData.timezone || 'UTC',
            manual_time: timeData.manual_time || '',
            last_synced_at: timeData.last_synced_at || '',
          })
        }
      } catch {
        // Time settings not available yet
      }

      try {
        const currentTimeData = await currentTimeRes.json()
        if (currentTimeData) {
          setCurrentTime(currentTimeData)
        }
      } catch {
        // Current time not available
      }
    } catch {
      // Failed to load settings
    }
    setLoading(false)
  }

  // Auto-clear status after 3 seconds
  const setStatusWithAutoClear = (setter: (s: FormStatus) => void, status: FormStatus) => {
    setter(status)
    setTimeout(() => setter(null), 3000)
  }

  const saveSMTPConfig = async (e: React.FormEvent) => {
    e.preventDefault()
    setSmtpStatus(null)

    try {
      const res = await fetch('/api/settings/smtp', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...smtpConfig,
          password: smtpPassword,
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to save SMTP config')
      }

      setStatusWithAutoClear(setSmtpStatus, { type: 'success', message: 'Saved' })
      setSMTPPassword('')
    } catch (err) {
      setStatusWithAutoClear(setSmtpStatus, { type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const testSMTP = async () => {
    if (!testEmail) {
      setStatusWithAutoClear(setSmtpTestStatus, { type: 'error', message: 'Enter email address' })
      return
    }

    setSmtpTestStatus(null)

    try {
      const res = await fetch('/api/settings/smtp/test', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ to_email: testEmail }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to send test email')
      }

      setStatusWithAutoClear(setSmtpTestStatus, { type: 'success', message: 'Sent!' })
    } catch (err) {
      setStatusWithAutoClear(setSmtpTestStatus, { type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const saveNotificationSettings = async (e: React.FormEvent) => {
    e.preventDefault()
    setNotificationStatus(null)

    try {
      const res = await fetch('/api/settings/notifications', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(notificationSettings),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to save settings')
      }

      setStatusWithAutoClear(setNotificationStatus, { type: 'success', message: 'Saved' })
    } catch (err) {
      setStatusWithAutoClear(setNotificationStatus, { type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const addRecipient = async (e: React.FormEvent) => {
    e.preventDefault()
    setRecipientStatus(null)

    try {
      const body: Record<string, unknown> = {
        email: newRecipient.email,
        is_global: newRecipient.is_global,
      }

      if (!newRecipient.is_global) {
        if (newRecipient.ca_id) body.ca_id = newRecipient.ca_id
        if (newRecipient.certificate_id) body.certificate_id = newRecipient.certificate_id
      }

      const res = await fetch('/api/recipients', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to add recipient')
      }

      setShowAddRecipient(false)
      setNewRecipient({ email: '', is_global: true, certificate_id: '', ca_id: '' })
      fetchData()
      setStatusWithAutoClear(setRecipientStatus, { type: 'success', message: 'Added' })
    } catch (err) {
      setStatusWithAutoClear(setRecipientStatus, { type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const deleteRecipient = async (id: string) => {
    if (!confirm('Are you sure you want to delete this recipient?')) return

    try {
      const res = await fetch(`/api/recipients/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('Failed to delete recipient')
      fetchData()
      setStatusWithAutoClear(setRecipientStatus, { type: 'success', message: 'Deleted' })
    } catch (err) {
      setStatusWithAutoClear(setRecipientStatus, { type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const saveDefaultSettings = async (e: React.FormEvent) => {
    e.preventDefault()
    setDefaultsStatus(null)

    try {
      const res = await fetch('/api/settings/defaults', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(defaultSettings),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to save default settings')
      }

      setStatusWithAutoClear(setDefaultsStatus, { type: 'success', message: 'Saved' })
    } catch (err) {
      setStatusWithAutoClear(setDefaultsStatus, { type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const saveTimeSettings = async (e: React.FormEvent) => {
    e.preventDefault()
    setTimeStatus(null)

    try {
      const res = await fetch('/api/settings/time', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(timeSettings),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to save time settings')
      }

      setStatusWithAutoClear(setTimeStatus, { type: 'success', message: 'Saved' })
      refreshCurrentTime()
    } catch (err) {
      setStatusWithAutoClear(setTimeStatus, { type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const refreshCurrentTime = async () => {
    try {
      const res = await fetch('/api/settings/time/current')
      const data = await res.json()
      if (data) {
        setCurrentTime(data)
      }
    } catch {
      // ignore
    }
  }

  const handleExportBackup = async () => {
    if (exportPassword.length < 8) {
      setStatusWithAutoClear(setBackupStatus, { type: 'error', message: 'Password must be at least 8 characters' })
      return
    }

    setBackupLoading(true)
    setBackupStatus(null)

    try {
      const res = await fetch('/api/backup/export', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: exportPassword }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to export backup')
      }

      const result = await res.json()

      // Download as file
      const blob = new Blob([result.data], { type: 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `easyca-backup-${new Date().toISOString().split('T')[0]}.ecab`
      a.click()
      URL.revokeObjectURL(url)

      setExportPassword('')
      setStatusWithAutoClear(setBackupStatus, { type: 'success', message: `Exported ${result.stats.cas} CAs, ${result.stats.certificates} certs` })
    } catch (err) {
      setStatusWithAutoClear(setBackupStatus, { type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
    setBackupLoading(false)
  }

  const handleImportBackup = async () => {
    if (!importData && !importFile) {
      setStatusWithAutoClear(setBackupStatus, { type: 'error', message: 'Please select a backup file' })
      return
    }

    if (!importPassword) {
      setStatusWithAutoClear(setBackupStatus, { type: 'error', message: 'Password is required' })
      return
    }

    setBackupLoading(true)
    setBackupStatus(null)

    try {
      let data = importData

      if (importFile && !data) {
        data = await importFile.text()
      }

      const res = await fetch('/api/backup/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ password: importPassword, data }),
      })

      if (!res.ok) {
        const result = await res.json()
        throw new Error(result.error || 'Failed to import backup')
      }

      const result = await res.json()

      setImportPassword('')
      setImportFile(null)
      setImportData('')
      setStatusWithAutoClear(setBackupStatus, { type: 'success', message: `Imported ${result.stats.cas} CAs, ${result.stats.certificates} certs` })

      // Refresh data
      fetchData()
    } catch (err) {
      setStatusWithAutoClear(setBackupStatus, { type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
    setBackupLoading(false)
  }

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setImportFile(file)
      setImportData('')
    }
  }

  const getNotificationTypeBadge = (type: string) => {
    switch (type) {
      case 'expiry_warning':
        return <span className="badge badge-warning">Expiry Warning</span>
      case 'ca_expiry_warning':
        return <span className="badge badge-warning">CA Expiry</span>
      case 'issuance':
        return <span className="badge badge-success">Issuance</span>
      case 'revocation':
        return <span className="badge badge-danger">Revocation</span>
      default:
        return <span className="badge">{type}</span>
    }
  }

  // Inline status component
  const StatusBadge = ({ status }: { status: FormStatus }) => {
    if (!status) return null
    return (
      <span style={{
        marginLeft: '0.75rem',
        padding: '0.25rem 0.75rem',
        borderRadius: '4px',
        fontSize: '0.85rem',
        fontWeight: 500,
        background: status.type === 'success' ? 'var(--success)' : 'var(--danger)',
        color: 'white',
      }}>
        {status.message}
      </span>
    )
  }

  if (loading) {
    return <div className="empty-state">Loading...</div>
  }

  return (
    <div>
      <h1 style={{ marginBottom: '1rem' }}>Settings</h1>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}>
        <button
          className={`btn ${activeTab === 'smtp' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('smtp')}
        >
          SMTP
        </button>
        <button
          className={`btn ${activeTab === 'notifications' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('notifications')}
        >
          Notifications
        </button>
        <button
          className={`btn ${activeTab === 'recipients' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('recipients')}
        >
          Recipients
        </button>
        <button
          className={`btn ${activeTab === 'log' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('log')}
        >
          Log
        </button>
        <button
          className={`btn ${activeTab === 'defaults' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('defaults')}
        >
          Defaults
        </button>
        <button
          className={`btn ${activeTab === 'time' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('time')}
        >
          Time
        </button>
        <button
          className={`btn ${activeTab === 'backup' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('backup')}
        >
          Backup
        </button>
      </div>

      {/* SMTP Tab */}
      {activeTab === 'smtp' && (
        <div className="card">
          <h2 style={{ marginBottom: '1rem' }}>SMTP Configuration</h2>
          <form onSubmit={saveSMTPConfig}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div className="form-group">
                <label>SMTP Host *</label>
                <input
                  type="text"
                  value={smtpConfig.host}
                  onChange={e => setSMTPConfig({ ...smtpConfig, host: e.target.value })}
                  placeholder="smtp.gmail.com"
                  required
                />
              </div>
              <div className="form-group">
                <label>Port</label>
                <input
                  type="number"
                  value={smtpConfig.port}
                  onChange={e => setSMTPConfig({ ...smtpConfig, port: parseInt(e.target.value) })}
                  placeholder="587"
                />
              </div>
              <div className="form-group">
                <label>Username</label>
                <input
                  type="text"
                  value={smtpConfig.username}
                  onChange={e => setSMTPConfig({ ...smtpConfig, username: e.target.value })}
                  placeholder="user@gmail.com"
                />
              </div>
              <div className="form-group">
                <label>Password</label>
                <input
                  type="password"
                  value={smtpPassword}
                  onChange={e => setSMTPPassword(e.target.value)}
                  placeholder="Leave empty to keep existing"
                />
              </div>
              <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                <label>From Address *</label>
                <input
                  type="email"
                  value={smtpConfig.from_address}
                  onChange={e => setSMTPConfig({ ...smtpConfig, from_address: e.target.value })}
                  placeholder="noreply@example.com"
                  required
                />
              </div>
            </div>

            <div style={{ display: 'flex', gap: '2rem', marginTop: '1rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={smtpConfig.tls_enabled}
                  onChange={e => setSMTPConfig({ ...smtpConfig, tls_enabled: e.target.checked })}
                />
                Enable TLS/SSL
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={smtpConfig.enabled}
                  onChange={e => setSMTPConfig({ ...smtpConfig, enabled: e.target.checked })}
                />
                Enable Notifications
              </label>
            </div>

            <div style={{ marginTop: '1.5rem', display: 'flex', alignItems: 'center' }}>
              <button type="submit" className="btn btn-primary">Save Configuration</button>
              <StatusBadge status={smtpStatus} />
            </div>
          </form>

          <hr style={{ margin: '1.5rem 0', border: 'none', borderTop: '1px solid var(--border)' }} />

          <h3 style={{ marginBottom: '1rem' }}>Test SMTP</h3>
          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
            <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
              <label>Test Email Address</label>
              <input
                type="email"
                value={testEmail}
                onChange={e => setTestEmail(e.target.value)}
                placeholder="test@example.com"
              />
            </div>
            <button className="btn btn-secondary" onClick={testSMTP}>
              Send Test
            </button>
            <StatusBadge status={smtpTestStatus} />
          </div>
        </div>
      )}

      {/* Notifications Tab */}
      {activeTab === 'notifications' && (
        <div className="card">
          <h2 style={{ marginBottom: '1rem' }}>Notification Settings</h2>
          <form onSubmit={saveNotificationSettings}>
            <div className="form-group">
              <label>Expiry Warning Days</label>
              <input
                type="text"
                value={notificationSettings.expiry_warning_days}
                onChange={e => setNotificationSettings({ ...notificationSettings, expiry_warning_days: e.target.value })}
                placeholder="30,14,7"
              />
              <small style={{ color: 'var(--text-muted)' }}>
                Comma-separated list of days before expiry to send warnings (e.g., 30,14,7)
              </small>
            </div>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', marginTop: '1rem' }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={notificationSettings.notify_on_issuance}
                  onChange={e => setNotificationSettings({ ...notificationSettings, notify_on_issuance: e.target.checked })}
                />
                Notify on certificate issuance
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={notificationSettings.notify_on_revocation}
                  onChange={e => setNotificationSettings({ ...notificationSettings, notify_on_revocation: e.target.checked })}
                />
                Notify on certificate revocation
              </label>
            </div>

            <div style={{ marginTop: '1.5rem', display: 'flex', alignItems: 'center' }}>
              <button type="submit" className="btn btn-primary">Save Settings</button>
              <StatusBadge status={notificationStatus} />
            </div>
          </form>
        </div>
      )}

      {/* Recipients Tab */}
      {activeTab === 'recipients' && (
        <div className="card">
          <div className="card-header" style={{ marginBottom: '1rem' }}>
            <h2>Notification Recipients</h2>
            <div style={{ display: 'flex', alignItems: 'center' }}>
              <button className="btn btn-primary" onClick={() => setShowAddRecipient(true)}>
                Add Recipient
              </button>
              <StatusBadge status={recipientStatus} />
            </div>
          </div>

          {recipients.length === 0 ? (
            <p style={{ color: 'var(--text-muted)' }}>No recipients configured.</p>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Email</th>
                  <th>Scope</th>
                  <th>Added</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {recipients.map(r => (
                  <tr key={r.id}>
                    <td>{r.email}</td>
                    <td>
                      {r.is_global ? (
                        <span className="badge badge-info">Global</span>
                      ) : r.ca_id ? (
                        <span className="badge badge-success">CA: {cas.find(c => c.id === r.ca_id)?.name || r.ca_id}</span>
                      ) : r.certificate_id ? (
                        <span className="badge badge-warning">Cert: {certificates.find(c => c.id === r.certificate_id)?.common_name || r.certificate_id}</span>
                      ) : (
                        <span className="badge">Unknown</span>
                      )}
                    </td>
                    <td>{new Date(r.created_at).toLocaleDateString()}</td>
                    <td>
                      <button className="btn btn-danger" onClick={() => deleteRecipient(r.id)}>
                        Delete
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {/* Add Recipient Modal */}
          {showAddRecipient && (
            <div className="modal-overlay" onClick={() => setShowAddRecipient(false)}>
              <div className="modal" onClick={e => e.stopPropagation()}>
                <div className="modal-header">
                  <h2 className="modal-title">Add Recipient</h2>
                  <button className="modal-close" onClick={() => setShowAddRecipient(false)}>&times;</button>
                </div>
                <form onSubmit={addRecipient}>
                  <div className="form-group">
                    <label>Email Address *</label>
                    <input
                      type="email"
                      value={newRecipient.email}
                      onChange={e => setNewRecipient({ ...newRecipient, email: e.target.value })}
                      placeholder="admin@example.com"
                      required
                    />
                  </div>
                  <div className="form-group">
                    <label style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', cursor: 'pointer' }}>
                      <input
                        type="checkbox"
                        checked={newRecipient.is_global}
                        onChange={e => setNewRecipient({ ...newRecipient, is_global: e.target.checked })}
                      />
                      Global recipient (receives all notifications)
                    </label>
                  </div>
                  {!newRecipient.is_global && (
                    <>
                      <div className="form-group">
                        <label>CA (optional)</label>
                        <select
                          value={newRecipient.ca_id}
                          onChange={e => setNewRecipient({ ...newRecipient, ca_id: e.target.value })}
                        >
                          <option value="">All CAs</option>
                          {cas.map(ca => (
                            <option key={ca.id} value={ca.id}>{ca.name}</option>
                          ))}
                        </select>
                      </div>
                      <div className="form-group">
                        <label>Certificate (optional)</label>
                        <select
                          value={newRecipient.certificate_id}
                          onChange={e => setNewRecipient({ ...newRecipient, certificate_id: e.target.value })}
                        >
                          <option value="">All Certificates</option>
                          {certificates.map(cert => (
                            <option key={cert.id} value={cert.id}>{cert.common_name}</option>
                          ))}
                        </select>
                      </div>
                    </>
                  )}
                  <div className="modal-actions">
                    <button type="button" className="btn btn-secondary" onClick={() => setShowAddRecipient(false)}>Cancel</button>
                    <button type="submit" className="btn btn-primary">Add</button>
                  </div>
                </form>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Log Tab */}
      {activeTab === 'log' && (
        <div className="card">
          <div className="card-header" style={{ marginBottom: '1rem' }}>
            <h2>Notification Log</h2>
            <button className="btn btn-secondary" onClick={fetchData}>
              Refresh
            </button>
          </div>

          {logs.length === 0 ? (
            <p style={{ color: 'var(--text-muted)' }}>No notifications sent yet.</p>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Type</th>
                  <th>Recipient</th>
                  <th>Days Left</th>
                  <th>Status</th>
                  <th>Sent At</th>
                </tr>
              </thead>
              <tbody>
                {logs.map(log => (
                  <tr key={log.id}>
                    <td>{getNotificationTypeBadge(log.notification_type)}</td>
                    <td>{log.recipient_email}</td>
                    <td>{log.days_until_expiry ?? '-'}</td>
                    <td>
                      {log.status === 'sent' ? (
                        <span className="badge badge-success">Sent</span>
                      ) : (
                        <span className="badge badge-danger" title={log.error_message}>Failed</span>
                      )}
                    </td>
                    <td>{new Date(log.sent_at).toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Defaults Tab */}
      {activeTab === 'defaults' && (
        <div className="card">
          <h2 style={{ marginBottom: '1rem' }}>Default Settings</h2>
          <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem' }}>
            Configure default values for creating CAs and certificates. These values will be pre-filled in forms.
          </p>
          <form onSubmit={saveDefaultSettings}>
            <h3 style={{ marginBottom: '1rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}>
              Cryptographic Defaults
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div className="form-group">
                <label>Key Algorithm</label>
                <select
                  value={defaultSettings.key_algorithm}
                  onChange={e => setDefaultSettings({ ...defaultSettings, key_algorithm: e.target.value })}
                >
                  <option value="rsa2048">RSA 2048 (Recommended)</option>
                  <option value="rsa3072">RSA 3072</option>
                  <option value="rsa4096">RSA 4096</option>
                  <option value="ecdsa-p256">ECDSA P-256</option>
                  <option value="ecdsa-p384">ECDSA P-384</option>
                  <option value="ecdsa-p521">ECDSA P-521</option>
                </select>
              </div>
              <div className="form-group">
                <label>Signature Algorithm</label>
                <select
                  value={defaultSettings.signature_algorithm}
                  onChange={e => setDefaultSettings({ ...defaultSettings, signature_algorithm: e.target.value })}
                >
                  <option value="sha256">SHA-256 (Recommended)</option>
                  <option value="sha384">SHA-384</option>
                  <option value="sha512">SHA-512</option>
                </select>
              </div>
            </div>

            <h3 style={{ marginTop: '1.5rem', marginBottom: '1rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}>
              Validity Defaults
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div className="form-group">
                <label>CA Validity (days)</label>
                <input
                  type="number"
                  value={defaultSettings.validity_days_ca}
                  onChange={e => setDefaultSettings({ ...defaultSettings, validity_days_ca: parseInt(e.target.value) })}
                  min={1}
                />
                <small style={{ color: 'var(--text-muted)' }}>Default: 3650 (10 years)</small>
              </div>
              <div className="form-group">
                <label>Certificate Validity (days)</label>
                <input
                  type="number"
                  value={defaultSettings.validity_days_cert}
                  onChange={e => setDefaultSettings({ ...defaultSettings, validity_days_cert: parseInt(e.target.value) })}
                  min={1}
                />
                <small style={{ color: 'var(--text-muted)' }}>Default: 365 (1 year)</small>
              </div>
            </div>

            <h3 style={{ marginTop: '1.5rem', marginBottom: '1rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}>
              Subject Defaults
            </h3>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div className="form-group">
                <label>Organization (O)</label>
                <input
                  type="text"
                  value={defaultSettings.organization}
                  onChange={e => setDefaultSettings({ ...defaultSettings, organization: e.target.value })}
                  placeholder="My Company"
                />
              </div>
              <div className="form-group">
                <label>Organizational Unit (OU)</label>
                <input
                  type="text"
                  value={defaultSettings.organizational_unit}
                  onChange={e => setDefaultSettings({ ...defaultSettings, organizational_unit: e.target.value })}
                  placeholder="IT Department"
                />
              </div>
              <div className="form-group">
                <label>Country (C) - 2-letter code</label>
                <input
                  type="text"
                  maxLength={2}
                  value={defaultSettings.country}
                  onChange={e => setDefaultSettings({ ...defaultSettings, country: e.target.value.toUpperCase() })}
                  placeholder="RS"
                />
              </div>
              <div className="form-group">
                <label>State/Province (ST)</label>
                <input
                  type="text"
                  value={defaultSettings.state}
                  onChange={e => setDefaultSettings({ ...defaultSettings, state: e.target.value })}
                  placeholder="Vojvodina"
                />
              </div>
              <div className="form-group">
                <label>Locality/City (L)</label>
                <input
                  type="text"
                  value={defaultSettings.locality}
                  onChange={e => setDefaultSettings({ ...defaultSettings, locality: e.target.value })}
                  placeholder="Novi Sad"
                />
              </div>
            </div>

            <div style={{ marginTop: '1.5rem', display: 'flex', alignItems: 'center' }}>
              <button type="submit" className="btn btn-primary">Save Defaults</button>
              <StatusBadge status={defaultsStatus} />
            </div>
          </form>
        </div>
      )}

      {/* Time Tab */}
      {activeTab === 'time' && (
        <div className="card">
          <h2 style={{ marginBottom: '1rem' }}>Time Settings</h2>

          {/* Current Time Display */}
          {currentTime && (
            <div style={{
              background: 'var(--bg-secondary)',
              padding: '1rem',
              borderRadius: '8px',
              marginBottom: '1.5rem',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center'
            }}>
              <div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.25rem' }}>
                  Current System Time
                </div>
                <div style={{ fontSize: '1.5rem', fontWeight: 600, fontFamily: 'var(--font-mono)' }}>
                  {new Date(currentTime.current_time).toLocaleString()}
                </div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginTop: '0.25rem' }}>
                  Source: {currentTime.source} | Timezone: {currentTime.timezone}
                </div>
              </div>
              <button className="btn btn-secondary" onClick={refreshCurrentTime}>
                Refresh
              </button>
            </div>
          )}

          <form onSubmit={saveTimeSettings}>
            <h3 style={{ marginBottom: '1rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}>
              Time Source
            </h3>

            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', marginBottom: '1.5rem' }}>
              <label style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '0.75rem',
                cursor: 'pointer',
                padding: '1rem',
                background: timeSettings.time_source === 'host' ? 'var(--bg-secondary)' : 'transparent',
                borderRadius: '8px',
                border: '1px solid var(--border)'
              }}>
                <input
                  type="radio"
                  name="time_source"
                  value="host"
                  checked={timeSettings.time_source === 'host'}
                  onChange={() => setTimeSettings({ ...timeSettings, time_source: 'host' })}
                  style={{ marginTop: '3px' }}
                />
                <div>
                  <div style={{ fontWeight: 500 }}>Sync with Docker Host</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)' }}>
                    Use the time from the Docker host system. Recommended for most deployments.
                  </div>
                </div>
              </label>

              <label style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '0.75rem',
                cursor: 'pointer',
                padding: '1rem',
                background: timeSettings.time_source === 'ntp' ? 'var(--bg-secondary)' : 'transparent',
                borderRadius: '8px',
                border: '1px solid var(--border)'
              }}>
                <input
                  type="radio"
                  name="time_source"
                  value="ntp"
                  checked={timeSettings.time_source === 'ntp'}
                  onChange={() => setTimeSettings({ ...timeSettings, time_source: 'ntp' })}
                  style={{ marginTop: '3px' }}
                />
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 500 }}>NTP Server</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                    Synchronize time with an NTP server for accurate time across distributed systems.
                  </div>
                  {timeSettings.time_source === 'ntp' && (
                    <input
                      type="text"
                      value={timeSettings.ntp_server}
                      onChange={e => setTimeSettings({ ...timeSettings, ntp_server: e.target.value })}
                      placeholder="pool.ntp.org"
                      style={{ width: '100%' }}
                    />
                  )}
                </div>
              </label>

              <label style={{
                display: 'flex',
                alignItems: 'flex-start',
                gap: '0.75rem',
                cursor: 'pointer',
                padding: '1rem',
                background: timeSettings.time_source === 'manual' ? 'var(--bg-secondary)' : 'transparent',
                borderRadius: '8px',
                border: '1px solid var(--border)'
              }}>
                <input
                  type="radio"
                  name="time_source"
                  value="manual"
                  checked={timeSettings.time_source === 'manual'}
                  onChange={() => setTimeSettings({ ...timeSettings, time_source: 'manual' })}
                  style={{ marginTop: '3px' }}
                />
                <div style={{ flex: 1 }}>
                  <div style={{ fontWeight: 500 }}>Manual</div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', marginBottom: '0.75rem' }}>
                    Set a specific date and time manually. Use for testing or isolated environments.
                  </div>
                  {timeSettings.time_source === 'manual' && (
                    <input
                      type="datetime-local"
                      value={timeSettings.manual_time}
                      onChange={e => setTimeSettings({ ...timeSettings, manual_time: e.target.value })}
                      style={{ width: '100%' }}
                    />
                  )}
                </div>
              </label>
            </div>

            <h3 style={{ marginBottom: '1rem', borderBottom: '1px solid var(--border)', paddingBottom: '0.5rem' }}>
              Timezone
            </h3>

            <div className="form-group">
              <label>Select Timezone</label>
              <select
                value={timeSettings.timezone}
                onChange={e => setTimeSettings({ ...timeSettings, timezone: e.target.value })}
              >
                <optgroup label="Common">
                  <option value="UTC">UTC</option>
                  <option value="Europe/Belgrade">Europe/Belgrade (CET/CEST)</option>
                  <option value="Europe/London">Europe/London (GMT/BST)</option>
                  <option value="Europe/Berlin">Europe/Berlin (CET/CEST)</option>
                  <option value="Europe/Paris">Europe/Paris (CET/CEST)</option>
                  <option value="America/New_York">America/New York (EST/EDT)</option>
                  <option value="America/Los_Angeles">America/Los Angeles (PST/PDT)</option>
                  <option value="America/Chicago">America/Chicago (CST/CDT)</option>
                  <option value="Asia/Tokyo">Asia/Tokyo (JST)</option>
                  <option value="Asia/Shanghai">Asia/Shanghai (CST)</option>
                  <option value="Asia/Dubai">Asia/Dubai (GST)</option>
                  <option value="Australia/Sydney">Australia/Sydney (AEST/AEDT)</option>
                </optgroup>
                <optgroup label="Europe">
                  <option value="Europe/Amsterdam">Europe/Amsterdam</option>
                  <option value="Europe/Athens">Europe/Athens</option>
                  <option value="Europe/Brussels">Europe/Brussels</option>
                  <option value="Europe/Budapest">Europe/Budapest</option>
                  <option value="Europe/Copenhagen">Europe/Copenhagen</option>
                  <option value="Europe/Dublin">Europe/Dublin</option>
                  <option value="Europe/Helsinki">Europe/Helsinki</option>
                  <option value="Europe/Istanbul">Europe/Istanbul</option>
                  <option value="Europe/Kiev">Europe/Kiev</option>
                  <option value="Europe/Lisbon">Europe/Lisbon</option>
                  <option value="Europe/Madrid">Europe/Madrid</option>
                  <option value="Europe/Moscow">Europe/Moscow</option>
                  <option value="Europe/Oslo">Europe/Oslo</option>
                  <option value="Europe/Prague">Europe/Prague</option>
                  <option value="Europe/Rome">Europe/Rome</option>
                  <option value="Europe/Stockholm">Europe/Stockholm</option>
                  <option value="Europe/Vienna">Europe/Vienna</option>
                  <option value="Europe/Warsaw">Europe/Warsaw</option>
                  <option value="Europe/Zurich">Europe/Zurich</option>
                </optgroup>
                <optgroup label="Americas">
                  <option value="America/Anchorage">America/Anchorage</option>
                  <option value="America/Bogota">America/Bogota</option>
                  <option value="America/Buenos_Aires">America/Buenos Aires</option>
                  <option value="America/Caracas">America/Caracas</option>
                  <option value="America/Denver">America/Denver</option>
                  <option value="America/Halifax">America/Halifax</option>
                  <option value="America/Lima">America/Lima</option>
                  <option value="America/Mexico_City">America/Mexico City</option>
                  <option value="America/Phoenix">America/Phoenix</option>
                  <option value="America/Santiago">America/Santiago</option>
                  <option value="America/Sao_Paulo">America/Sao Paulo</option>
                  <option value="America/Toronto">America/Toronto</option>
                  <option value="America/Vancouver">America/Vancouver</option>
                </optgroup>
                <optgroup label="Asia & Pacific">
                  <option value="Asia/Bangkok">Asia/Bangkok</option>
                  <option value="Asia/Hong_Kong">Asia/Hong Kong</option>
                  <option value="Asia/Jakarta">Asia/Jakarta</option>
                  <option value="Asia/Jerusalem">Asia/Jerusalem</option>
                  <option value="Asia/Karachi">Asia/Karachi</option>
                  <option value="Asia/Kolkata">Asia/Kolkata</option>
                  <option value="Asia/Kuala_Lumpur">Asia/Kuala Lumpur</option>
                  <option value="Asia/Manila">Asia/Manila</option>
                  <option value="Asia/Seoul">Asia/Seoul</option>
                  <option value="Asia/Singapore">Asia/Singapore</option>
                  <option value="Asia/Taipei">Asia/Taipei</option>
                  <option value="Pacific/Auckland">Pacific/Auckland</option>
                  <option value="Pacific/Fiji">Pacific/Fiji</option>
                  <option value="Pacific/Honolulu">Pacific/Honolulu</option>
                </optgroup>
                <optgroup label="Africa & Middle East">
                  <option value="Africa/Cairo">Africa/Cairo</option>
                  <option value="Africa/Johannesburg">Africa/Johannesburg</option>
                  <option value="Africa/Lagos">Africa/Lagos</option>
                  <option value="Africa/Nairobi">Africa/Nairobi</option>
                </optgroup>
              </select>
            </div>

            <div style={{ marginTop: '1.5rem', display: 'flex', alignItems: 'center' }}>
              <button type="submit" className="btn btn-primary">Save Time Settings</button>
              <StatusBadge status={timeStatus} />
            </div>
          </form>
        </div>
      )}

      {/* Backup Tab */}
      {activeTab === 'backup' && (
        <div className="card">
          <h2 style={{ marginBottom: '1rem' }}>Backup & Restore</h2>
          <p style={{ color: 'var(--text-muted)', marginBottom: '1.5rem' }}>
            Export all data (CAs, certificates, CSRs, and settings) as an encrypted backup file,
            or import a backup to restore data on a new instance.
          </p>

          {/* Export Section */}
          <div style={{
            padding: '1.5rem',
            background: 'var(--bg-secondary)',
            borderRadius: '8px',
            marginBottom: '1.5rem',
          }}>
            <h3 style={{ marginBottom: '1rem' }}>Export Backup</h3>
            <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem', marginBottom: '1rem' }}>
              Create an encrypted backup file containing all CAs (with private keys), certificates, CSRs, and settings.
              The backup will be encrypted with your password.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-end' }}>
              <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
                <label>Encryption Password (min 8 characters)</label>
                <input
                  type="password"
                  value={exportPassword}
                  onChange={e => setExportPassword(e.target.value)}
                  placeholder="Enter a strong password"
                  minLength={8}
                />
              </div>
              <button
                className="btn btn-primary"
                onClick={handleExportBackup}
                disabled={backupLoading || exportPassword.length < 8}
              >
                {backupLoading ? 'Exporting...' : 'Export Backup'}
              </button>
            </div>
          </div>

          {/* Import Section */}
          <div style={{
            padding: '1.5rem',
            background: 'var(--bg-secondary)',
            borderRadius: '8px',
          }}>
            <h3 style={{ marginBottom: '1rem' }}>Import Backup</h3>
            <div style={{
              padding: '1rem',
              background: 'var(--danger-light)',
              borderRadius: '6px',
              marginBottom: '1rem',
              border: '1px solid var(--danger)'
            }}>
              <p style={{ color: 'var(--danger)', fontWeight: 500, marginBottom: '0.25rem' }}>
                Warning: Import will replace all existing data!
              </p>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                All current CAs, certificates, CSRs, and settings will be deleted and replaced with the backup data.
              </p>
            </div>

            <div className="form-group">
              <label>Backup File (.ecab)</label>
              <input
                type="file"
                accept=".ecab"
                onChange={handleFileSelect}
                style={{
                  padding: '0.5rem',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  width: '100%',
                  background: 'var(--input-bg)',
                }}
              />
              {importFile && (
                <small style={{ color: 'var(--text-muted)' }}>
                  Selected: {importFile.name}
                </small>
              )}
            </div>

            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'flex-end' }}>
              <div className="form-group" style={{ flex: 1, marginBottom: 0 }}>
                <label>Decryption Password</label>
                <input
                  type="password"
                  value={importPassword}
                  onChange={e => setImportPassword(e.target.value)}
                  placeholder="Enter the backup password"
                />
              </div>
              <button
                className="btn btn-danger"
                onClick={handleImportBackup}
                disabled={backupLoading || !importFile || !importPassword}
              >
                {backupLoading ? 'Importing...' : 'Import Backup'}
              </button>
            </div>
          </div>

          {/* Status */}
          {backupStatus && (
            <div style={{
              marginTop: '1rem',
              padding: '0.75rem 1rem',
              borderRadius: '6px',
              background: backupStatus.type === 'success' ? 'var(--success)' : 'var(--danger)',
              color: 'white',
              fontWeight: 500,
            }}>
              {backupStatus.message}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default Settings
