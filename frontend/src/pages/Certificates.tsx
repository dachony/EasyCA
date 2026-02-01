import { useState, useEffect, useMemo } from 'react'

interface CA {
  id: string
  name: string
  type: 'root' | 'intermediate'
  parent_id?: string
  common_name?: string
  organization?: string
  dns_names?: string[]
  certificate_pem: string
  not_before: string
  not_after: string
}

interface Certificate {
  id: string
  serial_number: string
  ca_id: string
  common_name: string
  organization?: string
  dns_names?: string[]
  key_algorithm?: string
  signature_algorithm?: string
  type: 'server' | 'client'
  certificate_pem: string
  not_before: string
  not_after: string
  revoked_at?: string
  revocation_reason?: string
  created_at: string
}

interface NewCertResponse {
  certificate: Certificate
  certificate_pem: string
  private_key_pem: string
}

type FormStatus = { type: 'success' | 'error', message: string } | null

function Certificates() {
  const [certs, setCerts] = useState<Certificate[]>([])
  const [cas, setCAs] = useState<CA[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [showResultModal, setShowResultModal] = useState(false)
  const [newCertResult, setNewCertResult] = useState<NewCertResponse | null>(null)
  const [formStatus, setFormStatus] = useState<FormStatus>(null)
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [expandedCAs, setExpandedCAs] = useState<Set<string>>(new Set())
  const [searchQuery, setSearchQuery] = useState('')
  const [statusFilter, setStatusFilter] = useState<'all' | 'valid' | 'expired' | 'revoked'>('all')
  const [formData, setFormData] = useState({
    ca_id: '',
    common_name: '',
    organization: '',
    organizational_unit: '',
    country: '',
    state: '',
    locality: '',
    street_address: '',
    postal_code: '',
    email_address: '',
    type: 'server' as 'server' | 'client',
    dns_names: '',
    ip_addresses: '',
    validity_days: 365,
    key_algorithm: 'rsa2048',
    signature_algorithm: 'sha256',
  })
  const [showExportModal, setShowExportModal] = useState(false)
  const [exportCert, setExportCert] = useState<Certificate | null>(null)
  const [exportPassword, setExportPassword] = useState('')
  const [exportPrivateKey, setExportPrivateKey] = useState('')

  // Delete modal state
  const [showDeleteModal, setShowDeleteModal] = useState(false)
  const [deleteCert, setDeleteCert] = useState<Certificate | null>(null)
  const [deleteReason, setDeleteReason] = useState('')
  const [deleteConfirmation, setDeleteConfirmation] = useState('')

  const fetchData = () => {
    Promise.all([
      fetch('/api/certificates').then(r => r.json()),
      fetch('/api/ca').then(r => r.json()),
    ]).then(([certsData, casData]) => {
      setCerts(certsData || [])
      setCAs(casData || [])
      setLoading(false)
    }).catch(() => setLoading(false))
  }

  useEffect(() => {
    fetchData()
  }, [])

  const setStatusWithAutoClear = (status: FormStatus) => {
    setFormStatus(status)
    setTimeout(() => setFormStatus(null), 3000)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setFormStatus(null)

    try {
      const res = await fetch('/api/certificates', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...formData,
          dns_names: formData.dns_names ? formData.dns_names.split(',').map(s => s.trim()) : [],
          ip_addresses: formData.ip_addresses ? formData.ip_addresses.split(',').map(s => s.trim()) : [],
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to create certificate')
      }

      const result = await res.json()
      setNewCertResult(result)
      setShowModal(false)
      setShowResultModal(true)
      setFormData({
        ca_id: '', common_name: '', organization: '', organizational_unit: '',
        country: '', state: '', locality: '', street_address: '', postal_code: '',
        email_address: '', type: 'server', dns_names: '', ip_addresses: '', validity_days: 365,
        key_algorithm: 'rsa2048', signature_algorithm: 'sha256',
      })
      setShowAdvanced(false)
      fetchData()
    } catch (err) {
      setStatusWithAutoClear({ type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const handleRevoke = async (id: string) => {
    if (!confirm('Are you sure you want to revoke this certificate?')) return

    try {
      const res = await fetch(`/api/certificates/${id}/revoke`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reason: 'Manual revocation' }),
      })

      if (!res.ok) throw new Error('Failed to revoke certificate')

      setStatusWithAutoClear({ type: 'success', message: 'Revoked' })
      fetchData()
    } catch (err) {
      setStatusWithAutoClear({ type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const openDeleteModal = (cert: Certificate) => {
    setDeleteCert(cert)
    setDeleteReason('')
    setDeleteConfirmation('')
    setShowDeleteModal(true)
  }

  // Delete modal error state (local)
  const [deleteError, setDeleteError] = useState('')

  const handleDelete = async () => {
    if (!deleteCert) return
    setDeleteError('')

    const today = new Date()
    const expectedConfirmation = `${deleteCert.common_name}-${today.getFullYear()}${String(today.getMonth() + 1).padStart(2, '0')}${String(today.getDate()).padStart(2, '0')}`

    if (deleteConfirmation !== expectedConfirmation) {
      setDeleteError('Confirmation text does not match')
      return
    }

    if (!deleteReason.trim()) {
      setDeleteError('Please enter a reason for deletion')
      return
    }

    try {
      const res = await fetch(`/api/certificates/${deleteCert.id}`, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          reason: deleteReason,
          confirmation: deleteConfirmation,
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to delete certificate')
      }

      setShowDeleteModal(false)
      setDeleteCert(null)
      setDeleteReason('')
      setDeleteConfirmation('')
      setStatusWithAutoClear({ type: 'success', message: 'Deleted' })
      fetchData()
    } catch (err) {
      setDeleteError(err instanceof Error ? err.message : 'Error')
    }
  }

  const downloadFile = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'application/x-pem-file' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
  }

  const downloadChain = async (certId: string, commonName: string) => {
    try {
      const res = await fetch(`/api/certificates/${certId}/chain`)
      if (!res.ok) throw new Error('Failed to download chain')
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${commonName}-chain.pem`
      a.click()
    } catch (err) {
      setStatusWithAutoClear({ type: 'error', message: err instanceof Error ? err.message : 'Download failed' })
    }
  }

  const downloadDER = async (certId: string, commonName: string) => {
    try {
      const res = await fetch(`/api/certificates/${certId}/download?format=der`)
      if (!res.ok) throw new Error('Failed to download')
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${commonName}.der`
      a.click()
    } catch (err) {
      setStatusWithAutoClear({ type: 'error', message: err instanceof Error ? err.message : 'Download failed' })
    }
  }

  const downloadPKCS7 = async (certId: string, commonName: string) => {
    try {
      const res = await fetch(`/api/certificates/${certId}/export/pkcs7`)
      if (!res.ok) throw new Error('Failed to download')
      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${commonName}.p7b`
      a.click()
    } catch (err) {
      setStatusWithAutoClear({ type: 'error', message: err instanceof Error ? err.message : 'Download failed' })
    }
  }

  // Export modal error state (local)
  const [exportError, setExportError] = useState('')

  const handleExportPKCS12 = async () => {
    if (!exportCert || !exportPrivateKey) return
    setExportError('')

    try {
      const res = await fetch(`/api/certificates/${exportCert.id}/export/pkcs12`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          password: exportPassword || 'changeit',
          private_key_pem: exportPrivateKey,
          include_chain: true,
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to export PKCS12')
      }

      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `${exportCert.common_name}.p12`
      a.click()

      setShowExportModal(false)
      setExportCert(null)
      setExportPassword('')
      setExportPrivateKey('')
      setStatusWithAutoClear({ type: 'success', message: 'Exported' })
    } catch (err) {
      setExportError(err instanceof Error ? err.message : 'Export failed')
    }
  }

  const toggleExpand = (caId: string) => {
    setExpandedCAs(prev => {
      const next = new Set(prev)
      if (next.has(caId)) {
        next.delete(caId)
      } else {
        next.add(caId)
      }
      return next
    })
  }

  const getIntermediateCAs = (parentId: string) => cas.filter(c => c.type === 'intermediate' && c.parent_id === parentId)

  const getCertificateStatus = (cert: Certificate) => {
    if (cert.revoked_at) return 'revoked'
    if (new Date(cert.not_after) < new Date()) return 'expired'
    return 'valid'
  }

  const getCertificates = (caId: string) => {
    return certs.filter(c => {
      if (c.ca_id !== caId) return false
      if (statusFilter === 'all') return true
      return getCertificateStatus(c) === statusFilter
    })
  }

  // Filter logic
  const filteredRootCAs = useMemo(() => {
    const query = searchQuery.toLowerCase().trim()

    // Filter certs by status first
    const filteredCerts = statusFilter === 'all'
      ? certs
      : certs.filter(c => getCertificateStatus(c) === statusFilter)

    // If no search query, just filter by status
    if (!query) {
      // Find CAs that have matching certificates
      const casWithCerts = new Set<string>()
      filteredCerts.forEach(cert => {
        let ca = cas.find(c => c.id === cert.ca_id)
        while (ca) {
          casWithCerts.add(ca.id)
          if (ca.parent_id) {
            ca = cas.find(c => c.id === ca!.parent_id)
          } else {
            break
          }
        }
      })

      // If filter is active but no certs match, show empty
      if (statusFilter !== 'all' && filteredCerts.length === 0) {
        return []
      }

      // If filter is active, only show CAs with matching certs
      if (statusFilter !== 'all') {
        return cas.filter(c => c.type === 'root' && casWithCerts.has(c.id))
      }

      return cas.filter(c => c.type === 'root')
    }

    const matchingCAIds = new Set<string>()
    const matchingCertCAIds = new Set<string>()

    // Check certificates (only filtered ones)
    filteredCerts.forEach(cert => {
      const matches =
        cert.common_name.toLowerCase().includes(query) ||
        (cert.organization?.toLowerCase().includes(query)) ||
        (cert.dns_names?.some(d => d.toLowerCase().includes(query))) ||
        cert.serial_number.toLowerCase().includes(query)

      if (matches) {
        matchingCertCAIds.add(cert.ca_id)
        // Find root CA chain
        let ca = cas.find(c => c.id === cert.ca_id)
        while (ca) {
          matchingCAIds.add(ca.id)
          if (ca.parent_id) {
            ca = cas.find(c => c.id === ca!.parent_id)
          } else {
            break
          }
        }
      }
    })

    // Check CAs too
    cas.forEach(ca => {
      const matches =
        ca.name.toLowerCase().includes(query) ||
        (ca.common_name?.toLowerCase().includes(query)) ||
        (ca.organization?.toLowerCase().includes(query))

      if (matches) {
        matchingCAIds.add(ca.id)
        let current = ca
        while (current.parent_id) {
          matchingCAIds.add(current.parent_id)
          current = cas.find(c => c.id === current.parent_id) || current
          if (!current.parent_id) break
        }
      }
    })

    // Auto-expand
    if (query) {
      setExpandedCAs(new Set([...matchingCAIds, ...matchingCertCAIds]))
    }

    return cas.filter(c => c.type === 'root' && matchingCAIds.has(c.id))
  }, [cas, certs, searchQuery, statusFilter])

  const formatDNSNames = (dnsNames?: string[]) => {
    if (!dnsNames || dnsNames.length === 0) return '-'
    if (dnsNames.length <= 2) return dnsNames.join(', ')
    return `${dnsNames[0]}, ${dnsNames[1]}, +${dnsNames.length - 2} more`
  }

  const getRowClass = (type: 'root' | 'intermediate' | 'cert') => {
    switch (type) {
      case 'root': return 'row-root'
      case 'intermediate': return 'row-intermediate'
      case 'cert': return 'row-cert'
    }
  }

  const highlightMatch = (text: string) => {
    if (!searchQuery.trim()) return text
    const regex = new RegExp(`(${searchQuery.trim()})`, 'gi')
    const parts = text.split(regex)
    return parts.map((part, i) =>
      regex.test(part) ? <mark key={i} style={{ background: '#fef08a', padding: '0 2px', borderRadius: '2px' }}>{part}</mark> : part
    )
  }

  const renderCARow = (ca: CA, level: number = 0): React.ReactNode => {
    const isExpanded = expandedCAs.has(ca.id)
    const childIntermediates = getIntermediateCAs(ca.id)
    const childCerts = getCertificates(ca.id)
    const hasChildItems = childIntermediates.length > 0 || childCerts.length > 0

    return (
      <>
        <tr
          key={ca.id}
          className={`${getRowClass(ca.type)} ${hasChildItems ? 'row-clickable' : ''}`}
          onClick={() => hasChildItems && toggleExpand(ca.id)}
        >
          <td style={{ paddingLeft: `${level * 1.5 + 1}rem` }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              {hasChildItems ? (
                <span className={`expand-icon ${isExpanded ? 'expanded' : ''}`}>▶</span>
              ) : (
                <span style={{ width: '1.25rem' }} />
              )}
              <span style={{ color: 'var(--text-muted)' }}>{highlightMatch(ca.name)}</span>
            </div>
          </td>
          <td>
            <span className={`badge ${ca.type === 'root' ? 'badge-primary' : 'badge-success'}`}>
              {ca.type === 'root' ? 'Root CA' : 'Intermediate'}
            </span>
          </td>
          <td style={{ color: 'var(--text-muted)' }}>{ca.common_name ? highlightMatch(ca.common_name) : '-'}</td>
          <td style={{ color: 'var(--text-muted)' }}>{ca.organization ? highlightMatch(ca.organization) : '-'}</td>
          <td style={{ color: 'var(--text-muted)' }}>{formatDNSNames(ca.dns_names)}</td>
          <td style={{ color: 'var(--text-muted)' }}>{new Date(ca.not_after).toLocaleDateString()}</td>
          <td>-</td>
          <td>-</td>
        </tr>
        {isExpanded && childIntermediates.map(intermediate => renderCARow(intermediate, level + 1))}
        {isExpanded && childCerts.map(cert => renderCertRow(cert, level + 1))}
      </>
    )
  }

  const renderCertRow = (cert: Certificate, level: number) => (
    <tr key={cert.id} className={getRowClass('cert')}>
      <td style={{ paddingLeft: `${level * 1.5 + 1}rem` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ width: '1.25rem' }} />
          <strong>{highlightMatch(cert.common_name)}</strong>
        </div>
      </td>
      <td>
        <span className={`badge ${cert.type === 'server' ? 'badge-info' : 'badge-warning'}`}>
          {cert.type}
        </span>
      </td>
      <td>{highlightMatch(cert.common_name)}</td>
      <td>{cert.organization ? highlightMatch(cert.organization) : '-'}</td>
      <td>{formatDNSNames(cert.dns_names)}</td>
      <td>{new Date(cert.not_after).toLocaleDateString()}</td>
      <td>
        {cert.revoked_at ? (
          <span className="badge badge-danger">Revoked</span>
        ) : new Date(cert.not_after) < new Date() ? (
          <span className="badge badge-warning">Expired</span>
        ) : (
          <span className="badge badge-success">Valid</span>
        )}
      </td>
      <td onClick={e => e.stopPropagation()}>
        <div style={{ display: 'flex', gap: '0.25rem' }}>
          <select
            className="btn btn-secondary btn-sm"
            style={{ cursor: 'pointer' }}
            onChange={(e) => {
              const action = e.target.value
              e.target.value = ''
              switch (action) {
                case 'pem':
                  downloadFile(cert.certificate_pem, `${cert.common_name}.pem`)
                  break
                case 'der':
                  downloadDER(cert.id, cert.common_name)
                  break
                case 'chain':
                  downloadChain(cert.id, cert.common_name)
                  break
                case 'pkcs7':
                  downloadPKCS7(cert.id, cert.common_name)
                  break
                case 'pkcs12':
                  setExportCert(cert)
                  setShowExportModal(true)
                  break
              }
            }}
          >
            <option value="">Export</option>
            <option value="pem">PEM</option>
            <option value="der">DER</option>
            <option value="chain">Chain</option>
            <option value="pkcs7">P7B</option>
            <option value="pkcs12">P12</option>
          </select>
          {!cert.revoked_at && (
            <button
              className="btn btn-danger btn-sm"
              onClick={() => handleRevoke(cert.id)}
            >
              Revoke
            </button>
          )}
          <button
            className="btn btn-secondary btn-sm"
            onClick={() => openDeleteModal(cert)}
            title="Delete certificate"
            style={{ color: 'var(--danger)' }}
          >
            Delete
          </button>
        </div>
      </td>
    </tr>
  )

  // Stats
  const stats = useMemo(() => ({
    total: certs.length,
    valid: certs.filter(c => !c.revoked_at && new Date(c.not_after) >= new Date()).length,
    revoked: certs.filter(c => c.revoked_at).length,
    expired: certs.filter(c => !c.revoked_at && new Date(c.not_after) < new Date()).length,
  }), [certs])

  return (
    <div>
      <div className="card-header" style={{ marginBottom: '1rem' }}>
        <h1>Certificates</h1>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <button className="btn btn-primary" onClick={() => setShowModal(true)} disabled={cas.length === 0}>
            Issue Certificate
          </button>
          {formStatus && (
            <span style={{
              padding: '0.25rem 0.75rem',
              borderRadius: '4px',
              fontSize: '0.85rem',
              fontWeight: 500,
              background: formStatus.type === 'success' ? 'var(--success)' : 'var(--danger)',
              color: 'white',
            }}>
              {formStatus.message}
            </span>
          )}
        </div>
      </div>

      {cas.length === 0 && (
        <div style={{ padding: '1rem', background: 'var(--danger)', color: 'white', borderRadius: '8px', marginBottom: '1rem' }}>
          No Certificate Authorities available. Create a CA first.
        </div>
      )}

      {loading ? (
        <div className="empty-state">Loading...</div>
      ) : certs.length === 0 ? (
        <div className="card empty-state">
          <p>No certificates issued yet.</p>
        </div>
      ) : (
        <>
          {/* Stats */}
          <div className="stats-row">
            <div className="stat-card">
              <div className="stat-value">{stats.total}</div>
              <div className="stat-label">Total Certificates</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--success)' }}>{stats.valid}</div>
              <div className="stat-label">Valid</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--danger)' }}>{stats.revoked}</div>
              <div className="stat-label">Revoked</div>
            </div>
            <div className="stat-card">
              <div className="stat-value" style={{ color: 'var(--warning)' }}>{stats.expired}</div>
              <div className="stat-label">Expired</div>
            </div>
          </div>

          {/* Toolbar */}
          <div className="toolbar">
            <div className="toolbar-search" style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <div className="form-group" style={{ marginBottom: 0 }}>
                <input
                  type="text"
                  placeholder="Search by CN, organization, DNS, serial..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  style={{ paddingLeft: '2.5rem' }}
                />
              </div>
              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value as typeof statusFilter)}
                style={{ padding: '0.5rem', borderRadius: '4px', border: '1px solid var(--border)' }}
              >
                <option value="all">All Status</option>
                <option value="valid">Valid Only</option>
                <option value="expired">Expired Only</option>
                <option value="revoked">Revoked Only</option>
              </select>
            </div>
            <div className="legend">
              <div className="legend-item">
                <div className="legend-color root"></div>
                <span>Root CA</span>
              </div>
              <div className="legend-item">
                <div className="legend-color intermediate"></div>
                <span>Intermediate</span>
              </div>
              <div className="legend-item">
                <div className="legend-color cert"></div>
                <span>Certificate</span>
              </div>
            </div>
          </div>

          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div className="table-container">
              <table className="table">
                <thead>
                  <tr>
                    <th>Name</th>
                    <th>Type</th>
                    <th>Common Name</th>
                    <th>Organization</th>
                    <th>DNS Names</th>
                    <th>Valid Until</th>
                    <th>Status</th>
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRootCAs.length === 0 ? (
                    <tr>
                      <td colSpan={8} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                        {searchQuery ? 'No results found' : 'No certificates'}
                      </td>
                    </tr>
                  ) : (
                    filteredRootCAs.map(ca => renderCARow(ca))
                  )}
                </tbody>
              </table>
            </div>
            {filteredRootCAs.length > 0 && (
              <div style={{ padding: '0.75rem 1rem', borderTop: '1px solid var(--border-light)', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                Click on a row to expand/collapse hierarchy
              </div>
            )}
          </div>
        </>
      )}

      {showModal && (
        <div className="modal-overlay" onClick={() => setShowModal(false)}>
          <div className="modal" style={{ maxWidth: '600px' }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">Issue Certificate</h2>
              <button className="modal-close" onClick={() => setShowModal(false)}>&times;</button>
            </div>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>Certificate Authority *</label>
                <select
                  value={formData.ca_id}
                  onChange={e => setFormData({ ...formData, ca_id: e.target.value })}
                  required
                >
                  <option value="">Select CA...</option>
                  {cas.map(ca => (
                    <option key={ca.id} value={ca.id}>{ca.name} ({ca.type})</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>Common Name (CN) *</label>
                <input
                  type="text"
                  value={formData.common_name}
                  onChange={e => setFormData({ ...formData, common_name: e.target.value })}
                  placeholder="example.com"
                  required
                />
              </div>
              <div className="form-group">
                <label>Organization (O)</label>
                <input
                  type="text"
                  value={formData.organization}
                  onChange={e => setFormData({ ...formData, organization: e.target.value })}
                  placeholder="My Company"
                />
              </div>
              <div className="form-group">
                <label>Organizational Unit (OU)</label>
                <input
                  type="text"
                  value={formData.organizational_unit}
                  onChange={e => setFormData({ ...formData, organizational_unit: e.target.value })}
                  placeholder="IT Department"
                />
              </div>
              <div className="form-group">
                <label>Country (C) - 2-letter code</label>
                <input
                  type="text"
                  maxLength={2}
                  value={formData.country}
                  onChange={e => setFormData({ ...formData, country: e.target.value.toUpperCase() })}
                  placeholder="RS"
                />
              </div>

              <button
                type="button"
                className="btn btn-secondary"
                style={{ marginBottom: '1rem' }}
                onClick={() => setShowAdvanced(!showAdvanced)}
              >
                {showAdvanced ? 'Hide' : 'Show'} Advanced Fields
              </button>

              {showAdvanced && (
                <>
                  <div className="form-group">
                    <label>State/Province (ST)</label>
                    <input
                      type="text"
                      value={formData.state}
                      onChange={e => setFormData({ ...formData, state: e.target.value })}
                      placeholder="Vojvodina"
                    />
                  </div>
                  <div className="form-group">
                    <label>Locality/City (L)</label>
                    <input
                      type="text"
                      value={formData.locality}
                      onChange={e => setFormData({ ...formData, locality: e.target.value })}
                      placeholder="Novi Sad"
                    />
                  </div>
                  <div className="form-group">
                    <label>Street Address</label>
                    <input
                      type="text"
                      value={formData.street_address}
                      onChange={e => setFormData({ ...formData, street_address: e.target.value })}
                      placeholder="Bulevar Oslobodjenja 1"
                    />
                  </div>
                  <div className="form-group">
                    <label>Postal Code</label>
                    <input
                      type="text"
                      value={formData.postal_code}
                      onChange={e => setFormData({ ...formData, postal_code: e.target.value })}
                      placeholder="21000"
                    />
                  </div>
                  <div className="form-group">
                    <label>Email Address</label>
                    <input
                      type="email"
                      value={formData.email_address}
                      onChange={e => setFormData({ ...formData, email_address: e.target.value })}
                      placeholder="admin@example.com"
                    />
                  </div>
                </>
              )}

              <div className="form-group">
                <label>Type</label>
                <select
                  value={formData.type}
                  onChange={e => setFormData({ ...formData, type: e.target.value as 'server' | 'client' })}
                >
                  <option value="server">Server</option>
                  <option value="client">Client</option>
                </select>
              </div>
              <div className="form-group">
                <label>Key Algorithm</label>
                <select
                  value={formData.key_algorithm}
                  onChange={e => setFormData({ ...formData, key_algorithm: e.target.value })}
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
                  value={formData.signature_algorithm}
                  onChange={e => setFormData({ ...formData, signature_algorithm: e.target.value })}
                >
                  <option value="sha256">SHA-256 (Recommended)</option>
                  <option value="sha384">SHA-384</option>
                  <option value="sha512">SHA-512</option>
                </select>
              </div>
              <div className="form-group">
                <label>DNS Names (comma-separated)</label>
                <input
                  type="text"
                  value={formData.dns_names}
                  onChange={e => setFormData({ ...formData, dns_names: e.target.value })}
                  placeholder="example.com, www.example.com"
                />
              </div>
              <div className="form-group">
                <label>IP Addresses (comma-separated)</label>
                <input
                  type="text"
                  value={formData.ip_addresses}
                  onChange={e => setFormData({ ...formData, ip_addresses: e.target.value })}
                  placeholder="192.168.1.1, 10.0.0.1"
                />
              </div>
              <div className="form-group">
                <label>Validity (days)</label>
                <input
                  type="number"
                  value={formData.validity_days}
                  onChange={e => setFormData({ ...formData, validity_days: parseInt(e.target.value) })}
                  min={1}
                />
              </div>
              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Issue</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {showResultModal && newCertResult && (
        <div className="modal-overlay" onClick={() => setShowResultModal(false)}>
          <div className="modal" style={{ maxWidth: '700px' }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">Certificate Issued</h2>
              <button className="modal-close" onClick={() => setShowResultModal(false)}>&times;</button>
            </div>
            <div className="alert alert-success">
              Certificate for {newCertResult.certificate.common_name} issued successfully!
            </div>
            <p style={{ marginBottom: '1rem', color: 'var(--danger)', fontWeight: 500 }}>
              Save the private key now! It will not be stored on the server.
            </p>
            <div className="form-group">
              <label>Certificate (PEM)</label>
              <pre>{newCertResult.certificate_pem}</pre>
            </div>
            <div className="form-group">
              <label>Private Key (PEM)</label>
              <pre>{newCertResult.private_key_pem}</pre>
            </div>
            <div className="modal-actions">
              <button className="btn btn-secondary" onClick={() => downloadFile(newCertResult.certificate_pem, `${newCertResult.certificate.common_name}.crt`)}>
                Download Certificate
              </button>
              <button className="btn btn-primary" onClick={() => downloadFile(newCertResult.private_key_pem, `${newCertResult.certificate.common_name}.key`)}>
                Download Private Key
              </button>
            </div>
          </div>
        </div>
      )}

      {showExportModal && exportCert && (
        <div className="modal-overlay" onClick={() => setShowExportModal(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">Export PKCS12</h2>
              <button className="modal-close" onClick={() => setShowExportModal(false)}>&times;</button>
            </div>
            <p style={{ marginBottom: '1rem', color: 'var(--text-muted)' }}>
              Export {exportCert.common_name} as PKCS12 (.p12) file
            </p>
            <div className="form-group">
              <label>Private Key (PEM) *</label>
              <textarea
                value={exportPrivateKey}
                onChange={e => setExportPrivateKey(e.target.value)}
                placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END RSA PRIVATE KEY-----"
                style={{
                  width: '100%',
                  minHeight: '150px',
                  padding: '0.5rem 0.75rem',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize: '0.75rem',
                  background: 'var(--input-bg)',
                  color: 'var(--text)',
                }}
                required
              />
            </div>
            <div className="form-group">
              <label>Password (default: changeit)</label>
              <input
                type="password"
                value={exportPassword}
                onChange={e => setExportPassword(e.target.value)}
                placeholder="Enter password for .p12 file"
              />
            </div>
            <div className="modal-actions" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <button type="button" className="btn btn-secondary" onClick={() => setShowExportModal(false)}>Cancel</button>
              <button
                className="btn btn-primary"
                onClick={handleExportPKCS12}
                disabled={!exportPrivateKey}
              >
                Export PKCS12
              </button>
              {exportError && (
                <span style={{
                  padding: '0.25rem 0.75rem',
                  borderRadius: '4px',
                  fontSize: '0.85rem',
                  fontWeight: 500,
                  background: 'var(--danger)',
                  color: 'white',
                }}>
                  {exportError}
                </span>
              )}
            </div>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {showDeleteModal && deleteCert && (
        <div className="modal-overlay" onClick={() => setShowDeleteModal(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title" style={{ color: 'var(--danger)' }}>Delete Certificate</h2>
              <button className="modal-close" onClick={() => setShowDeleteModal(false)}>&times;</button>
            </div>

            <div style={{
              padding: '1rem',
              background: 'var(--danger-light)',
              borderRadius: '6px',
              marginBottom: '1rem',
              border: '1px solid var(--danger)'
            }}>
              <p style={{ color: 'var(--danger)', fontWeight: 500, marginBottom: '0.5rem' }}>
                Warning: This action cannot be undone!
              </p>
              <p style={{ color: 'var(--text-muted)', fontSize: '0.875rem' }}>
                You are about to permanently delete the certificate <strong>{deleteCert.common_name}</strong>.
              </p>
            </div>

            <div className="form-group">
              <label>Reason for deletion *</label>
              <textarea
                value={deleteReason}
                onChange={e => setDeleteReason(e.target.value)}
                placeholder="Enter the reason for deleting this certificate..."
                style={{
                  width: '100%',
                  minHeight: '80px',
                  padding: '0.5rem 0.75rem',
                  border: '1px solid var(--border)',
                  borderRadius: '6px',
                  fontFamily: 'inherit',
                  fontSize: '0.875rem',
                  background: 'var(--input-bg)',
                  color: 'var(--text)',
                  resize: 'vertical',
                }}
                required
              />
            </div>

            <div className="form-group">
              <label>
                To confirm deletion, please type: <strong style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  background: 'var(--bg)',
                  padding: '0.125rem 0.375rem',
                  borderRadius: '4px',
                  fontSize: '0.875rem'
                }}>
                  {deleteCert.common_name}-{new Date().getFullYear()}{String(new Date().getMonth() + 1).padStart(2, '0')}{String(new Date().getDate()).padStart(2, '0')}
                </strong>
              </label>
              <input
                type="text"
                value={deleteConfirmation}
                onChange={e => setDeleteConfirmation(e.target.value)}
                placeholder="Enter confirmation text..."
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              />
            </div>

            <div className="modal-actions" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <button type="button" className="btn btn-secondary" onClick={() => setShowDeleteModal(false)}>
                Cancel
              </button>
              <button
                className="btn btn-danger"
                onClick={handleDelete}
                disabled={!deleteReason.trim() || !deleteConfirmation}
              >
                Delete Certificate
              </button>
              {deleteError && (
                <span style={{
                  padding: '0.25rem 0.75rem',
                  borderRadius: '4px',
                  fontSize: '0.85rem',
                  fontWeight: 500,
                  background: 'var(--danger)',
                  color: 'white',
                }}>
                  {deleteError}
                </span>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default Certificates
