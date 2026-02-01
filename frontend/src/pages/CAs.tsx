import { useState, useEffect, useMemo } from 'react'

interface CA {
  id: string
  name: string
  type: 'root' | 'intermediate'
  parent_id?: string
  common_name?: string
  organization?: string
  dns_names?: string[]
  key_algorithm?: string
  signature_algorithm?: string
  certificate_pem: string
  not_before: string
  not_after: string
  created_at: string
}

interface Certificate {
  id: string
  serial_number: string
  ca_id: string
  common_name: string
  organization?: string
  dns_names?: string[]
  type: 'server' | 'client'
  certificate_pem: string
  not_before: string
  not_after: string
  revoked_at?: string
  created_at: string
}

type FormStatus = { type: 'success' | 'error', message: string } | null

function CAs() {
  const [cas, setCAs] = useState<CA[]>([])
  const [certs, setCerts] = useState<Certificate[]>([])
  const [loading, setLoading] = useState(true)
  const [showModal, setShowModal] = useState(false)
  const [modalType, setModalType] = useState<'root' | 'intermediate'>('root')
  const [formStatus, setFormStatus] = useState<FormStatus>(null)
  const [expandedCAs, setExpandedCAs] = useState<Set<string>>(new Set())
  const [showAdvanced, setShowAdvanced] = useState(false)
  const [searchQuery, setSearchQuery] = useState('')
  const [formData, setFormData] = useState({
    name: '',
    common_name: '',
    organization: '',
    organizational_unit: '',
    country: '',
    state: '',
    locality: '',
    street_address: '',
    postal_code: '',
    email_address: '',
    validity_days: 3650,
    parent_id: '',
    key_algorithm: 'rsa2048',
    signature_algorithm: 'sha256',
  })

  const fetchData = () => {
    Promise.all([
      fetch('/api/ca').then(r => r.json()),
      fetch('/api/certificates').then(r => r.json()),
    ]).then(([casData, certsData]) => {
      setCAs(casData || [])
      setCerts(certsData || [])
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

    const endpoint = modalType === 'root' ? '/api/ca/root' : '/api/ca/intermediate'

    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to create CA')
      }

      setShowModal(false)
      setFormData({
        name: '', common_name: '', organization: '', organizational_unit: '',
        country: '', state: '', locality: '', street_address: '', postal_code: '',
        email_address: '', validity_days: 3650, parent_id: '',
        key_algorithm: 'rsa2048', signature_algorithm: 'sha256',
      })
      setShowAdvanced(false)
      fetchData()
      setStatusWithAutoClear({ type: 'success', message: `${modalType === 'root' ? 'Root' : 'Intermediate'} CA created` })
    } catch (err) {
      setStatusWithAutoClear({ type: 'error', message: err instanceof Error ? err.message : 'Error' })
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
  const getCertificates = (caId: string) => certs.filter(c => c.ca_id === caId)

  // Filter logic
  const filteredRootCAs = useMemo(() => {
    const query = searchQuery.toLowerCase().trim()
    if (!query) return cas.filter(c => c.type === 'root')

    // Find all CAs and certs that match
    const matchingCAIds = new Set<string>()
    const matchingCertCAIds = new Set<string>()

    cas.forEach(ca => {
      const matches =
        ca.name.toLowerCase().includes(query) ||
        (ca.common_name?.toLowerCase().includes(query)) ||
        (ca.organization?.toLowerCase().includes(query)) ||
        (ca.dns_names?.some(d => d.toLowerCase().includes(query)))

      if (matches) {
        matchingCAIds.add(ca.id)
        // Also add parent chain
        let current = ca
        while (current.parent_id) {
          matchingCAIds.add(current.parent_id)
          current = cas.find(c => c.id === current.parent_id) || current
          if (!current.parent_id) break
        }
      }
    })

    certs.forEach(cert => {
      const matches =
        cert.common_name.toLowerCase().includes(query) ||
        (cert.organization?.toLowerCase().includes(query)) ||
        (cert.dns_names?.some(d => d.toLowerCase().includes(query)))

      if (matches) {
        matchingCertCAIds.add(cert.ca_id)
        // Find root CA for this cert
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

    // Auto-expand CAs with matching children
    if (query) {
      setExpandedCAs(new Set([...matchingCAIds, ...matchingCertCAIds]))
    }

    return cas.filter(c => c.type === 'root' && matchingCAIds.has(c.id))
  }, [cas, certs, searchQuery])

  const formatDNSNames = (dnsNames?: string[]) => {
    if (!dnsNames || dnsNames.length === 0) return '-'
    if (dnsNames.length <= 2) return dnsNames.join(', ')
    return `${dnsNames[0]}, ${dnsNames[1]}, +${dnsNames.length - 2} more`
  }

  const downloadCA = (ca: CA) => {
    const blob = new Blob([ca.certificate_pem], { type: 'application/x-pem-file' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${ca.name}.pem`
    a.click()
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
              <strong>{highlightMatch(ca.name)}</strong>
            </div>
          </td>
          <td>
            <span className={`badge ${ca.type === 'root' ? 'badge-primary' : 'badge-success'}`}>
              {ca.type === 'root' ? 'Root CA' : 'Intermediate'}
            </span>
          </td>
          <td>{ca.common_name ? highlightMatch(ca.common_name) : '-'}</td>
          <td>{ca.organization ? highlightMatch(ca.organization) : '-'}</td>
          <td>{formatDNSNames(ca.dns_names)}</td>
          <td>{new Date(ca.not_after).toLocaleDateString()}</td>
          <td onClick={e => e.stopPropagation()}>
            <button className="btn btn-secondary btn-sm" onClick={() => downloadCA(ca)}>
              Download
            </button>
          </td>
        </tr>
        {isExpanded && childIntermediates.map(intermediate => renderCARow(intermediate, level + 1))}
        {isExpanded && childCerts.map(cert => (
          <tr key={cert.id} className={getRowClass('cert')}>
            <td style={{ paddingLeft: `${(level + 1) * 1.5 + 1}rem` }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ width: '1.25rem' }} />
                <span>{highlightMatch(cert.common_name)}</span>
              </div>
            </td>
            <td>
              <span className={`badge ${cert.type === 'server' ? 'badge-info' : 'badge-warning'}`}>
                {cert.type}
              </span>
              {cert.revoked_at && <span className="badge badge-danger" style={{ marginLeft: '0.25rem' }}>Revoked</span>}
            </td>
            <td>{highlightMatch(cert.common_name)}</td>
            <td>{cert.organization ? highlightMatch(cert.organization) : '-'}</td>
            <td>{formatDNSNames(cert.dns_names)}</td>
            <td>{new Date(cert.not_after).toLocaleDateString()}</td>
            <td>-</td>
          </tr>
        ))}
      </>
    )
  }

  // Stats
  const stats = useMemo(() => ({
    rootCAs: cas.filter(c => c.type === 'root').length,
    intermediateCAs: cas.filter(c => c.type === 'intermediate').length,
    certificates: certs.length,
  }), [cas, certs])

  return (
    <div>
      <div className="card-header" style={{ marginBottom: '1rem' }}>
        <h1>Certificate Authorities</h1>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button className="btn btn-primary" onClick={() => { setModalType('root'); setShowModal(true); }}>
            Create Root CA
          </button>
          <button className="btn btn-secondary" onClick={() => { setModalType('intermediate'); setShowModal(true); }} disabled={stats.rootCAs === 0}>
            Create Intermediate CA
          </button>
          {formStatus && (
            <span style={{
              marginLeft: '0.5rem',
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

      {loading ? (
        <div className="empty-state">Loading...</div>
      ) : cas.length === 0 ? (
        <div className="card empty-state">
          <p>No Certificate Authorities yet.</p>
          <p>Create a Root CA to get started.</p>
        </div>
      ) : (
        <>
          {/* Stats */}
          <div className="stats-row">
            <div className="stat-card">
              <div className="stat-value">{stats.rootCAs}</div>
              <div className="stat-label">Root CAs</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{stats.intermediateCAs}</div>
              <div className="stat-label">Intermediate CAs</div>
            </div>
            <div className="stat-card">
              <div className="stat-value">{stats.certificates}</div>
              <div className="stat-label">Certificates</div>
            </div>
          </div>

          {/* Toolbar */}
          <div className="toolbar">
            <div className="toolbar-search">
              <div className="form-group" style={{ marginBottom: 0 }}>
                <input
                  type="text"
                  placeholder="Search by name, CN, organization, DNS..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                  style={{ paddingLeft: '2.5rem' }}
                />
              </div>
            </div>
            <div className="legend">
              <div className="legend-item">
                <div className="legend-color root"></div>
                <span>Root CA</span>
              </div>
              <div className="legend-item">
                <div className="legend-color intermediate"></div>
                <span>Intermediate CA</span>
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
                    <th>Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredRootCAs.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: 'center', padding: '2rem', color: 'var(--text-muted)' }}>
                        {searchQuery ? 'No results found' : 'No Certificate Authorities'}
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
              <h2 className="modal-title">Create {modalType === 'root' ? 'Root' : 'Intermediate'} CA</h2>
              <button className="modal-close" onClick={() => setShowModal(false)}>&times;</button>
            </div>
            <form onSubmit={handleSubmit}>
              <div className="form-group">
                <label>Name *</label>
                <input
                  type="text"
                  value={formData.name}
                  onChange={e => setFormData({ ...formData, name: e.target.value })}
                  placeholder="My Root CA"
                  required
                />
              </div>
              <div className="form-group">
                <label>Common Name (CN) *</label>
                <input
                  type="text"
                  value={formData.common_name}
                  onChange={e => setFormData({ ...formData, common_name: e.target.value })}
                  placeholder="My Root CA"
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
                <label>Validity (days)</label>
                <input
                  type="number"
                  value={formData.validity_days}
                  onChange={e => setFormData({ ...formData, validity_days: parseInt(e.target.value) })}
                  min={1}
                />
              </div>
              {modalType === 'intermediate' && (
                <div className="form-group">
                  <label>Parent CA *</label>
                  <select
                    value={formData.parent_id}
                    onChange={e => setFormData({ ...formData, parent_id: e.target.value })}
                    required
                  >
                    <option value="">Select parent CA...</option>
                    {cas.map(ca => (
                      <option key={ca.id} value={ca.id}>{ca.name} ({ca.type})</option>
                    ))}
                  </select>
                </div>
              )}
              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setShowModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Create</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default CAs
