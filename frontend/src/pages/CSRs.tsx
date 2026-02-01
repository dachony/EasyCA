import { useState, useEffect } from 'react'

interface CA {
  id: string
  name: string
  type: string
}

interface CSR {
  id: string
  name: string
  csr_pem: string
  common_name: string
  organization: string
  organizational_unit: string
  country: string
  state: string
  locality: string
  dns_names: string[]
  ip_addresses: string[]
  status: 'pending' | 'signed' | 'rejected'
  signed_certificate_id?: string
  created_at: string
}

interface GenerateCSRResponse {
  csr: CSR
  csr_pem: string
  private_key_pem: string
}

type FormStatus = { type: 'success' | 'error', message: string } | null

function CSRs() {
  const [csrs, setCSRs] = useState<CSR[]>([])
  const [cas, setCAs] = useState<CA[]>([])
  const [loading, setLoading] = useState(true)
  const [showGenerateModal, setShowGenerateModal] = useState(false)
  const [showImportModal, setShowImportModal] = useState(false)
  const [showSignModal, setShowSignModal] = useState(false)
  const [showResultModal, setShowResultModal] = useState(false)
  const [selectedCSR, setSelectedCSR] = useState<CSR | null>(null)
  const [generateResult, setGenerateResult] = useState<GenerateCSRResponse | null>(null)
  const [formStatus, setFormStatus] = useState<FormStatus>(null)
  const [showAdvanced, setShowAdvanced] = useState(false)

  const [generateForm, setGenerateForm] = useState({
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
    dns_names: '',
    ip_addresses: '',
    key_algorithm: 'rsa2048',
  })

  const [importForm, setImportForm] = useState({
    name: '',
    csr_pem: '',
  })

  const [signForm, setSignForm] = useState({
    ca_id: '',
    type: 'server' as 'server' | 'client',
    validity_days: 365,
  })

  const fetchData = () => {
    Promise.all([
      fetch('/api/csr').then(r => r.json()),
      fetch('/api/ca').then(r => r.json()),
    ]).then(([csrData, caData]) => {
      setCSRs(csrData || [])
      setCAs(caData || [])
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

  const handleGenerate = async (e: React.FormEvent) => {
    e.preventDefault()
    setFormStatus(null)

    try {
      const res = await fetch('/api/csr/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ...generateForm,
          dns_names: generateForm.dns_names ? generateForm.dns_names.split(',').map(s => s.trim()) : [],
          ip_addresses: generateForm.ip_addresses ? generateForm.ip_addresses.split(',').map(s => s.trim()) : [],
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to generate CSR')
      }

      const result = await res.json()
      setGenerateResult(result)
      setShowGenerateModal(false)
      setShowResultModal(true)
      setGenerateForm({
        name: '', common_name: '', organization: '', organizational_unit: '',
        country: '', state: '', locality: '', street_address: '', postal_code: '',
        email_address: '', dns_names: '', ip_addresses: '', key_algorithm: 'rsa2048',
      })
      fetchData()
    } catch (err) {
      setStatusWithAutoClear({ type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const handleImport = async (e: React.FormEvent) => {
    e.preventDefault()
    setFormStatus(null)

    try {
      const res = await fetch('/api/csr/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(importForm),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to import CSR')
      }

      setShowImportModal(false)
      setImportForm({ name: '', csr_pem: '' })
      fetchData()
      setStatusWithAutoClear({ type: 'success', message: 'Imported' })
    } catch (err) {
      setStatusWithAutoClear({ type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const handleSign = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!selectedCSR) return
    setFormStatus(null)

    try {
      const res = await fetch(`/api/csr/${selectedCSR.id}/sign`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(signForm),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to sign CSR')
      }

      setShowSignModal(false)
      setSelectedCSR(null)
      setSignForm({ ca_id: '', type: 'server', validity_days: 365 })
      fetchData()
      setStatusWithAutoClear({ type: 'success', message: 'Signed' })
    } catch (err) {
      setStatusWithAutoClear({ type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Are you sure you want to delete this CSR?')) return

    try {
      const res = await fetch(`/api/csr/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('Failed to delete CSR')
      fetchData()
      setStatusWithAutoClear({ type: 'success', message: 'Deleted' })
    } catch (err) {
      setStatusWithAutoClear({ type: 'error', message: err instanceof Error ? err.message : 'Error' })
    }
  }

  const downloadCSR = async (csr: CSR) => {
    const blob = new Blob([csr.csr_pem], { type: 'application/x-pem-file' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${csr.name}.csr`
    a.click()
  }

  const downloadFile = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'application/x-pem-file' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
  }

  const getStatusBadge = (status: string) => {
    switch (status) {
      case 'pending':
        return <span className="badge badge-warning">Pending</span>
      case 'signed':
        return <span className="badge badge-success">Signed</span>
      case 'rejected':
        return <span className="badge badge-danger">Rejected</span>
      default:
        return <span className="badge">{status}</span>
    }
  }

  return (
    <div>
      <div className="card-header" style={{ marginBottom: '1rem' }}>
        <h1>Certificate Signing Requests</h1>
        <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
          <button className="btn btn-primary" onClick={() => setShowGenerateModal(true)}>
            Generate CSR
          </button>
          <button className="btn btn-secondary" onClick={() => setShowImportModal(true)}>
            Import CSR
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

      {loading ? (
        <div className="empty-state">Loading...</div>
      ) : csrs.length === 0 ? (
        <div className="card empty-state">
          <p>No Certificate Signing Requests yet.</p>
          <p>Generate a new CSR or import an existing one.</p>
        </div>
      ) : (
        <div className="card">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Common Name</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {csrs.map(csr => (
                <tr key={csr.id}>
                  <td><strong>{csr.name}</strong></td>
                  <td>{csr.common_name}</td>
                  <td>{getStatusBadge(csr.status)}</td>
                  <td>{new Date(csr.created_at).toLocaleDateString()}</td>
                  <td style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <button className="btn btn-secondary" onClick={() => downloadCSR(csr)}>
                      Download
                    </button>
                    {csr.status === 'pending' && cas.length > 0 && (
                      <button
                        className="btn btn-primary"
                        onClick={() => { setSelectedCSR(csr); setShowSignModal(true); }}
                      >
                        Sign
                      </button>
                    )}
                    <button className="btn btn-danger" onClick={() => handleDelete(csr.id)}>
                      Delete
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Generate CSR Modal */}
      {showGenerateModal && (
        <div className="modal-overlay" onClick={() => setShowGenerateModal(false)}>
          <div className="modal" style={{ maxWidth: '600px' }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">Generate CSR</h2>
              <button className="modal-close" onClick={() => setShowGenerateModal(false)}>&times;</button>
            </div>
            <form onSubmit={handleGenerate}>
              <div className="form-group">
                <label>Name *</label>
                <input
                  type="text"
                  value={generateForm.name}
                  onChange={e => setGenerateForm({ ...generateForm, name: e.target.value })}
                  placeholder="My CSR"
                  required
                />
              </div>
              <div className="form-group">
                <label>Common Name (CN) *</label>
                <input
                  type="text"
                  value={generateForm.common_name}
                  onChange={e => setGenerateForm({ ...generateForm, common_name: e.target.value })}
                  placeholder="example.com"
                  required
                />
              </div>
              <div className="form-group">
                <label>Organization</label>
                <input
                  type="text"
                  value={generateForm.organization}
                  onChange={e => setGenerateForm({ ...generateForm, organization: e.target.value })}
                  placeholder="My Company"
                />
              </div>
              <div className="form-group">
                <label>Organizational Unit</label>
                <input
                  type="text"
                  value={generateForm.organizational_unit}
                  onChange={e => setGenerateForm({ ...generateForm, organizational_unit: e.target.value })}
                  placeholder="IT Department"
                />
              </div>
              <div className="form-group">
                <label>Country (2-letter code)</label>
                <input
                  type="text"
                  maxLength={2}
                  value={generateForm.country}
                  onChange={e => setGenerateForm({ ...generateForm, country: e.target.value.toUpperCase() })}
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
                    <label>State/Province</label>
                    <input
                      type="text"
                      value={generateForm.state}
                      onChange={e => setGenerateForm({ ...generateForm, state: e.target.value })}
                      placeholder="Vojvodina"
                    />
                  </div>
                  <div className="form-group">
                    <label>Locality/City</label>
                    <input
                      type="text"
                      value={generateForm.locality}
                      onChange={e => setGenerateForm({ ...generateForm, locality: e.target.value })}
                      placeholder="Novi Sad"
                    />
                  </div>
                  <div className="form-group">
                    <label>Street Address</label>
                    <input
                      type="text"
                      value={generateForm.street_address}
                      onChange={e => setGenerateForm({ ...generateForm, street_address: e.target.value })}
                      placeholder="Bulevar Oslobodjenja 1"
                    />
                  </div>
                  <div className="form-group">
                    <label>Postal Code</label>
                    <input
                      type="text"
                      value={generateForm.postal_code}
                      onChange={e => setGenerateForm({ ...generateForm, postal_code: e.target.value })}
                      placeholder="21000"
                    />
                  </div>
                  <div className="form-group">
                    <label>Email Address</label>
                    <input
                      type="email"
                      value={generateForm.email_address}
                      onChange={e => setGenerateForm({ ...generateForm, email_address: e.target.value })}
                      placeholder="admin@example.com"
                    />
                  </div>
                </>
              )}

              <div className="form-group">
                <label>DNS Names (comma-separated)</label>
                <input
                  type="text"
                  value={generateForm.dns_names}
                  onChange={e => setGenerateForm({ ...generateForm, dns_names: e.target.value })}
                  placeholder="example.com, www.example.com"
                />
              </div>
              <div className="form-group">
                <label>IP Addresses (comma-separated)</label>
                <input
                  type="text"
                  value={generateForm.ip_addresses}
                  onChange={e => setGenerateForm({ ...generateForm, ip_addresses: e.target.value })}
                  placeholder="192.168.1.1, 10.0.0.1"
                />
              </div>
              <div className="form-group">
                <label>Key Algorithm</label>
                <select
                  value={generateForm.key_algorithm}
                  onChange={e => setGenerateForm({ ...generateForm, key_algorithm: e.target.value })}
                >
                  <option value="rsa2048">RSA 2048 (Recommended)</option>
                  <option value="rsa3072">RSA 3072</option>
                  <option value="rsa4096">RSA 4096</option>
                  <option value="ecdsa-p256">ECDSA P-256</option>
                  <option value="ecdsa-p384">ECDSA P-384</option>
                  <option value="ecdsa-p521">ECDSA P-521</option>
                </select>
              </div>

              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setShowGenerateModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Generate</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Import CSR Modal */}
      {showImportModal && (
        <div className="modal-overlay" onClick={() => setShowImportModal(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">Import CSR</h2>
              <button className="modal-close" onClick={() => setShowImportModal(false)}>&times;</button>
            </div>
            <form onSubmit={handleImport}>
              <div className="form-group">
                <label>Name *</label>
                <input
                  type="text"
                  value={importForm.name}
                  onChange={e => setImportForm({ ...importForm, name: e.target.value })}
                  placeholder="Imported CSR"
                  required
                />
              </div>
              <div className="form-group">
                <label>CSR (PEM) *</label>
                <textarea
                  value={importForm.csr_pem}
                  onChange={e => setImportForm({ ...importForm, csr_pem: e.target.value })}
                  placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"
                  style={{
                    width: '100%',
                    minHeight: '200px',
                    padding: '0.5rem 0.75rem',
                    border: '1px solid var(--border)',
                    borderRadius: '6px',
                    fontFamily: 'monospace',
                    fontSize: '0.75rem',
                    background: 'var(--input-bg)',
                    color: 'var(--text)',
                  }}
                  required
                />
              </div>
              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setShowImportModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Import</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Sign CSR Modal */}
      {showSignModal && selectedCSR && (
        <div className="modal-overlay" onClick={() => setShowSignModal(false)}>
          <div className="modal" onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">Sign CSR</h2>
              <button className="modal-close" onClick={() => setShowSignModal(false)}>&times;</button>
            </div>
            <p style={{ marginBottom: '1rem', color: 'var(--text-muted)' }}>
              Sign CSR: <strong>{selectedCSR.name}</strong> ({selectedCSR.common_name})
            </p>
            <form onSubmit={handleSign}>
              <div className="form-group">
                <label>Certificate Authority *</label>
                <select
                  value={signForm.ca_id}
                  onChange={e => setSignForm({ ...signForm, ca_id: e.target.value })}
                  required
                >
                  <option value="">Select CA...</option>
                  {cas.map(ca => (
                    <option key={ca.id} value={ca.id}>{ca.name} ({ca.type})</option>
                  ))}
                </select>
              </div>
              <div className="form-group">
                <label>Certificate Type</label>
                <select
                  value={signForm.type}
                  onChange={e => setSignForm({ ...signForm, type: e.target.value as 'server' | 'client' })}
                >
                  <option value="server">Server</option>
                  <option value="client">Client</option>
                </select>
              </div>
              <div className="form-group">
                <label>Validity (days)</label>
                <input
                  type="number"
                  value={signForm.validity_days}
                  onChange={e => setSignForm({ ...signForm, validity_days: parseInt(e.target.value) })}
                  min={1}
                />
              </div>
              <div className="modal-actions">
                <button type="button" className="btn btn-secondary" onClick={() => setShowSignModal(false)}>Cancel</button>
                <button type="submit" className="btn btn-primary">Sign & Issue Certificate</button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Result Modal */}
      {showResultModal && generateResult && (
        <div className="modal-overlay" onClick={() => setShowResultModal(false)}>
          <div className="modal" style={{ maxWidth: '700px' }} onClick={e => e.stopPropagation()}>
            <div className="modal-header">
              <h2 className="modal-title">CSR Generated</h2>
              <button className="modal-close" onClick={() => setShowResultModal(false)}>&times;</button>
            </div>
            <div className="alert alert-success">
              CSR for {generateResult.csr.common_name} generated successfully!
            </div>
            <p style={{ marginBottom: '1rem', color: 'var(--danger)', fontWeight: 500 }}>
              Save the private key now! It will not be stored on the server.
            </p>
            <div className="form-group">
              <label>CSR (PEM)</label>
              <pre style={{ maxHeight: '150px', overflow: 'auto' }}>{generateResult.csr_pem}</pre>
            </div>
            <div className="form-group">
              <label>Private Key (PEM)</label>
              <pre style={{ maxHeight: '150px', overflow: 'auto' }}>{generateResult.private_key_pem}</pre>
            </div>
            <div className="modal-actions">
              <button className="btn btn-secondary" onClick={() => downloadFile(generateResult.csr_pem, `${generateResult.csr.name}.csr`)}>
                Download CSR
              </button>
              <button className="btn btn-primary" onClick={() => downloadFile(generateResult.private_key_pem, `${generateResult.csr.name}.key`)}>
                Download Private Key
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default CSRs
