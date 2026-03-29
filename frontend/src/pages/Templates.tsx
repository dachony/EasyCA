import { useState, useEffect } from 'react'

interface Template {
  id: string
  name: string
  description: string
  type: string
  key_algorithm: string
  signature_algorithm: string
  validity_days: number
  organization: string
  organizational_unit: string
  country: string
  state: string
  locality: string
  dns_names: string[]
  ip_addresses: string[]
  created_at: string
  updated_at: string
}

const keyAlgorithms = [
  { value: 'rsa2048', label: 'RSA 2048' },
  { value: 'rsa3072', label: 'RSA 3072' },
  { value: 'rsa4096', label: 'RSA 4096' },
  { value: 'ecdsa-p256', label: 'ECDSA P-256' },
  { value: 'ecdsa-p384', label: 'ECDSA P-384' },
  { value: 'ecdsa-p521', label: 'ECDSA P-521' },
]

const sigAlgorithms = [
  { value: 'sha256', label: 'SHA-256' },
  { value: 'sha384', label: 'SHA-384' },
  { value: 'sha512', label: 'SHA-512' },
]

function Templates() {
  const [templates, setTemplates] = useState<Template[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const emptyForm = {
    name: '',
    description: '',
    type: 'server' as string,
    key_algorithm: 'rsa2048',
    signature_algorithm: 'sha256',
    validity_days: 365,
    organization: '',
    organizational_unit: '',
    country: '',
    state: '',
    locality: '',
    dns_names: '' as string,
    ip_addresses: '' as string,
  }
  const [form, setForm] = useState(emptyForm)

  const fetchTemplates = () => {
    fetch('/api/templates')
      .then(r => r.json())
      .then(data => {
        setTemplates(data || [])
        setLoading(false)
      })
      .catch(() => setLoading(false))
  }

  useEffect(() => { fetchTemplates() }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    setSuccess('')

    const body = {
      ...form,
      dns_names: form.dns_names ? form.dns_names.split(',').map(s => s.trim()).filter(Boolean) : [],
      ip_addresses: form.ip_addresses ? form.ip_addresses.split(',').map(s => s.trim()).filter(Boolean) : [],
    }

    try {
      const url = editingId ? `/api/templates/${editingId}` : '/api/templates'
      const method = editingId ? 'PUT' : 'POST'
      const res = await fetch(url, {
        method,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to save template')
      }
      setSuccess(editingId ? 'Template updated' : 'Template created')
      setShowForm(false)
      setEditingId(null)
      setForm(emptyForm)
      fetchTemplates()
    } catch (err: any) {
      setError(err.message)
    }
  }

  const handleEdit = (t: Template) => {
    setForm({
      name: t.name,
      description: t.description,
      type: t.type,
      key_algorithm: t.key_algorithm,
      signature_algorithm: t.signature_algorithm,
      validity_days: t.validity_days,
      organization: t.organization,
      organizational_unit: t.organizational_unit,
      country: t.country,
      state: t.state,
      locality: t.locality,
      dns_names: (t.dns_names || []).join(', '),
      ip_addresses: (t.ip_addresses || []).join(', '),
    })
    setEditingId(t.id)
    setShowForm(true)
    setError('')
    setSuccess('')
  }

  const handleDelete = async (id: string, name: string) => {
    if (!confirm(`Delete template "${name}"?`)) return
    try {
      const res = await fetch(`/api/templates/${id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error('Failed to delete')
      setSuccess('Template deleted')
      fetchTemplates()
    } catch (err: any) {
      setError(err.message)
    }
  }

  const handleUseTemplate = (t: Template) => {
    // Store template data and redirect to certificates page
    sessionStorage.setItem('certificate_template', JSON.stringify(t))
    window.location.href = '/certificates'
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h1>Certificate Templates</h1>
        <button className="btn btn-primary" onClick={() => {
          setShowForm(!showForm)
          setEditingId(null)
          setForm(emptyForm)
          setError('')
          setSuccess('')
        }}>
          {showForm ? 'Cancel' : '+ New Template'}
        </button>
      </div>

      {error && <div className="alert alert-danger" style={{ marginBottom: '1rem' }}>{error}</div>}
      {success && <div className="alert alert-success" style={{ marginBottom: '1rem' }}>{success}</div>}

      {showForm && (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <h3 style={{ marginBottom: '1rem' }}>{editingId ? 'Edit Template' : 'Create Template'}</h3>
          <form onSubmit={handleSubmit}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div className="form-group">
                <label>Template Name *</label>
                <input className="form-control" value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} required />
              </div>
              <div className="form-group">
                <label>Certificate Type *</label>
                <select className="form-control" value={form.type} onChange={e => setForm({ ...form, type: e.target.value })}>
                  <option value="server">Server</option>
                  <option value="client">Client</option>
                </select>
              </div>
              <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                <label>Description</label>
                <input className="form-control" value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} placeholder="Optional description" />
              </div>
              <div className="form-group">
                <label>Key Algorithm</label>
                <select className="form-control" value={form.key_algorithm} onChange={e => setForm({ ...form, key_algorithm: e.target.value })}>
                  {keyAlgorithms.map(a => <option key={a.value} value={a.value}>{a.label}</option>)}
                </select>
              </div>
              <div className="form-group">
                <label>Signature Algorithm</label>
                <select className="form-control" value={form.signature_algorithm} onChange={e => setForm({ ...form, signature_algorithm: e.target.value })}>
                  {sigAlgorithms.map(a => <option key={a.value} value={a.value}>{a.label}</option>)}
                </select>
              </div>
              <div className="form-group">
                <label>Validity (days)</label>
                <input type="number" className="form-control" value={form.validity_days} onChange={e => setForm({ ...form, validity_days: parseInt(e.target.value) || 365 })} />
              </div>
              <div className="form-group">
                <label>Organization</label>
                <input className="form-control" value={form.organization} onChange={e => setForm({ ...form, organization: e.target.value })} />
              </div>
              <div className="form-group">
                <label>Organizational Unit</label>
                <input className="form-control" value={form.organizational_unit} onChange={e => setForm({ ...form, organizational_unit: e.target.value })} />
              </div>
              <div className="form-group">
                <label>Country</label>
                <input className="form-control" value={form.country} onChange={e => setForm({ ...form, country: e.target.value })} maxLength={2} placeholder="RS" />
              </div>
              <div className="form-group">
                <label>State</label>
                <input className="form-control" value={form.state} onChange={e => setForm({ ...form, state: e.target.value })} />
              </div>
              <div className="form-group">
                <label>Locality</label>
                <input className="form-control" value={form.locality} onChange={e => setForm({ ...form, locality: e.target.value })} />
              </div>
              <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                <label>DNS Names (comma-separated)</label>
                <input className="form-control" value={form.dns_names} onChange={e => setForm({ ...form, dns_names: e.target.value })} placeholder="example.com, *.example.com" />
              </div>
              <div className="form-group" style={{ gridColumn: '1 / -1' }}>
                <label>IP Addresses (comma-separated)</label>
                <input className="form-control" value={form.ip_addresses} onChange={e => setForm({ ...form, ip_addresses: e.target.value })} placeholder="10.0.0.1, 192.168.1.1" />
              </div>
            </div>
            <div style={{ marginTop: '1rem', display: 'flex', gap: '0.5rem' }}>
              <button type="submit" className="btn btn-primary">{editingId ? 'Update' : 'Create'} Template</button>
              <button type="button" className="btn btn-secondary" onClick={() => { setShowForm(false); setEditingId(null) }}>Cancel</button>
            </div>
          </form>
        </div>
      )}

      {loading ? (
        <div className="empty-state">Loading...</div>
      ) : templates.length === 0 ? (
        <div className="card empty-state">
          <p>No templates yet. Create one to quickly issue certificates with predefined settings.</p>
        </div>
      ) : (
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(350px, 1fr))', gap: '1rem' }}>
          {templates.map(t => (
            <div key={t.id} className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '0.75rem' }}>
                <div>
                  <h3 style={{ margin: 0 }}>{t.name}</h3>
                  {t.description && <p style={{ color: 'var(--text-muted)', fontSize: '0.85rem', margin: '0.25rem 0 0' }}>{t.description}</p>}
                </div>
                <span className={`badge ${t.type === 'server' ? 'badge-info' : 'badge-warning'}`}>
                  {t.type}
                </span>
              </div>
              <div style={{ fontSize: '0.85rem', color: 'var(--text-muted)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.25rem 1rem' }}>
                <div><strong>Key:</strong> {keyAlgorithms.find(a => a.value === t.key_algorithm)?.label || t.key_algorithm}</div>
                <div><strong>Signature:</strong> {sigAlgorithms.find(a => a.value === t.signature_algorithm)?.label || t.signature_algorithm}</div>
                <div><strong>Validity:</strong> {t.validity_days} days</div>
                {t.organization && <div><strong>Org:</strong> {t.organization}</div>}
                {t.country && <div><strong>Country:</strong> {t.country}</div>}
                {t.dns_names && t.dns_names.length > 0 && (
                  <div style={{ gridColumn: '1 / -1' }}><strong>DNS:</strong> {t.dns_names.join(', ')}</div>
                )}
                {t.ip_addresses && t.ip_addresses.length > 0 && (
                  <div style={{ gridColumn: '1 / -1' }}><strong>IPs:</strong> {t.ip_addresses.join(', ')}</div>
                )}
              </div>
              <div style={{ marginTop: '1rem', display: 'flex', gap: '0.5rem' }}>
                <button className="btn btn-primary btn-sm" onClick={() => handleUseTemplate(t)}>Use Template</button>
                <button className="btn btn-secondary btn-sm" onClick={() => handleEdit(t)}>Edit</button>
                <button className="btn btn-danger btn-sm" onClick={() => handleDelete(t.id, t.name)}>Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

export default Templates
