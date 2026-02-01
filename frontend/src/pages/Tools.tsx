import { useState, useEffect } from 'react'

interface CA {
  id: string
  name: string
}

function Tools() {
  const [cas, setCAs] = useState<CA[]>([])
  const [activeTab, setActiveTab] = useState<'convert' | 'analyze' | 'import'>('convert')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')

  const [convertInput, setConvertInput] = useState('')
  const [fromFormat, setFromFormat] = useState('pem')
  const [toFormat, setToFormat] = useState('der')
  const [convertResult, setConvertResult] = useState<{
    output: string
    subject: string
    issuer: string
    not_before: string
    not_after: string
  } | null>(null)

  const [analyzeInput, setAnalyzeInput] = useState('')
  const [analyzeResult, setAnalyzeResult] = useState<{
    subject: string
    issuer: string
    not_before: string
    not_after: string
    serial_number: string
    signature_algorithm: string
    public_key_algorithm: string
    dns_names: string[]
    is_ca: boolean
  } | null>(null)

  const [importCaId, setImportCaId] = useState('')
  const [importPem, setImportPem] = useState('')
  const [importType, setImportType] = useState('server')

  useEffect(() => {
    fetch('/api/ca')
      .then(r => r.json())
      .then(data => setCAs(data || []))
  }, [])

  const handleConvert = async () => {
    setError('')
    setSuccess('')
    setConvertResult(null)
    setLoading(true)

    try {
      const res = await fetch('/api/convert', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          input: convertInput,
          from_format: fromFormat,
          to_format: toFormat,
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Conversion failed')
      }

      const result = await res.json()
      setConvertResult(result)
      setSuccess('Conversion successful!')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const handleAnalyze = async () => {
    setError('')
    setSuccess('')
    setAnalyzeResult(null)
    setLoading(true)

    try {
      const res = await fetch('/api/analyze', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input: analyzeInput }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Analysis failed')
      }

      const result = await res.json()
      setAnalyzeResult(result)
      setSuccess('Analysis complete!')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const handleImport = async () => {
    setError('')
    setSuccess('')
    setLoading(true)

    try {
      const res = await fetch('/api/certificates/import', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          ca_id: importCaId,
          certificate_pem: importPem,
          type: importType,
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Import failed')
      }

      setSuccess('Certificate imported successfully!')
      setImportPem('')
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const downloadConvertedFile = () => {
    if (!convertResult) return
    const blob = new Blob([convertResult.output], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    const extensions: Record<string, string> = {
      pem: '.pem',
      der: '.der.b64',
      p7b: '.p7b.b64',
    }
    a.download = `certificate${extensions[toFormat] || '.txt'}`
    a.click()
  }

  return (
    <div>
      <h1 style={{ marginBottom: '1.5rem' }}>Tools</h1>

      <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1rem' }}>
        <button
          className={`btn ${activeTab === 'convert' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('convert')}
        >
          Convert
        </button>
        <button
          className={`btn ${activeTab === 'analyze' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('analyze')}
        >
          Analyze
        </button>
        <button
          className={`btn ${activeTab === 'import' ? 'btn-primary' : 'btn-secondary'}`}
          onClick={() => setActiveTab('import')}
        >
          Import
        </button>
      </div>

      {error && <div className="alert alert-error">{error}</div>}
      {success && <div className="alert alert-success">{success}</div>}

      {activeTab === 'convert' && (
        <div className="card">
          <h2 className="card-title" style={{ marginBottom: '1rem' }}>Convert Certificate Format</h2>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1rem' }}>
            <div className="form-group">
              <label>From Format</label>
              <select value={fromFormat} onChange={e => setFromFormat(e.target.value)}>
                <option value="pem">PEM (.pem, .crt, .cer)</option>
                <option value="der">DER (Base64 encoded)</option>
              </select>
            </div>
            <div className="form-group">
              <label>To Format</label>
              <select value={toFormat} onChange={e => setToFormat(e.target.value)}>
                <option value="pem">PEM (.pem, .crt, .cer)</option>
                <option value="der">DER (Base64 encoded)</option>
                <option value="p7b">PKCS#7 (.p7b) - Base64</option>
              </select>
            </div>
          </div>

          <div className="form-group">
            <label>Input Certificate</label>
            <textarea
              value={convertInput}
              onChange={e => setConvertInput(e.target.value)}
              placeholder={fromFormat === 'pem'
                ? '-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----'
                : 'Base64 encoded DER certificate'}
              style={{
                width: '100%',
                minHeight: '150px',
                padding: '0.5rem 0.75rem',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                fontFamily: 'monospace',
                fontSize: '0.75rem',
                background: 'var(--input-bg)',
                color: 'var(--text)',
              }}
            />
          </div>

          <button className="btn btn-primary" onClick={handleConvert} disabled={loading || !convertInput}>
            {loading ? 'Converting...' : 'Convert'}
          </button>

          {convertResult && (
            <div style={{ marginTop: '1.5rem' }}>
              <h3 style={{ marginBottom: '0.5rem' }}>Result</h3>
              <div style={{ marginBottom: '1rem', fontSize: '0.875rem', color: 'var(--text-muted)' }}>
                <div><strong>Subject:</strong> {convertResult.subject}</div>
                <div><strong>Issuer:</strong> {convertResult.issuer}</div>
                <div><strong>Valid:</strong> {new Date(convertResult.not_before).toLocaleDateString()} - {new Date(convertResult.not_after).toLocaleDateString()}</div>
              </div>
              <pre style={{ marginBottom: '1rem' }}>{convertResult.output}</pre>
              <button className="btn btn-secondary" onClick={downloadConvertedFile}>
                Download
              </button>
            </div>
          )}
        </div>
      )}

      {activeTab === 'analyze' && (
        <div className="card">
          <h2 className="card-title" style={{ marginBottom: '1rem' }}>Analyze Certificate</h2>
          <p style={{ marginBottom: '1rem', color: 'var(--text-muted)', fontSize: '0.875rem' }}>
            Paste a certificate in PEM format to view its details.
          </p>

          <div className="form-group">
            <label>Certificate (PEM)</label>
            <textarea
              value={analyzeInput}
              onChange={e => setAnalyzeInput(e.target.value)}
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
              style={{
                width: '100%',
                minHeight: '150px',
                padding: '0.5rem 0.75rem',
                border: '1px solid var(--border)',
                borderRadius: '6px',
                fontFamily: 'monospace',
                fontSize: '0.75rem',
                background: 'var(--input-bg)',
                color: 'var(--text)',
              }}
            />
          </div>

          <button className="btn btn-primary" onClick={handleAnalyze} disabled={loading || !analyzeInput}>
            {loading ? 'Analyzing...' : 'Analyze'}
          </button>

          {analyzeResult && (
            <div style={{ marginTop: '1.5rem' }}>
              <h3 style={{ marginBottom: '1rem' }}>Certificate Details</h3>
              <table className="table" style={{ fontSize: '0.875rem' }}>
                <tbody>
                  <tr>
                    <td style={{ fontWeight: 600, width: '40%' }}>Subject</td>
                    <td style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{analyzeResult.subject}</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>Issuer</td>
                    <td style={{ fontFamily: 'monospace', wordBreak: 'break-all' }}>{analyzeResult.issuer}</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>Serial Number</td>
                    <td style={{ fontFamily: 'monospace' }}>{analyzeResult.serial_number}</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>Valid From</td>
                    <td>{new Date(analyzeResult.not_before).toLocaleString()}</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>Valid Until</td>
                    <td>{new Date(analyzeResult.not_after).toLocaleString()}</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>Signature Algorithm</td>
                    <td>{analyzeResult.signature_algorithm}</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>Public Key Algorithm</td>
                    <td>{analyzeResult.public_key_algorithm}</td>
                  </tr>
                  <tr>
                    <td style={{ fontWeight: 600 }}>Is CA</td>
                    <td>{analyzeResult.is_ca ? 'Yes' : 'No'}</td>
                  </tr>
                  {analyzeResult.dns_names && analyzeResult.dns_names.length > 0 && (
                    <tr>
                      <td style={{ fontWeight: 600 }}>DNS Names (SANs)</td>
                      <td>{analyzeResult.dns_names.join(', ')}</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {activeTab === 'import' && (
        <div className="card">
          <h2 className="card-title" style={{ marginBottom: '1rem' }}>Import Certificate</h2>

          {cas.length === 0 ? (
            <div className="alert alert-error">
              No Certificate Authorities available. Create a CA first.
            </div>
          ) : (
            <>
              <div className="form-group">
                <label>Certificate Authority</label>
                <select value={importCaId} onChange={e => setImportCaId(e.target.value)} required>
                  <option value="">Select CA...</option>
                  {cas.map(ca => (
                    <option key={ca.id} value={ca.id}>{ca.name}</option>
                  ))}
                </select>
              </div>

              <div className="form-group">
                <label>Certificate Type</label>
                <select value={importType} onChange={e => setImportType(e.target.value)}>
                  <option value="server">Server</option>
                  <option value="client">Client</option>
                </select>
              </div>

              <div className="form-group">
                <label>Certificate (PEM)</label>
                <textarea
                  value={importPem}
                  onChange={e => setImportPem(e.target.value)}
                  placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
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
                />
              </div>

              <button
                className="btn btn-primary"
                onClick={handleImport}
                disabled={loading || !importCaId || !importPem}
              >
                {loading ? 'Importing...' : 'Import Certificate'}
              </button>
            </>
          )}
        </div>
      )}
    </div>
  )
}

export default Tools
