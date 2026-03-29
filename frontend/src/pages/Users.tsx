import { useState, useEffect } from 'react'

interface User {
  id: string
  username: string
  role: string
  full_name: string
  email: string
  active: boolean
  created_at: string
}

function Users() {
  const [users, setUsers] = useState<User[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [showAddForm, setShowAddForm] = useState(false)
  const [newUser, setNewUser] = useState({ username: '', password: '', full_name: '', email: '' })
  const [resetPasswordUser, setResetPasswordUser] = useState<User | null>(null)
  const [newPassword, setNewPassword] = useState('')
  const [editUser, setEditUser] = useState<User | null>(null)

  const token = localStorage.getItem('token') || ''
  const headers = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` }

  const fetchUsers = () => {
    fetch('/api/users', { headers })
      .then(r => r.json())
      .then(data => { setUsers(data || []); setLoading(false) })
      .catch(() => setLoading(false))
  }

  useEffect(() => { fetchUsers() }, [])

  const handleUpdateField = async (id: string, data: Record<string, any>) => {
    try {
      const res = await fetch(`/api/users/${id}`, {
        method: 'PUT', headers,
        body: JSON.stringify(data),
      })
      if (!res.ok) throw new Error('Failed to update')
      setSuccess('User updated')
      setTimeout(() => setSuccess(''), 3000)
      fetchUsers()
    } catch (err: any) { setError(err.message) }
  }

  const handleEditSave = async () => {
    if (!editUser) return
    await handleUpdateField(editUser.id, {
      full_name: editUser.full_name,
      email: editUser.email,
    })
    setEditUser(null)
  }

  const handleToggleActive = async (user: User) => {
    await handleUpdateField(user.id, { active: !user.active })
  }

  const handleDelete = async (user: User) => {
    if (!confirm(`Delete user "${user.username}"?`)) return
    try {
      const res = await fetch(`/api/users/${user.id}`, { method: 'DELETE', headers })
      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to delete')
      }
      setSuccess('User deleted')
      setTimeout(() => setSuccess(''), 3000)
      fetchUsers()
    } catch (err: any) { setError(err.message) }
  }

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!resetPasswordUser) return
    setError('')
    try {
      const res = await fetch(`/api/users/${resetPasswordUser.id}/reset-password`, {
        method: 'POST', headers,
        body: JSON.stringify({ new_password: newPassword }),
      })
      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to reset password')
      }
      setSuccess(`Password reset for ${resetPasswordUser.username}`)
      setResetPasswordUser(null)
      setNewPassword('')
      setTimeout(() => setSuccess(''), 3000)
    } catch (err: any) { setError(err.message) }
  }

  const handleAddUser = async (e: React.FormEvent) => {
    e.preventDefault()
    setError('')
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST', headers,
        body: JSON.stringify(newUser),
      })
      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error || 'Failed to create user')
      }
      setSuccess('User created')
      setShowAddForm(false)
      setNewUser({ username: '', password: '', full_name: '', email: '' })
      setTimeout(() => setSuccess(''), 3000)
      fetchUsers()
    } catch (err: any) { setError(err.message) }
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.5rem' }}>
        <h1>User Management</h1>
        <button className="btn btn-primary" onClick={() => setShowAddForm(!showAddForm)}>
          {showAddForm ? 'Cancel' : '+ Add User'}
        </button>
      </div>

      {error && <div className="alert alert-danger" style={{ marginBottom: '1rem' }}>{error}</div>}
      {success && <div className="alert alert-success" style={{ marginBottom: '1rem' }}>{success}</div>}

      {showAddForm && (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <h3 style={{ marginBottom: '1rem' }}>Add New User</h3>
          <form onSubmit={handleAddUser}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
              <div className="form-group">
                <label>Username *</label>
                <input className="form-control" value={newUser.username} onChange={e => setNewUser({ ...newUser, username: e.target.value })} required minLength={3} />
              </div>
              <div className="form-group">
                <label>Password *</label>
                <input type="password" className="form-control" value={newUser.password} onChange={e => setNewUser({ ...newUser, password: e.target.value })} required minLength={8} />
              </div>
              <div className="form-group">
                <label>Full Name</label>
                <input className="form-control" value={newUser.full_name} onChange={e => setNewUser({ ...newUser, full_name: e.target.value })} />
              </div>
              <div className="form-group">
                <label>Email</label>
                <input type="email" className="form-control" value={newUser.email} onChange={e => setNewUser({ ...newUser, email: e.target.value })} />
              </div>
            </div>
            <button type="submit" className="btn btn-primary" style={{ marginTop: '1rem' }}>Create User</button>
          </form>
        </div>
      )}

      {loading ? (
        <div className="empty-state">Loading...</div>
      ) : (
        <div className="card">
          <table className="table">
            <thead>
              <tr>
                <th>Username</th>
                <th>Full Name</th>
                <th>Email</th>
                <th>Role</th>
                <th>Status</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {users.map(u => (
                <tr key={u.id}>
                  <td><strong>{u.username}</strong></td>
                  <td>{u.full_name || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td>{u.email || <span style={{ color: 'var(--text-muted)' }}>-</span>}</td>
                  <td>
                    <select
                      value={u.role}
                      onChange={e => handleUpdateField(u.id, { role: e.target.value })}
                      className="form-control"
                      style={{ width: 'auto', display: 'inline', padding: '0.25rem 0.5rem', fontSize: '0.85rem' }}
                    >
                      <option value="admin">Admin</option>
                      <option value="operator">Operator</option>
                      <option value="viewer">Viewer</option>
                    </select>
                  </td>
                  <td>
                    <span className={`badge ${u.active ? 'badge-success' : 'badge-danger'}`}>
                      {u.active ? 'Active' : 'Disabled'}
                    </span>
                  </td>
                  <td style={{ whiteSpace: 'nowrap' }}>{new Date(u.created_at).toLocaleDateString()}</td>
                  <td>
                    <div style={{ display: 'flex', gap: '0.25rem' }}>
                      <button className="btn btn-secondary btn-sm" onClick={() => setEditUser({ ...u })}>
                        Edit
                      </button>
                      <button className="btn btn-secondary btn-sm" onClick={() => { setResetPasswordUser(u); setNewPassword('') }}>
                        Password
                      </button>
                      <button className="btn btn-secondary btn-sm" onClick={() => handleToggleActive(u)}>
                        {u.active ? 'Disable' : 'Enable'}
                      </button>
                      <button className="btn btn-danger btn-sm" onClick={() => handleDelete(u)}>Delete</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {editUser && (
        <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="card" style={{ width: '100%', maxWidth: '420px', padding: '2rem' }}>
            <h3 style={{ marginBottom: '1rem' }}>Edit User: {editUser.username}</h3>
            <div className="form-group">
              <label>Full Name</label>
              <input
                className="form-control"
                value={editUser.full_name}
                onChange={e => setEditUser({ ...editUser, full_name: e.target.value })}
                placeholder="Ime i prezime"
                autoFocus
              />
            </div>
            <div className="form-group">
              <label>Email</label>
              <input
                type="email"
                className="form-control"
                value={editUser.email}
                onChange={e => setEditUser({ ...editUser, email: e.target.value })}
                placeholder="email@example.com"
              />
            </div>
            <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
              <button className="btn btn-primary" onClick={handleEditSave}>Save</button>
              <button className="btn btn-secondary" onClick={() => setEditUser(null)}>Cancel</button>
            </div>
          </div>
        </div>
      )}

      {resetPasswordUser && (
        <div className="modal-overlay" style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, background: 'rgba(0,0,0,0.5)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 1000 }}>
          <div className="card" style={{ width: '100%', maxWidth: '420px', padding: '2rem' }}>
            <h3 style={{ marginBottom: '1rem' }}>Reset Password: {resetPasswordUser.username}</h3>
            <form onSubmit={handleResetPassword}>
              <div className="form-group">
                <label>New Password</label>
                <input
                  type="password"
                  className="form-control"
                  value={newPassword}
                  onChange={e => setNewPassword(e.target.value)}
                  required
                  minLength={8}
                  placeholder="Min 8 characters"
                  autoFocus
                />
              </div>
              <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
                <button type="submit" className="btn btn-primary">Reset Password</button>
                <button type="button" className="btn btn-secondary" onClick={() => setResetPasswordUser(null)}>Cancel</button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}

export default Users
