import { useState, useEffect } from 'react'
import './index.css'

function App() {
  const [token, setToken] = useState(localStorage.getItem('token'))
  const [notes, setNotes] = useState([])
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [newNoteTitle, setNewNoteTitle] = useState('')
  const [newNoteContent, setNewNoteContent] = useState('')
  const [error, setError] = useState('')
  const [isLogin, setIsLogin] = useState(true)

  useEffect(() => {
    if (token) fetchNotes()
  }, [token])

  const handleAuth = async (e) => {
    e.preventDefault()
    setError('')
    const endpoint = isLogin ? '/api/login' : '/api/register'
    try {
      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        // SECURITY: React implicitly prevents XSS here, but sending raw input requires backend sanitization
        body: JSON.stringify({ username, password })
      })
      const data = await res.json()
      if (!res.ok) throw new Error(data.message || 'Authentication failed')
      
      if (isLogin) {
        setToken(data.data.token)
        // SECURITY: For this demo we use localStorage, but HttpOnly cookies are strictly better for JWTs
        localStorage.setItem('token', data.data.token)
      } else {
        setIsLogin(true)
        setError('Registration successful. Please log in.')
      }
    } catch (err) {
      setError(err.message)
    }
  }

  const fetchNotes = async () => {
    try {
      const res = await fetch('/api/notes', {
        headers: { 'Authorization': `Bearer ${token}` }
      })
      if (!res.ok) {
        if (res.status === 401) logout()
        throw new Error('Failed to fetch notes')
      }
      const data = await res.json()
      setNotes(data.data || [])
    } catch (err) {
      console.error(err)
    }
  }

  const createNote = async (e) => {
    e.preventDefault()
    try {
      const res = await fetch('/api/notes', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ title: newNoteTitle, content: newNoteContent })
      })
      if (!res.ok) throw new Error('Failed to create note')
      setNewNoteTitle('')
      setNewNoteContent('')
      fetchNotes()
    } catch (err) {
      setError(err.message)
    }
  }

  const deleteNote = async (id) => {
    try {
      const res = await fetch(`/api/notes/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
      })
      if (!res.ok) throw new Error('Failed to delete note')
      fetchNotes()
    } catch (err) {
      setError(err.message)
    }
  }

  const logout = () => {
    setToken(null)
    localStorage.removeItem('token')
    setNotes([])
  }

  if (!token) {
    return (
      <div className="auth-container">
        <div className="auth-card glass-panel">
          <h1 className="gradient-text">SecureVault</h1>
          <p className="subtitle">Military-grade Note Taker</p>
          <form onSubmit={handleAuth} className="auth-form">
            <input type="text" placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} required minLength={3} />
            <input type="password" placeholder="Password" value={password} onChange={e => setPassword(e.target.value)} required minLength={8} />
            {error && <p className="error-msg">{error}</p>}
            <button type="submit" className="primary-btn">{isLogin ? 'Access Vault' : 'Create Credentials'}</button>
          </form>
          <button className="text-btn" onClick={() => setIsLogin(!isLogin)}>
            {isLogin ? "Need an account? Register" : "Have credentials? Login"}
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="dashboard">
      <header className="glass-header">
        <h2 className="gradient-text">SecureVault Dashboard</h2>
        <button onClick={logout} className="outline-btn">Secure Logout</button>
      </header>

      <main className="main-content">
        <section className="create-note-section glass-panel">
          <h3>Encrypt New Note</h3>
          <form onSubmit={createNote} className="note-form">
            <input type="text" placeholder="Classification Title" value={newNoteTitle} onChange={e => setNewNoteTitle(e.target.value)} required maxLength={100} />
            <textarea placeholder="Sensitive Content..." value={newNoteContent} onChange={e => setNewNoteContent(e.target.value)} required />
            <button type="submit" className="primary-btn">Store Securely</button>
          </form>
        </section>

        <section className="notes-grid">
          {notes.map(note => (
            <div key={note.id} className="note-card glass-panel">
              <div className="note-header">
                <h4>{note.title}</h4>
                <button onClick={() => deleteNote(note.id)} className="delete-btn">Destroy</button>
              </div>
              <p className="note-content">{note.content}</p>
              <small className="note-meta">Logged: {new Date(note.created_at).toLocaleString()}</small>
            </div>
          ))}
          {notes.length === 0 && <p className="empty-state">No secure logs found in your vault.</p>}
        </section>
      </main>
    </div>
  )
}

export default App
