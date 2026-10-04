import { useState, useEffect } from 'react'

function App() {
  const [health, setHealth] = useState('Checking...')

  useEffect(() => {
    // SECURITY: API calls should handle potential network errors gracefully.
    fetch('/health')
      .then(res => res.json())
      .then(data => setHealth(data.status))
      .catch(err => setHealth('API Offline'))
  }, [])

  return (
    <div className="app-container">
      <h1>Secure Note Taker</h1>
      <p>API Status: {health}</p>
      
      {/* SECURITY Note: React automatically escapes variables used in JSX like this, 
          mitigating XSS if user input were placed here. */}
      <div className="note-card">
        <h3>Welcome</h3>
        <p>This is a secure application emphasizing data protection.</p>
      </div>
    </div>
  )
}

export default App
