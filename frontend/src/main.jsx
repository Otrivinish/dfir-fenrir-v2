import React from 'react'
import ReactDOM from 'react-dom/client'
import './styles/tokens.css'
import './styles/base.css'
import './styles/auth.css'
import './styles/shell.css'
import './styles/incidents.css'
import './styles/playbooks.css'
import './styles/settings.css'
import './styles/warroom.css'
import './styles/notifications.css'
import App from './App.jsx'

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
