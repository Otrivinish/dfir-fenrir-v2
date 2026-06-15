import { useState } from 'react'

// Swagger UI + ReDoc are mounted on the backend at /api/docs and /api/redoc
// and gated behind require_admin. The browser is already authenticated
// (session cookie), so the iframe load + Swagger's openapi.json fetch both
// pick up auth automatically.

const VIEWS = [
  { key: 'swagger', label: 'Swagger UI', src: '/api/docs',  hint: 'Interactive — try requests inline.' },
  { key: 'redoc',   label: 'ReDoc',      src: '/api/redoc', hint: 'Read-only — searchable navigation.' },
]

export default function APIDocs() {
  const [view, setView] = useState('swagger')
  const active = VIEWS.find(v => v.key === view) ?? VIEWS[0]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-3)', height: '100%' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 'var(--space-3)' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 16, fontWeight: 600 }}>API Docs</h2>
          <div style={{ color: 'var(--muted)', fontSize: 12, marginTop: 2 }}>
            {active.hint} OpenAPI spec at{' '}
            <a href="/api/openapi.json" target="_blank" rel="noreferrer" style={{ color: 'var(--accent)' }}>
              /api/openapi.json
            </a>
            .
          </div>
        </div>

        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <div role="tablist" aria-label="Docs renderer" style={{ display: 'flex', gap: 4 }}>
            {VIEWS.map(v => (
              <button
                key={v.key}
                type="button"
                role="tab"
                aria-selected={view === v.key}
                onClick={() => setView(v.key)}
                className="btn"
                style={{
                  padding: '4px 10px', fontSize: 12,
                  background: view === v.key ? 'var(--accent-soft)' : 'var(--surface)',
                  borderColor: view === v.key ? 'var(--accent)' : 'var(--border)',
                  color: view === v.key ? 'var(--accent)' : 'var(--text)',
                }}
              >
                {v.label}
              </button>
            ))}
          </div>
          <a
            href={active.src}
            target="_blank"
            rel="noreferrer"
            className="btn"
            style={{ padding: '4px 10px', fontSize: 12, textDecoration: 'none' }}
            title="Open in a new tab"
          >
            Open ↗
          </a>
        </div>
      </div>

      <div
        style={{
          flex: 1,
          minHeight: 600,
          border: '1px solid var(--border)',
          borderRadius: 'var(--radius)',
          overflow: 'hidden',
          background: 'var(--surface)',
        }}
      >
        <iframe
          key={active.key}
          src={active.src}
          title={`${active.label} (API documentation)`}
          style={{ width: '100%', height: '100%', border: 0, display: 'block' }}
          sandbox="allow-same-origin allow-scripts allow-forms allow-popups"
        />
      </div>
    </div>
  )
}
