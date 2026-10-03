import { useCallback, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { api } from '../api/client.js'
import { useAuth } from '../hooks/useAuth.jsx'
import { StakeholderBoard, verifiedLabel } from './incident/comms/Stakeholders.jsx'

// Prepare → Contacts (E2): the organisation's Contacts directory, shown on the same board as an
// incident's Stakeholders tab with the directory API as its source. Analysts read; admins add,
// edit, verify and delete. The API enforces the same rule (GET admin + analyst, writes admin).

async function listAllContacts() {
  const out = []
  let cursor = null
  do {
    const d = await api.listContacts({ limit: 200, cursor })
    out.push(...d.items)
    cursor = d.next_cursor
  } while (cursor)
  return out
}

function VerifyLine({ contact: c, canVerify, onVerified }) {
  const [busy, setBusy] = useState(false)
  const [err,  setErr]  = useState('')

  const verify = async () => {
    setBusy(true); setErr('')
    try {
      onVerified(await api.updateContact(c.id, { verified: true }))
    } catch (e) {
      setErr(e.message || 'Could not mark it verified')
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="ct-verified" style={{
      display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 'var(--space-2)',
      fontSize: 11, color: 'var(--muted)',
    }}>
      <span className="ct-verified-text">{verifiedLabel(c)}</span>
      {canVerify && (
        <button className="btn ghost" type="button" style={{ fontSize: 12, marginLeft: 'auto' }}
                disabled={busy} onClick={verify} aria-label={`Mark ${c.name} verified`}>
          {busy ? 'Saving…' : 'Mark verified'}
        </button>
      )}
      {err && <span role="alert" style={{ color: 'var(--crit)', flexBasis: '100%' }}>{err}</span>}
    </div>
  )
}

export default function Contacts() {
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'

  const source = useMemo(() => ({
    list:   listAllContacts,
    create: (payload)     => api.createContact(payload),
    update: (id, payload) => api.updateContact(id, payload),
    remove: (id)          => api.deleteContact(id),
  }), [])

  const cardExtra = useCallback((c, replace) => (
    <VerifyLine contact={c} canVerify={isAdmin} onVerified={replace} />
  ), [isAdmin])

  return (
    <div className="page-wrap">
      <div className="page-head">
        <div>
          <h1 className="page-title">Contacts</h1>
          <div className="page-sub">
            The organisation's prepared external contacts{isAdmin ? '' : ' · read-only: an admin edits them'}
          </div>
        </div>
      </div>

      <p style={{ margin: '0 0 var(--space-3)', fontSize: 13, color: 'var(--muted)', maxWidth: 820 }}>
        Keep the supervisory authority, national CSIRT, police cyber unit, insurer, IR retainer and PR here,
        and mark each one verified when you have checked it still works. <Link to="/readiness">Readiness</Link> warns
        when one is missing or was not verified in the last 90 days. On an incident, <b>Comms → Stakeholders → Add
        from directory</b> copies an entry into the case.
      </p>

      <StakeholderBoard
        source={source}
        readOnly={!isAdmin}
        title="Contacts directory"
        cardExtra={cardExtra}
        emptyText="No contacts in the directory yet."
        emptyHint="Start with the supervisory authority, national CSIRT, police cyber unit, insurer, IR retainer and PR."
        deleteConfirm="Delete this directory contact? Incidents keep the copies they already have."
        noun="contact"
      />
    </div>
  )
}
