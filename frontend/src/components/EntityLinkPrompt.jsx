// TE — "N timeline events name <entity> but aren't linked to it · Link them". The count is a dry run of
// POST …/timeline/entity-links; nothing is linked until the analyst clicks (D1). Renders nothing when no
// unlinked event names the entity, or when the count can't be read. Writers only (the API refuses others).
import { useEffect, useState } from 'react'
import { api } from '../api/client.js'
import { labelOf } from '../lib/incidentVocab.js'

export default function EntityLinkPrompt({ incidentId, entity, onLinked }) {
  const [matched, setMatched] = useState(0)
  const [linked, setLinked]   = useState(null)
  const [busy, setBusy]       = useState(false)
  const [error, setError]     = useState(null)

  useEffect(() => {
    let live = true
    setMatched(0); setLinked(null); setError(null)
    api.linkTimelineEntity(incidentId, { entity_id: entity.id, dry_run: true })
      .then(r => { if (live) setMatched(r.matched) })
      .catch(() => {})
    return () => { live = false }
  }, [incidentId, entity.id])

  const link = async () => {
    setBusy(true); setError(null)
    try {
      const r = await api.linkTimelineEntity(incidentId, { entity_id: entity.id })
      setLinked(r.linked)
      onLinked?.(r.linked)
    } catch (e) {
      setError(e.message || 'Could not link the events')
    } finally {
      setBusy(false)
    }
  }

  const name = <><span>{labelOf('entity_type', entity.type)}</span>{' '}
    <span style={{ fontFamily: 'var(--font-mono)' }}>{entity.value}</span></>
  if (linked != null) {
    return (
      <div className="alert ok" role="status" data-testid="entity-link-done">
        <span className="alert-icon">✓</span>
        <span>Linked {linked} timeline event{linked === 1 ? '' : 's'} to {name}.</span>
      </div>
    )
  }
  if (!matched) return null
  return (
    <div className="alert info" role="status" data-testid="entity-link-prompt">
      <span className="alert-icon">i</span>
      <span style={{ flex: 1 }}>
        {matched} timeline event{matched === 1 ? '' : 's'} name{matched === 1 ? 's' : ''} {name} but
        {matched === 1 ? ' isn’t' : ' aren’t'} linked to it.
        {error && <span role="alert" style={{ display: 'block', color: 'var(--crit)' }}>{error}</span>}
      </span>
      <button type="button" className="btn ghost" onClick={link} disabled={busy} data-testid="entity-link-all">
        {busy ? 'Linking…' : 'Link them'}
      </button>
    </div>
  )
}
