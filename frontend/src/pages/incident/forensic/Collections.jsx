import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'

// U1 — signed offline collectors. Generate an incident-scoped, Ed25519-signed
// Velociraptor collection package; the responder runs it out-of-band and uploads
// the output back via Artifacts (ingest lands in U1.2).

function fmtSize(bytes) {
  if (bytes === null || bytes === undefined) return '—'
  if (bytes < 1024)              return `${bytes} B`
  if (bytes < 1024 * 1024)       return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`
}

const STATUS_COLOR = {
  generated:  'var(--ok)',
  consumed:   'var(--muted)',
  expired:    'var(--dim)',
  superseded: 'var(--high)',
  deleted:    'var(--dim)',
}

function StatusPill({ status, isStale }) {
  const color = STATUS_COLOR[status] || 'var(--muted)'
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 'var(--radius-sm)',
      fontSize: 10, fontWeight: 700, textTransform: 'uppercase', letterSpacing: '0.06em',
      fontFamily: 'var(--font-mono)',
      color, background: `color-mix(in srgb, ${color} 18%, transparent)`,
      border: `1px solid color-mix(in srgb, ${color} 45%, transparent)`,
    }}>
      {status}{isStale && status === 'superseded' ? '' : ''}
    </span>
  )
}

export default function Collections() {
  const { inc } = useOutletContext()
  const isClosed = inc?.status === 'closed'

  const [profiles, setProfiles] = useState([])
  const [packages, setPackages] = useState([])
  const [cap,      setCap]      = useState(null)
  const [loading,  setLoading]  = useState(true)
  const [error,    setError]    = useState(null)
  const [busy,     setBusy]     = useState(false)

  const [name,    setName]    = useState('')
  const [profile, setProfile] = useState('')   // "platform/profile"
  const [justGenerated, setJustGenerated] = useState(null)  // one-time download payload

  const [ingestTarget, setIngestTarget] = useState(null)   // package awaiting an output upload
  const [ingesting,    setIngesting]    = useState(false)
  const [ingestMsg,    setIngestMsg]    = useState(null)
  const ingestRef = useRef(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const [profRes, pkgRes] = await Promise.all([
        api.listCollectionProfiles(inc.id),
        api.listCollections(inc.id),
      ])
      const profs = profRes.items || []
      setProfiles(profs)
      setPackages(pkgRes.items || [])
      setCap(pkgRes.cap?.max_active_per_incident ?? null)
      if (!profile && profs.length) setProfile(`${profs[0].platform}/${profs[0].profile}`)
    } catch (e) {
      setError(e.message || 'Could not load collection packages')
    } finally {
      setLoading(false)
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [inc.id])

  useEffect(() => { load() }, [load])

  const selectedProfile = useMemo(
    () => profiles.find(p => `${p.platform}/${p.profile}` === profile),
    [profiles, profile],
  )

  const onGenerate = async () => {
    if (!name.trim() || !selectedProfile) return
    setBusy(true); setError(null); setJustGenerated(null)
    try {
      const res = await api.generateCollection(inc.id, {
        name:     name.trim(),
        platform: selectedProfile.platform,
        profile:  selectedProfile.profile,
      })
      setJustGenerated(res)
      setName('')
      await load()
    } catch (e) {
      setError(e.message || 'Generation failed')
    } finally {
      setBusy(false)
    }
  }

  const startIngest = (pkg) => {
    setIngestTarget(pkg)
    setIngestMsg(null)
    ingestRef.current?.click()
  }

  const onIngestFile = async (e) => {
    const file = e.target.files?.[0]
    e.target.value = ''
    if (!file || !ingestTarget) return
    setIngesting(true); setError(null); setIngestMsg(null)
    try {
      const res = await api.ingestCollection(inc.id, ingestTarget.id, file)
      setIngestMsg(`Ingested "${ingestTarget.name}" → artifact ${res.artifact?.original_filename} (${fmtSize(res.artifact?.file_size)}).`)
      setIngestTarget(null)
      await load()
    } catch (err) {
      setError(err.message || 'Ingest failed')
    } finally {
      setIngesting(false)
    }
  }

  const onDelete = async (pkg) => {
    if (!window.confirm(`Delete collection package "${pkg.name}"?\n\nThis removes the package file. The audit record is kept.`)) return
    try {
      await api.deleteCollection(inc.id, pkg.id)
      await load()
    } catch (e) {
      setError(e.message || 'Delete failed')
    }
  }

  const copy = (text) => { navigator.clipboard?.writeText(text) }

  if (loading) return <div className="panel-empty">Loading…</div>

  const activeCount = packages.filter(p => p.status === 'generated').length

  return (
    <div>
      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      <input ref={ingestRef} type="file" accept=".zip" hidden onChange={onIngestFile} />
      {(ingesting || ingestMsg) && (
        <div className="alert" role="status" style={{ marginBottom: 'var(--space-3)' }}>
          <span>{ingesting ? 'Ingesting collection output…' : ingestMsg}</span>
        </div>
      )}

      {/* Intro */}
      <div style={{
        fontSize: 12, color: 'var(--muted)', lineHeight: 1.6,
        marginBottom: 'var(--space-3)',
      }}>
        Generate a signed, incident-scoped <strong>Velociraptor</strong> collection package.
        A responder runs it on the target host out-of-band, then uploads the output back
        here with <strong>Ingest results</strong> — it's decrypted and registered as an Artifact
        for analysis. Packages are Ed25519-signed and single-use; the collection output is
        <strong>X.509-encrypted</strong> to a per-package key only FENRIR holds (encrypted on the
        responder's media). The download link is shown once.
      </div>

      {/* One-time download surface */}
      {justGenerated && (
        <div className="panel" style={{
          marginBottom: 'var(--space-3)',
          borderLeft: '3px solid var(--ok)',
        }}>
          <div style={{ fontWeight: 700, fontSize: 13, color: 'var(--text)', marginBottom: 6 }}>
            Package ready — download link shown once
          </div>
          <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 8 }}>
            This single-use link expires {justGenerated.download_expires_at ? formatLocal(justGenerated.download_expires_at) : 'in 24h'}.
            Copy it now — it won't be shown again.
          </div>
          <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
            <code style={{
              fontFamily: 'var(--font-mono)', fontSize: 11, color: 'var(--accent)',
              background: 'var(--surface-2)', padding: '6px 10px', borderRadius: 'var(--radius-sm)',
              wordBreak: 'break-all', flex: 1, minWidth: 240,
            }}>{justGenerated.download_url}</code>
            <a className="btn primary" href={justGenerated.download_url} style={{ fontSize: 12, textDecoration: 'none' }}>
              Download
            </a>
            <button type="button" className="btn ghost" style={{ fontSize: 12 }}
                    onClick={() => copy(justGenerated.download_url)}>Copy</button>
            <button type="button" className="btn ghost" style={{ fontSize: 12 }}
                    onClick={() => setJustGenerated(null)}>Dismiss</button>
          </div>
          <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 8, fontFamily: 'var(--font-mono)' }}>
            SHA-256 {justGenerated.package_sha256}
          </div>
        </div>
      )}

      {/* Generate */}
      {!isClosed && (
        <div className="panel" style={{ marginBottom: 'var(--space-4)' }}>
          <div style={{ display: 'flex', gap: 'var(--space-3)', flexWrap: 'wrap', alignItems: 'flex-end' }}>
            <div style={{ flex: '1 1 200px' }}>
              <label className="field-label" style={{ display: 'block', marginBottom: 4 }}>Package name</label>
              <input className="input" value={name} onChange={e => setName(e.target.value)}
                     placeholder="e.g. WORKSTATION-07 triage" maxLength={200} style={{ width: '100%' }} />
            </div>
            <div style={{ flex: '1 1 200px' }}>
              <label className="field-label" style={{ display: 'block', marginBottom: 4 }}>Profile</label>
              <select className="select" value={profile} onChange={e => setProfile(e.target.value)} style={{ width: '100%' }}>
                {profiles.map(p => (
                  <option key={`${p.platform}/${p.profile}`} value={`${p.platform}/${p.profile}`}>
                    {p.label}
                  </option>
                ))}
              </select>
            </div>
            <button type="button" className="btn primary"
                    disabled={busy || !name.trim() || !selectedProfile || (cap !== null && activeCount >= cap)}
                    onClick={onGenerate} style={{ fontSize: 12 }}>
              {busy ? 'Generating…' : 'Generate package'}
            </button>
          </div>
          {selectedProfile && (
            <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 10, lineHeight: 1.5 }}>
              {selectedProfile.description}
              <div style={{ marginTop: 4, fontFamily: 'var(--font-mono)' }}>
                {selectedProfile.artifacts.length} artifacts: {selectedProfile.artifacts.join(' · ')}
              </div>
            </div>
          )}
          {cap !== null && (
            <div style={{ fontSize: 11, color: activeCount >= cap ? 'var(--high)' : 'var(--dim)', marginTop: 8 }}>
              {activeCount} / {cap} active packages for this incident
              {activeCount >= cap && ' — download or delete one before generating another.'}
            </div>
          )}
        </div>
      )}

      {/* Package list */}
      {packages.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">⊟</div>
          <div>No collection packages yet</div>
        </div>
      ) : (
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
            <thead>
              <tr>
                {['Name', 'Profile', 'Status', 'Size', 'Created', 'SHA-256', ''].map(h => (
                  <th key={h} style={{
                    textAlign: 'left', padding: '8px 10px', borderBottom: '1px solid var(--border)',
                    color: 'var(--dim)', fontSize: 10, fontWeight: 700, textTransform: 'uppercase',
                    letterSpacing: '0.06em', whiteSpace: 'nowrap',
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {packages.map(p => (
                <tr key={p.id}>
                  <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)' }}>
                    <div style={{ fontWeight: 600, color: 'var(--text)' }}>{p.name}</div>
                    <div style={{ fontSize: 10, color: 'var(--dim)', fontFamily: 'var(--font-mono)' }}>{p.platform}</div>
                  </td>
                  <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)', fontFamily: 'var(--font-mono)', fontSize: 11 }}>
                    {p.profile}
                  </td>
                  <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)' }}>
                    <StatusPill status={p.status} isStale={p.is_stale} />
                    {p.is_stale && p.status === 'generated' && (
                      <div style={{ fontSize: 10, color: 'var(--high)', marginTop: 2 }} title="Built with an outdated Velociraptor version">⚠ outdated build</div>
                    )}
                  </td>
                  <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)', whiteSpace: 'nowrap' }}>
                    {fmtSize(p.file_size)}
                  </td>
                  <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)', color: 'var(--muted)', whiteSpace: 'nowrap', fontSize: 11 }}>
                    {p.created_at ? formatLocal(p.created_at) : '—'}
                    <div style={{ fontSize: 10, color: 'var(--dim)' }}>{p.created_by}</div>
                  </td>
                  <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)', color: 'var(--dim)', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
                    {p.package_sha256 ? `${p.package_sha256.slice(0, 10)}…` : '—'}
                  </td>
                  <td style={{ padding: '8px 10px', borderBottom: '1px solid var(--border)', textAlign: 'right', whiteSpace: 'nowrap' }}>
                    {p.status === 'ingested' && p.result_artifact_id && (
                      <>
                        <Link to={`../timeline-import?artifact=${p.result_artifact_id}`} relative="path"
                              className="btn ghost" style={{ fontSize: 11, textDecoration: 'none', marginRight: 6 }}>
                          Review in Timeline Import
                        </Link>
                        <Link to="../artifacts" relative="path" className="btn ghost" style={{ fontSize: 11, textDecoration: 'none', marginRight: 6 }}>
                          View artifact ↗
                        </Link>
                      </>
                    )}
                    {!isClosed && p.status !== 'deleted' && p.status !== 'ingested' && (
                      <button type="button" className="btn ghost" style={{ fontSize: 11, marginRight: 6 }}
                              disabled={ingesting}
                              onClick={() => startIngest(p)}>Ingest results</button>
                    )}
                    {!isClosed && p.status !== 'deleted' && (
                      <button type="button" className="btn ghost" style={{ fontSize: 11 }}
                              onClick={() => onDelete(p)}>Delete</button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
