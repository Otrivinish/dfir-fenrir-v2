import { useCallback, useEffect, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal, relative } from '../../../lib/datetime.js'
import UtcDateTimePicker from '../../../components/UtcDateTimePicker.jsx'

// Web Browser History — upload a Chrome/Edge/Brave `History` file or
// Firefox `places.sqlite`, parsed offline (read-only SQLite, no BLOB/
// favicon rendering, quarantined like any other forensic artifact).
// Parsed visits/search-terms persist server-side, so this page survives a
// refresh — it isn't request-scoped state.

// Real URLs (SSO redirects, search-tool query strings, tracking pixels) can
// run into the thousands of characters — truncate for display with a
// native <details> expand, same pattern OSINT's crt.sh subdomain list uses.
const URL_TRUNCATE_AT = 90

function TruncatedUrl({ url }) {
  if (!url || url.length <= URL_TRUNCATE_AT) {
    return <span style={{ wordBreak: 'break-all' }}>{url}</span>
  }
  return (
    <details>
      <summary style={{ cursor: 'pointer', wordBreak: 'break-all' }}>
        {url.slice(0, URL_TRUNCATE_AT)}… <span style={{ color: 'var(--dim)', fontSize: 10 }}>({url.length} chars)</span>
      </summary>
      <div style={{ wordBreak: 'break-all', marginTop: 4, color: 'var(--muted)' }}>{url}</div>
    </details>
  )
}

function formatBytes(n) {
  if (n == null) return '—'
  if (n < 1024) return `${n} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = n, i = -1
  do { v /= 1024; i++ } while (v >= 1024 && i < units.length - 1)
  return `${v.toFixed(1)} ${units[i]}`
}

const DOWNLOAD_STATE_COLOR = { complete: 'var(--ok)', in_progress: 'var(--accent)', cancelled: 'var(--dim)', interrupted: 'var(--high)' }

const BROWSERS = [
  { value: 'chrome',  label: 'Chrome' },
  { value: 'edge',    label: 'Edge' },
  { value: 'brave',   label: 'Brave' },
  { value: 'firefox', label: 'Firefox' },
]
const BROWSER_LABEL = Object.fromEntries(BROWSERS.map(b => [b.value, b.label]))

export default function WebBrowserHistory() {
  const { inc } = useOutletContext()
  const incidentId = inc.id
  const isClosed = inc?.status === 'closed'

  const [uploads, setUploads]   = useState([])
  const [uploadsErr, setUploadsErr] = useState(null)

  const [file, setFile]       = useState(null)
  const [browser, setBrowser] = useState('chrome')
  const [formHistoryFile, setFormHistoryFile] = useState(null)
  const [uploading, setUploading] = useState(false)
  const [uploadErr, setUploadErr] = useState(null)

  const [tab, setTab] = useState('visits')   // 'visits' | 'search-terms' | 'downloads'
  const [filterUpload, setFilterUpload] = useState('')
  const [filterBrowser, setFilterBrowser] = useState('')
  const [search, setSearch] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')

  const [visits, setVisits] = useState([])
  const [visitsCursor, setVisitsCursor] = useState(null)
  const [visitsLoading, setVisitsLoading] = useState(false)
  const [visitsErr, setVisitsErr] = useState(null)

  const [terms, setTerms] = useState([])
  const [termsCursor, setTermsCursor] = useState(null)
  const [termsLoading, setTermsLoading] = useState(false)

  const [downloads, setDownloads] = useState([])
  const [downloadsCursor, setDownloadsCursor] = useState(null)
  const [downloadsLoading, setDownloadsLoading] = useState(false)
  const [downloadsErr, setDownloadsErr] = useState(null)

  const [selected, setSelected] = useState(new Set())
  const [iocTarget, setIocTarget] = useState(null)

  const loadUploads = useCallback(() => {
    api.listWebHistoryUploads(incidentId)
      .then(r => setUploads(r.items))
      .catch(e => setUploadsErr(e.message || 'Failed to load uploads.'))
  }, [incidentId])
  useEffect(() => { loadUploads() }, [loadUploads])

  // uploadOverride lets a just-clicked Uploads-list row search immediately
  // with its own id, bypassing the stale `filterUpload` closure a state
  // setter + synchronous call would otherwise read before the re-render.
  const buildFilters = useCallback((cursor, uploadOverride) => ({
    search: search.trim() || undefined,
    upload_id: (uploadOverride !== undefined ? uploadOverride : filterUpload) || undefined,
    browser: filterBrowser || undefined,
    date_from: dateFrom || undefined,
    date_to: dateTo || undefined,
    cursor: cursor || undefined,
  }), [search, filterUpload, filterBrowser, dateFrom, dateTo])

  const runVisitSearch = useCallback(async (uploadOverride) => {
    setVisitsLoading(true); setVisitsErr(null)
    try {
      const r = await api.listWebHistoryVisits(incidentId, buildFilters(null, uploadOverride))
      setVisits(r.items); setVisitsCursor(r.next_cursor); setSelected(new Set())
    } catch (e) {
      setVisitsErr(e.message || 'Search failed.')
    } finally {
      setVisitsLoading(false)
    }
  }, [incidentId, buildFilters])

  const loadMoreVisits = async () => {
    if (!visitsCursor) return
    setVisitsLoading(true)
    try {
      const r = await api.listWebHistoryVisits(incidentId, buildFilters(visitsCursor))
      setVisits(prev => [...prev, ...r.items]); setVisitsCursor(r.next_cursor)
    } catch (e) {
      setVisitsErr(e.message || 'Search failed.')
    } finally {
      setVisitsLoading(false)
    }
  }

  const runTermSearch = useCallback(async (uploadOverride) => {
    setTermsLoading(true)
    try {
      const r = await api.listWebHistorySearchTerms(incidentId, {
        search: search.trim() || undefined,
        upload_id: (uploadOverride !== undefined ? uploadOverride : filterUpload) || undefined,
      })
      setTerms(r.items); setTermsCursor(r.next_cursor)
    } finally {
      setTermsLoading(false)
    }
  }, [incidentId, search, filterUpload])

  const loadMoreTerms = async () => {
    if (!termsCursor) return
    setTermsLoading(true)
    try {
      const r = await api.listWebHistorySearchTerms(incidentId, {
        search: search.trim() || undefined, upload_id: filterUpload || undefined, cursor: termsCursor,
      })
      setTerms(prev => [...prev, ...r.items]); setTermsCursor(r.next_cursor)
    } finally {
      setTermsLoading(false)
    }
  }

  const runDownloadSearch = useCallback(async (uploadOverride) => {
    setDownloadsLoading(true); setDownloadsErr(null)
    try {
      const r = await api.listWebHistoryDownloads(incidentId, {
        search: search.trim() || undefined,
        upload_id: (uploadOverride !== undefined ? uploadOverride : filterUpload) || undefined,
        browser: filterBrowser || undefined,
      })
      setDownloads(r.items); setDownloadsCursor(r.next_cursor); setSelected(new Set())
    } catch (e) {
      setDownloadsErr(e.message || 'Search failed.')
    } finally {
      setDownloadsLoading(false)
    }
  }, [incidentId, search, filterUpload, filterBrowser])

  const loadMoreDownloads = async () => {
    if (!downloadsCursor) return
    setDownloadsLoading(true)
    try {
      const r = await api.listWebHistoryDownloads(incidentId, {
        search: search.trim() || undefined, upload_id: filterUpload || undefined,
        browser: filterBrowser || undefined, cursor: downloadsCursor,
      })
      setDownloads(prev => [...prev, ...r.items]); setDownloadsCursor(r.next_cursor)
    } catch (e) {
      setDownloadsErr(e.message || 'Search failed.')
    } finally {
      setDownloadsLoading(false)
    }
  }

  const runActiveSearch = (uploadOverride) => {
    if (tab === 'visits') runVisitSearch(uploadOverride)
    else if (tab === 'downloads') runDownloadSearch(uploadOverride)
    else runTermSearch(uploadOverride)
  }

  const onSelectUploadRow = (u) => {
    const next = filterUpload === u.id ? '' : u.id
    setFilterUpload(next)
    runActiveSearch(next)
  }

  useEffect(() => {
    if (uploads.length === 0) return
    runActiveSearch()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [uploads.length, tab])

  const onUpload = async () => {
    if (!file) return
    setUploading(true); setUploadErr(null)
    try {
      const created = await api.uploadWebHistory(incidentId, { file, browser, formHistoryFile: browser === 'firefox' ? formHistoryFile : null })
      setFile(null); setFormHistoryFile(null)
      loadUploads()
      // Auto-select the just-uploaded file so its parsed data shows immediately,
      // instead of silently staying on "All uploads" (looked like nothing happened
      // when e.g. a 0-visit file was uploaded on top of other uploads' data).
      setFilterUpload(created.id)
      runActiveSearch(created.id)
    } catch (e) {
      setUploadErr(e.message || 'Upload failed.')
    } finally {
      setUploading(false)
    }
  }

  const onDeleteUpload = async (u) => {
    if (!confirm(`Delete this ${BROWSER_LABEL[u.browser]} upload and its ${u.record_count} visits, ${u.search_term_count} search terms, and ${u.download_count} downloads?`)) return
    try {
      await api.deleteWebHistoryUpload(incidentId, u.id)
      const stillSelected = filterUpload === u.id ? '' : filterUpload
      if (stillSelected !== filterUpload) setFilterUpload(stillSelected)
      loadUploads(); runActiveSearch(stillSelected)
    } catch (e) {
      setUploadsErr(e.message || 'Delete failed.')
    }
  }

  const onMintEvidence = async (u) => {
    try {
      await api.mintWebHistoryEvidence(incidentId, u.id)
      loadUploads()
    } catch (e) {
      setUploadsErr(e.message || 'Mint failed.')
    }
  }

  const toggleSelect = (id) => setSelected(prev => {
    const n = new Set(prev)
    n.has(id) ? n.delete(id) : n.add(id)
    return n
  })
  const activeList = tab === 'visits' ? visits : tab === 'downloads' ? downloads : []
  const allSelected = activeList.length > 0 && activeList.every(v => selected.has(v.id))
  const toggleAll = () => setSelected(allSelected ? new Set() : new Set(activeList.map(v => v.id)))

  const hasChromiumUpload = uploads.some(u => u.schema_family === 'chromium')
  const hasAnyDownloads = uploads.some(u => u.download_count > 0)

  return (
    <section className="panel">
      <div className="panel-toolbar">
        <h2 className="panel-h">Web Browser History</h2>
        <span style={{ color: 'var(--muted)', fontSize: 13 }}>
          Upload a browser history database → search, filter, promote to IOCs
        </span>
      </div>

      {/* Upload */}
      <div style={{
        display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap',
        padding: 'var(--space-3)', background: 'var(--surface-2)', borderRadius: 'var(--radius)',
        marginBottom: 'var(--space-3)',
      }}>
        <select className="select" value={browser} onChange={e => setBrowser(e.target.value)} disabled={uploading || isClosed}>
          {BROWSERS.map(b => <option key={b.value} value={b.value}>{b.label}</option>)}
        </select>
        <input type="file" disabled={uploading || isClosed}
               onChange={e => setFile(e.target.files?.[0] || null)} />
        {browser === 'firefox' && (
          <label style={{ display: 'flex', gap: 'var(--space-1)', alignItems: 'center', fontSize: 12, color: 'var(--muted)' }}>
            + formhistory.sqlite (optional, for search terms)
            <input type="file" disabled={uploading || isClosed}
                   onChange={e => setFormHistoryFile(e.target.files?.[0] || null)} />
          </label>
        )}
        <button type="button" className="btn primary" onClick={onUpload} disabled={!file || uploading || isClosed}>
          {uploading ? 'Uploading…' : 'Upload & Parse'}
        </button>
        <span style={{ color: 'var(--dim)', fontSize: 11 }}>
          Chrome/Edge/Brave "History" or Firefox "places.sqlite" — up to 500 MB. Parsed offline, read-only; nothing is executed.
          Firefox search-bar terms live in a separate formhistory.sqlite — upload both together.
        </span>
      </div>
      {uploadErr && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{uploadErr}</span>
        </div>
      )}
      {uploadsErr && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{uploadsErr}</span>
        </div>
      )}

      {/* Uploads list */}
      {uploads.length === 0 ? (
        <div className="panel-empty" style={{ marginBottom: 'var(--space-3)' }}>No uploads yet.</div>
      ) : (
        <div style={{ marginBottom: 'var(--space-4)' }}>
          {uploads.map(u => (
            <div key={u.id} onClick={() => onSelectUploadRow(u)} title="Click to show only this upload's parsed data" style={{
              display: 'flex', alignItems: 'center', gap: 'var(--space-3)', flexWrap: 'wrap', cursor: 'pointer',
              padding: 'var(--space-2)', margin: '0 calc(-1 * var(--space-2))', borderRadius: 'var(--radius)',
              borderBottom: '1px solid var(--border)', fontSize: 12,
              background: filterUpload === u.id ? 'var(--accent-soft)' : 'transparent',
            }}>
              <span className="pill">{BROWSER_LABEL[u.browser] || u.browser}</span>
              <span style={{ fontFamily: 'var(--font-mono)' }}>{u.original_filename}</span>
              <span style={{ color: 'var(--muted)' }}>{u.record_count} visits · {u.search_term_count} search terms · {u.download_count} downloads</span>
              {u.truncated && <span style={{ color: 'var(--high)' }}>⚠ truncated at defensive cap</span>}
              <span style={{ color: 'var(--dim)' }} title={formatLocal(u.uploaded_at)}>{relative(u.uploaded_at)} · {u.uploaded_by}</span>
              <div style={{ marginLeft: 'auto', display: 'flex', gap: 'var(--space-2)' }} onClick={e => e.stopPropagation()}>
                {u.evidence_id ? (
                  <span style={{ color: 'var(--ok)' }}>Evidence ✓</span>
                ) : (
                  <button type="button" className="btn ghost" style={{ fontSize: 12, padding: '2px 8px' }}
                          onClick={() => onMintEvidence(u)} disabled={isClosed}>Mint as Evidence</button>
                )}
                <button type="button" className="btn-link danger" onClick={() => onDeleteUpload(u)} disabled={isClosed}>Delete</button>
              </div>
            </div>
          ))}
        </div>
      )}

      {uploads.length > 0 && (
        <>
          {/* Tabs */}
          <div className="det-add-tabs" style={{ marginBottom: 'var(--space-3)' }}>
            <button type="button" className={`btn ghost ${tab === 'visits' ? 'active' : ''}`} onClick={() => setTab('visits')}>Visits</button>
            {hasChromiumUpload && (
              <button type="button" className={`btn ghost ${tab === 'search-terms' ? 'active' : ''}`} onClick={() => setTab('search-terms')}>Search terms</button>
            )}
            {hasAnyDownloads && (
              <button type="button" className={`btn ghost ${tab === 'downloads' ? 'active' : ''}`} onClick={() => setTab('downloads')}>Downloads</button>
            )}
          </div>

          {/* Filters */}
          <div style={{ display: 'flex', gap: 'var(--space-2)', flexWrap: 'wrap', alignItems: 'center', marginBottom: 'var(--space-2)' }}>
            <input className="input" style={{ maxWidth: 260 }} placeholder="Search URL/title/host…"
                   value={search} onChange={e => setSearch(e.target.value)}
                   onKeyDown={e => e.key === 'Enter' && runActiveSearch()} />
            <select className="select" value={filterUpload} onChange={e => setFilterUpload(e.target.value)}>
              <option value="">All uploads</option>
              {uploads.map(u => <option key={u.id} value={u.id}>{u.original_filename} ({BROWSER_LABEL[u.browser]})</option>)}
            </select>
            {(tab === 'visits' || tab === 'downloads') && (
              <>
                <select className="select" value={filterBrowser} onChange={e => setFilterBrowser(e.target.value)}>
                  <option value="">All browsers</option>
                  {BROWSERS.map(b => <option key={b.value} value={b.value}>{b.label}</option>)}
                </select>
                <div style={{ width: 190 }}><UtcDateTimePicker value={dateFrom} onChange={setDateFrom} clearable /></div>
                <div style={{ width: 190 }}><UtcDateTimePicker value={dateTo} onChange={setDateTo} clearable /></div>
              </>
            )}
            <button type="button" className="btn primary" onClick={() => runActiveSearch()}>Search</button>
            {(tab === 'visits' || tab === 'downloads') && selected.size > 0 && (
              <button type="button" className="btn ghost" onClick={() => setIocTarget([...selected])} disabled={isClosed}>
                Add {selected.size} to IOCs
              </button>
            )}
          </div>

          {tab === 'visits' ? (
            <>
              {visitsErr && (
                <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-2)' }}>
                  <span className="alert-icon">!</span><span>{visitsErr}</span>
                </div>
              )}
              <div style={{ overflowX: 'auto' }}>
                <table className="settings-table">
                  <thead>
                    <tr>
                      <th style={{ width: 32 }}><input type="checkbox" checked={allSelected} onChange={toggleAll} /></th>
                      <th style={{ width: 150 }}>Visit time (UTC)</th>
                      <th>URL</th>
                      <th>Title</th>
                      <th style={{ width: 80 }}>Browser</th>
                      <th style={{ width: 90 }}>Transition</th>
                    </tr>
                  </thead>
                  <tbody>
                    {visits.map(v => (
                      <tr key={v.id}>
                        <td><input type="checkbox" checked={selected.has(v.id)} onChange={() => toggleSelect(v.id)} /></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} title={formatLocal(v.visit_time)}>
                          {v.visit_time.replace('T', ' ').slice(0, 19)}
                        </td>
                        <td style={{ fontSize: 12, maxWidth: 360 }}><TruncatedUrl url={v.url} /></td>
                        <td style={{ fontSize: 12, color: 'var(--muted)' }}>{v.title || '—'}</td>
                        <td><span className="pill" style={{ fontSize: 10 }}>{BROWSER_LABEL[v.browser] || v.browser}</span></td>
                        <td style={{ fontSize: 11, color: 'var(--dim)' }}>{v.transition || '—'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {visits.length === 0 && !visitsLoading && <div className="panel-empty">No visits match.</div>}
              {visitsCursor && (
                <button type="button" className="btn ghost" style={{ marginTop: 'var(--space-2)' }} onClick={loadMoreVisits} disabled={visitsLoading}>
                  {visitsLoading ? 'Loading…' : 'Load more'}
                </button>
              )}
            </>
          ) : tab === 'downloads' ? (
            <>
              {downloadsErr && (
                <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-2)' }}>
                  <span className="alert-icon">!</span><span>{downloadsErr}</span>
                </div>
              )}
              <div style={{ overflowX: 'auto' }}>
                <table className="settings-table">
                  <thead>
                    <tr>
                      <th style={{ width: 32 }}><input type="checkbox" checked={allSelected} onChange={toggleAll} /></th>
                      <th style={{ width: 150 }}>Start time (UTC)</th>
                      <th>Saved to</th>
                      <th>URL</th>
                      <th style={{ width: 90 }}>Size</th>
                      <th style={{ width: 90 }}>State</th>
                      <th style={{ width: 80 }}>Browser</th>
                    </tr>
                  </thead>
                  <tbody>
                    {downloads.map(d => (
                      <tr key={d.id}>
                        <td><input type="checkbox" checked={selected.has(d.id)} onChange={() => toggleSelect(d.id)} disabled={!d.url} /></td>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} title={d.start_time ? formatLocal(d.start_time) : ''}>
                          {d.start_time ? d.start_time.replace('T', ' ').slice(0, 19) : '—'}
                        </td>
                        <td style={{ fontSize: 12 }}><TruncatedUrl url={d.target_path} /></td>
                        <td style={{ fontSize: 12, maxWidth: 300 }}>{d.url ? <TruncatedUrl url={d.url} /> : <span style={{ color: 'var(--dim)' }}>—</span>}</td>
                        <td style={{ fontSize: 12, color: 'var(--muted)' }}>{formatBytes(d.total_bytes ?? d.received_bytes)}</td>
                        <td>
                          {d.state && (
                            <span style={{ color: DOWNLOAD_STATE_COLOR[d.state] || 'var(--muted)', fontSize: 11, fontWeight: 600 }}>{d.state}</span>
                          )}
                          {d.danger && d.danger !== 'not_dangerous' && (
                            <div style={{ color: 'var(--crit)', fontSize: 10 }}>⚠ {d.danger}</div>
                          )}
                        </td>
                        <td><span className="pill" style={{ fontSize: 10 }}>{BROWSER_LABEL[d.browser] || d.browser}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {downloads.length === 0 && !downloadsLoading && <div className="panel-empty">No downloads match.</div>}
              {downloadsCursor && (
                <button type="button" className="btn ghost" style={{ marginTop: 'var(--space-2)' }} onClick={loadMoreDownloads} disabled={downloadsLoading}>
                  {downloadsLoading ? 'Loading…' : 'Load more'}
                </button>
              )}
            </>
          ) : (
            <>
              <div style={{ overflowX: 'auto' }}>
                <table className="settings-table">
                  <thead><tr><th style={{ width: 150 }}>Time (UTC)</th><th>Term</th><th>Associated URL</th><th style={{ width: 80 }}>Browser</th></tr></thead>
                  <tbody>
                    {terms.map(t => (
                      <tr key={t.id}>
                        <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }} title={t.visit_time ? formatLocal(t.visit_time) : ''}>
                          {t.visit_time ? t.visit_time.replace('T', ' ').slice(0, 19) : '—'}
                        </td>
                        <td style={{ fontSize: 13, fontWeight: 600 }}>{t.term}</td>
                        <td style={{ fontSize: 12, color: 'var(--muted)' }}>{t.url ? <TruncatedUrl url={t.url} /> : '—'}</td>
                        <td><span className="pill" style={{ fontSize: 10 }}>{BROWSER_LABEL[t.browser] || t.browser}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {terms.length === 0 && !termsLoading && <div className="panel-empty">No search terms match.</div>}
              {termsCursor && (
                <button type="button" className="btn ghost" style={{ marginTop: 'var(--space-2)' }} onClick={loadMoreTerms} disabled={termsLoading}>
                  {termsLoading ? 'Loading…' : 'Load more'}
                </button>
              )}
            </>
          )}
        </>
      )}

      {iocTarget && (
        <AddUrlsIocModal
          incidentId={incidentId}
          items={activeList.filter(v => iocTarget.includes(v.id) && v.url)}
          onClose={() => setIocTarget(null)}
          onCreated={() => { setIocTarget(null); setSelected(new Set()) }}
        />
      )}
    </section>
  )
}

// Generic bulk "add as IOC" modal for anything with a `.url` — reused for
// both visits and downloads (a download's target_path isn't promotable,
// only its source URL).
function AddUrlsIocModal({ incidentId, items, onClose, onCreated }) {
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState(null)
  const [done, setDone] = useState(null)

  const onSubmit = async (e) => {
    e.preventDefault()
    setBusy(true); setError(null)
    let created = 0, skipped = 0
    for (const v of items) {
      try {
        await api.createIoc(incidentId, { type: 'url', value: v.url, source: 'Browser history' })
        created++
      } catch (err) {
        if (err.status === 409) skipped++
        else { setError(err.message || 'Could not add IOC.'); setBusy(false); return }
      }
    }
    setDone({ created, skipped })
    setBusy(false)
  }

  return (
    <div className="modal-backdrop">
      <div className="modal" role="dialog" aria-labelledby="webhist-ioc-title" style={{ maxWidth: 480 }}>
        <div className="modal-head">
          <h2 id="webhist-ioc-title">Add {items.length} URL{items.length !== 1 ? 's' : ''} as IOCs</h2>
          <button type="button" className="modal-close" onClick={onClose} disabled={busy} aria-label="Close">×</button>
        </div>
        {done ? (
          <div className="modal-body">
            <div className="alert info" role="alert">
              <span className="alert-icon">✓</span>
              <span>Added {done.created} IOC{done.created !== 1 ? 's' : ''}.{done.skipped > 0 ? ` ${done.skipped} already existed (skipped).` : ''}</span>
            </div>
            <div className="modal-foot" style={{ marginTop: 'var(--space-3)' }}>
              <button type="button" className="btn primary" onClick={onCreated}>Close</button>
            </div>
          </div>
        ) : (
          <form onSubmit={onSubmit}>
            <div className="modal-body">
              {error && (
                <div className="alert error" style={{ marginBottom: 'var(--space-3)' }}>
                  <span className="alert-icon">!</span><span>{error}</span>
                </div>
              )}
              <div style={{ fontSize: 12, color: 'var(--muted)', maxHeight: 200, overflowY: 'auto' }}>
                {items.map(v => <div key={v.id} style={{ fontFamily: 'var(--font-mono)', marginBottom: 2 }}><TruncatedUrl url={v.url} /></div>)}
              </div>
            </div>
            <div className="modal-foot">
              <button type="button" className="btn ghost" onClick={onClose} disabled={busy}>Cancel</button>
              <button type="submit" className="btn primary" disabled={busy}>{busy ? 'Adding…' : `Add ${items.length} IOCs`}</button>
            </div>
          </form>
        )}
      </div>
    </div>
  )
}
