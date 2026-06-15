import { useCallback, useEffect, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'

// ─── Analysis tool definitions ───────────────────────────────────────────────

const TOOLS = [
  { id: 'hashes',      label: 'Hashes'       },
  { id: 'file-type',   label: 'File Type'     },
  { id: 'strings',     label: 'Strings'       },
  { id: 'ioc-extract', label: 'IOC Extract'   },
  { id: 'entropy',     label: 'Entropy'       },
  { id: 'pe',          label: 'PE Analysis'   },
  { id: 'office',      label: 'Office/Macro'  },
  { id: 'pdf',         label: 'PDF'           },
  { id: 'exif',        label: 'Metadata/EXIF' },
  { id: 'hexdump',     label: 'Hex Dump'      },
  { id: 'yara',        label: 'YARA'          },
]

function fmtSize(bytes) {
  if (bytes === null || bytes === undefined) return '—'
  if (bytes < 1024)         return `${bytes} B`
  if (bytes < 1024 * 1024)  return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

function truncHash(h) {
  return h ? `${h.slice(0, 8)}…${h.slice(-8)}` : '—'
}

// ─── Main component ──────────────────────────────────────────────────────────

export default function Artifacts() {
  const { inc } = useOutletContext()
  const isClosed = inc?.status === 'closed'

  const [artifacts, setArtifacts] = useState([])
  const [loading,   setLoading]   = useState(true)
  const [error,     setError]     = useState(null)
  const [uploading, setUploading] = useState(false)
  const [dragOver,  setDragOver]  = useState(false)
  const [selected,  setSelected]  = useState(null)   // artifact being analysed
  const fileRef = useRef(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const r = await api.listArtifacts(inc.id)
      setArtifacts(r.items || [])
    } catch (e) {
      setError(e.message || 'Could not load artifacts')
    } finally {
      setLoading(false)
    }
  }, [inc.id])

  useEffect(() => { load() }, [load])

  const handleUpload = async (file) => {
    if (!file) return
    setUploading(true); setError(null)
    try {
      await api.uploadArtifact(inc.id, file, null)
      await load()
    } catch (e) {
      setError(e.message || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  const onFileChange = (e) => {
    const f = e.target.files?.[0]
    if (f) handleUpload(f)
    e.target.value = ''
  }

  const onDrop = (e) => {
    e.preventDefault(); setDragOver(false)
    if (isClosed || uploading) return
    const f = e.dataTransfer.files?.[0]
    if (f) handleUpload(f)
  }

  const onDelete = async (artifact) => {
    if (!window.confirm(`Delete artifact "${artifact.original_filename}"?\n\nThis permanently removes the file.`)) return
    try {
      await api.deleteArtifact(inc.id, artifact.id)
      if (selected?.id === artifact.id) setSelected(null)
      await load()
    } catch (e) {
      setError(e.message || 'Delete failed')
    }
  }

  if (loading) return <div className="panel-empty">Loading…</div>

  return (
    <div>
      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {/* Upload zone */}
      {!isClosed && (
        <div
          onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={onDrop}
          onClick={() => !uploading && fileRef.current?.click()}
          style={{
            border: `2px dashed ${dragOver ? 'var(--accent)' : 'var(--border)'}`,
            borderRadius: 'var(--radius)',
            padding: 'var(--space-4)',
            textAlign: 'center',
            cursor: uploading ? 'default' : 'pointer',
            background: dragOver ? 'color-mix(in srgb, var(--accent) 6%, var(--surface))' : 'var(--surface)',
            marginBottom: 'var(--space-4)',
            transition: 'border-color 0.15s, background 0.15s',
          }}
        >
          <input ref={fileRef} type="file" style={{ display: 'none' }} onChange={onFileChange} />
          <div style={{ fontSize: 22, marginBottom: 8, color: 'var(--muted)' }}>⬆</div>
          <div style={{ fontSize: 13, color: 'var(--muted)' }}>
            {uploading ? 'Uploading…' : 'Drop a file here or click to select (max 500 MB)'}
          </div>
          {!uploading && (
            <div style={{ fontSize: 11, color: 'var(--dim)', marginTop: 6 }}>
              SHA-256, SHA-512 &amp; MD5 hashed on ingest · MIME detected · IOCs auto-extracted
            </div>
          )}
        </div>
      )}

      {artifacts.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">◌</div>
          <div>No artifacts uploaded yet.</div>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 'var(--space-2)' }}>
          {artifacts.map(a => (
            <ArtifactCard
              key={a.id}
              artifact={a}
              incidentId={inc.id}
              isClosed={isClosed}
              isSelected={selected?.id === a.id}
              onSelect={() => setSelected(prev => prev?.id === a.id ? null : a)}
              onDelete={() => onDelete(a)}
              onAnalysisResult={(updated) => {
                setArtifacts(prev => prev.map(x => x.id === updated.id ? updated : x))
                setSelected(updated)
              }}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Artifact card ───────────────────────────────────────────────────────────

function ArtifactCard({ artifact, incidentId, isClosed, isSelected, onSelect, onDelete, onAnalysisResult }) {
  const mimeIcon = (mime) => {
    if (!mime) return '📄'
    if (mime.includes('pdf'))         return '📕'
    if (mime.includes('msword') || mime.includes('wordprocessingml')) return '📄'
    if (mime.includes('excel') || mime.includes('spreadsheetml'))     return '📊'
    if (mime.includes('zip') || mime.includes('rar') || mime.includes('7z')) return '🗜'
    if (mime.includes('x-dosexec') || mime.includes('x-executable'))  return '⚙'
    if (mime.includes('text'))        return '📝'
    if (mime.includes('image'))       return '🖼'
    if (mime.includes('video'))       return '🎬'
    if (mime.includes('audio'))       return '🎵'
    return '📄'
  }

  return (
    <div style={{
      background: 'var(--surface)',
      border: `1px solid ${isSelected ? 'var(--border-strong)' : 'var(--border)'}`,
      borderRadius: 'var(--radius)',
      overflow: 'hidden',
    }}>
      {/* Header row */}
      <div
        role="button"
        tabIndex={0}
        onClick={onSelect}
        onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); onSelect() } }}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 'var(--space-3)',
          padding: 'var(--space-3)',
          cursor: 'pointer',
          userSelect: 'none',
        }}
      >
        <span style={{ fontSize: 20, flexShrink: 0 }}>{mimeIcon(artifact.mime_type)}</span>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text)', wordBreak: 'break-all', marginBottom: 2 }}>
            {artifact.original_filename}
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', fontSize: 11, color: 'var(--muted)' }}>
            <span style={{ fontFamily: 'var(--font-mono)' }}>{artifact.mime_type || '—'}</span>
            <span>{fmtSize(artifact.file_size)}</span>
            <span style={{ fontFamily: 'var(--font-mono)' }} title={artifact.sha256_hash}>
              sha256:{truncHash(artifact.sha256_hash)}
            </span>
            <span style={{ color: 'var(--dim)' }}>{artifact.uploaded_by}</span>
            <span style={{ color: 'var(--dim)' }}>{artifact.uploaded_at ? formatLocal(artifact.uploaded_at) : ''}</span>
          </div>
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', flexShrink: 0, alignItems: 'center' }}>
          <a
            href={`/api/incidents/${incidentId}/artifacts/${artifact.id}/download`}
            download
            onClick={(e) => e.stopPropagation()}
            className="btn ghost"
            style={{ fontSize: 11 }}
            title="Download (password-protected ZIP, password: infected)"
          >
            Download
          </a>
          {!isClosed && (
            <button
              type="button"
              className="btn ghost"
              style={{ fontSize: 11 }}
              onClick={(e) => { e.stopPropagation(); onDelete() }}
            >
              Delete
            </button>
          )}
          <span style={{ fontSize: 11, color: 'var(--dim)' }}>{isSelected ? '▲' : '▼'}</span>
        </div>
      </div>

      {/* Analysis panel */}
      {isSelected && (
        <AnalysisPanel
          artifact={artifact}
          incidentId={incidentId}
          onResult={onAnalysisResult}
        />
      )}
    </div>
  )
}

// ─── Analysis panel ──────────────────────────────────────────────────────────

function AnalysisPanel({ artifact, incidentId, onResult }) {
  const [activeTool, setActiveTool] = useState(null)
  const [running,    setRunning]    = useState(false)
  const [error,      setError]      = useState(null)

  const runTool = async (toolId) => {
    setActiveTool(toolId); setRunning(true); setError(null)
    try {
      const result = await api.analyzeArtifact(incidentId, artifact.id, toolId)
      // Merge result into artifact so the display updates.
      onResult({
        ...artifact,
        analysis_results: { ...artifact.analysis_results, [toolId]: result },
        analysis_status: 'completed',
      })
    } catch (e) {
      setError(e.message || `Analysis failed for ${toolId}`)
    } finally {
      setRunning(false)
    }
  }

  const currentResult = activeTool ? artifact.analysis_results?.[activeTool] : null

  return (
    <div style={{
      borderTop: '1px solid var(--border)',
      background: 'var(--surface-2)',
    }}>
      {/* Tool selector tabs */}
      <div style={{
        display: 'flex',
        overflowX: 'auto',
        gap: 2,
        padding: '0 var(--space-3)',
        borderBottom: '1px solid var(--border)',
      }}>
        {TOOLS.map(t => {
          const hasResult = Boolean(artifact.analysis_results?.[t.id])
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => runTool(t.id)}
              disabled={running}
              style={{
                padding: '8px 12px',
                fontSize: 11,
                fontFamily: 'var(--font-mono)',
                border: 'none',
                borderBottom: activeTool === t.id ? '2px solid var(--accent)' : '2px solid transparent',
                background: 'none',
                color: activeTool === t.id ? 'var(--accent)' : hasResult ? 'var(--text)' : 'var(--muted)',
                cursor: running ? 'default' : 'pointer',
                whiteSpace: 'nowrap',
                fontWeight: activeTool === t.id ? 700 : 400,
              }}
            >
              {t.label}{hasResult && activeTool !== t.id ? ' ✓' : ''}
            </button>
          )
        })}
      </div>

      {/* Results area */}
      <div style={{ padding: 'var(--space-3)' }}>
        {!activeTool && (
          <div style={{ fontSize: 12, color: 'var(--dim)', textAlign: 'center', paddingTop: 8 }}>
            Select a tool above to run static analysis against this artifact.
          </div>
        )}

        {activeTool && running && (
          <div style={{ fontSize: 12, color: 'var(--muted)', textAlign: 'center', paddingTop: 8 }}>
            Running {activeTool}…
          </div>
        )}

        {error && !running && (
          <div className="alert error" role="alert">
            <span className="alert-icon">!</span><span>{error}</span>
          </div>
        )}

        {activeTool && !running && currentResult && !error && (
          <ToolResult tool={activeTool} result={currentResult} />
        )}
      </div>
    </div>
  )
}

// ─── Tool result renderers ───────────────────────────────────────────────────

function ToolResult({ tool, result }) {
  if (result?.error) {
    return (
      <div style={{ fontSize: 12, color: 'var(--high)', fontFamily: 'var(--font-mono)' }}>
        {result.error}
      </div>
    )
  }

  switch (tool) {
    case 'hashes':     return <HashesResult r={result} />
    case 'file-type':  return <FileTypeResult r={result} />
    case 'strings':    return <StringsResult r={result} />
    case 'ioc-extract': return <IOCExtractResult r={result} />
    case 'entropy':    return <EntropyResult r={result} />
    case 'pe':         return <PEResult r={result} />
    case 'office':     return <OfficeResult r={result} />
    case 'pdf':        return <PDFResult r={result} />
    case 'exif':       return <ExifResult r={result} />
    case 'hexdump':    return <HexResult r={result} />
    case 'yara':       return <YaraResult r={result} />
    default:           return <pre style={{ fontSize: 11, fontFamily: 'var(--font-mono)', overflowX: 'auto' }}>{JSON.stringify(result, null, 2)}</pre>
  }
}

// — Shared primitives —

function KV({ label, value, mono }) {
  return (
    <div style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 4, alignItems: 'flex-start' }}>
      <span style={{ fontSize: 11, color: 'var(--muted)', minWidth: 140, flexShrink: 0 }}>{label}</span>
      <span style={{ fontSize: 11, fontFamily: mono ? 'var(--font-mono)' : undefined, color: 'var(--text)', wordBreak: 'break-all' }}>
        {value ?? '—'}
      </span>
    </div>
  )
}

function Pill({ children, color }) {
  return (
    <span className="pill" style={{ fontSize: 10, color, background: color ? `color-mix(in srgb, ${color} 15%, var(--surface-2))` : undefined }}>
      {children}
    </span>
  )
}

function Section({ title, children }) {
  return (
    <div style={{ marginBottom: 'var(--space-3)' }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: '0.05em' }}>
        {title}
      </div>
      {children}
    </div>
  )
}

// — Renderers —

function HashesResult({ r }) {
  const entropyColor = r.entropy > 7 ? 'var(--crit)' : r.entropy > 6 ? 'var(--high)' : r.entropy > 4 ? 'var(--med)' : 'var(--ok)'
  return (
    <div>
      <KV label="MD5"    value={r.md5}    mono />
      <KV label="SHA-1"  value={r.sha1}   mono />
      <KV label="SHA-256" value={r.sha256} mono />
      <KV label="SHA-512" value={r.sha512} mono />
      <KV label="Size"   value={fmtSize(r.size)} />
      <KV label="Entropy" value={
        <span style={{ color: entropyColor }}>{r.entropy} bits/byte — {r.entropy_flag?.replace(/_/g, ' ')}</span>
      } />
    </div>
  )
}

function FileTypeResult({ r }) {
  return (
    <div>
      <KV label="MIME type"    value={r.mime_type}    mono />
      <KV label="Description"  value={r.description} />
      <KV label="Declared ext" value={r.declared_ext || '—'} mono />
      <KV label="Expected ext" value={r.expected_ext || '—'} mono />
      {r.ext_mismatch && (
        <div style={{ fontSize: 12, color: 'var(--crit)', fontWeight: 600, marginTop: 8 }}>
          ⚠ Extension mismatch — declared {r.declared_ext} but detected {r.expected_ext}
        </div>
      )}
      <KV label="Size" value={fmtSize(r.file_size)} />
    </div>
  )
}

function StringsResult({ r }) {
  return (
    <div>
      {r.error && <div style={{ color: 'var(--high)', fontSize: 11, marginBottom: 8 }}>{r.error}</div>}
      {Object.keys(r.suspicious_apis || {}).length > 0 && (
        <Section title="Suspicious APIs">
          {Object.entries(r.suspicious_apis).map(([cat, fns]) => (
            <div key={cat} style={{ marginBottom: 6 }}>
              <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--high)' }}>{cat.replace(/_/g, ' ')}: </span>
              {fns.map(fn => (
                <Pill key={fn} color="var(--high)">{fn}</Pill>
              ))}
            </div>
          ))}
        </Section>
      )}
      {Object.entries(r.iocs || {}).filter(([, v]) => v?.length).map(([k, v]) => (
        <Section key={k} title={`IOCs — ${k}`}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {v.slice(0, 50).map((x, i) => (
              <Pill key={i} color="var(--accent)">{x}</Pill>
            ))}
            {v.length > 50 && <span style={{ fontSize: 11, color: 'var(--dim)' }}>+{v.length - 50} more</span>}
          </div>
        </Section>
      ))}
      {r.b64_candidates?.length > 0 && (
        <Section title="Base64 candidates">
          <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, display: 'flex', flexDirection: 'column', gap: 2 }}>
            {r.b64_candidates.slice(0, 20).map((s, i) => (
              <div key={i} style={{ color: 'var(--muted)', wordBreak: 'break-all' }}>{s}</div>
            ))}
          </div>
        </Section>
      )}
      <Section title={`Strings (${r.ascii?.length || 0} ASCII, ${r.unicode?.length || 0} Unicode)`}>
        <pre style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text)', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: 8, maxHeight: 250, overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>
          {(r.ascii || []).slice(0, 500).join('\n')}
        </pre>
      </Section>
    </div>
  )
}

function IOCExtractResult({ r }) {
  const categories = [
    ['IPs', r.ips], ['URLs', r.urls], ['Domains', r.domains],
    ['Emails', r.emails], ['MD5s', r.md5s], ['SHA1s', r.sha1s],
    ['SHA256s', r.sha256s], ['CVEs', r.cves], ['Registry keys', r.registry_keys], ['UNC paths', r.unc_paths],
  ].filter(([, v]) => v?.length)

  return (
    <div>
      <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 12 }}>
        Total: {r.total} IOC{r.total !== 1 ? 's' : ''} found
      </div>
      {categories.map(([label, items]) => (
        <Section key={label} title={`${label} (${items.length})`}>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {items.slice(0, 40).map((x, i) => (
              <Pill key={i} color="var(--accent)">{x}</Pill>
            ))}
            {items.length > 40 && <span style={{ fontSize: 11, color: 'var(--dim)' }}>+{items.length - 40} more</span>}
          </div>
        </Section>
      ))}
      {categories.length === 0 && <div style={{ fontSize: 12, color: 'var(--dim)' }}>No IOCs found.</div>}
    </div>
  )
}

function EntropyResult({ r }) {
  const color = r.overall_entropy > 7.2 ? 'var(--crit)' : r.overall_entropy > 6.5 ? 'var(--high)' : 'var(--ok)'
  return (
    <div>
      <div style={{ textAlign: 'center', marginBottom: 16 }}>
        <div style={{ fontSize: 36, fontWeight: 700, fontFamily: 'var(--font-mono)', color }}>{r.overall_entropy}</div>
        <div style={{ fontSize: 11, color: 'var(--muted)' }}>bits per byte</div>
        <div style={{ fontSize: 12, color, marginTop: 4 }}>{r.interpretation?.replace(/_/g, ' ')}</div>
      </div>
      <KV label="High-entropy chunks" value={`${r.high_entropy_chunks} / ${r.total_chunks}`} />
      <Section title="Per-chunk distribution">
        <div style={{ display: 'flex', gap: 1, flexWrap: 'wrap', maxHeight: 80, overflowY: 'auto' }}>
          {(r.chunks || []).map((c, i) => {
            const h = Math.min(c.entropy / 8, 1)
            const col = h > 0.9 ? 'var(--crit)' : h > 0.8 ? 'var(--high)' : h > 0.6 ? 'var(--med)' : 'var(--ok)'
            return (
              <div key={i} title={`Offset ${c.offset}: ${c.entropy} bits/byte`}
                style={{ width: 6, height: `${Math.round(h * 24) + 4}px`, background: col, flexShrink: 0 }}
              />
            )
          })}
        </div>
      </Section>
    </div>
  )
}

function PEResult({ r }) {
  return (
    <div>
      <div style={{ display: 'flex', gap: 'var(--space-3)', marginBottom: 12, flexWrap: 'wrap', alignItems: 'center' }}>
        <div style={{ fontSize: 24, fontWeight: 700, fontFamily: 'var(--font-mono)', color: r.suspicion_score > 60 ? 'var(--crit)' : r.suspicion_score > 30 ? 'var(--high)' : 'var(--ok)' }}>
          {r.suspicion_score}<span style={{ fontSize: 12, fontWeight: 400 }}>/100</span>
        </div>
        <div style={{ fontSize: 11, color: 'var(--muted)' }}>suspicion score</div>
        {(r.suspicion_flags || []).map(f => (
          <Pill key={f} color="var(--high)">{f.replace(/_/g, ' ')}</Pill>
        ))}
      </div>
      <KV label="Machine"     value={r.machine}      mono />
      <KV label="Entry point" value={r.entry_point}   mono />
      <KV label="Image base"  value={r.image_base}    mono />
      <KV label="Sections"    value={r.num_sections} />
      {r.version_info && Object.keys(r.version_info).length > 0 && (
        <Section title="Version info">
          {Object.entries(r.version_info).map(([k, v]) => <KV key={k} label={k} value={v} mono />)}
        </Section>
      )}
      {r.sections?.length > 0 && (
        <Section title="Sections">
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {r.sections.map(s => (
              <div key={s.name} style={{ display: 'flex', gap: 12, fontSize: 11, fontFamily: 'var(--font-mono)', alignItems: 'center' }}>
                <span style={{ minWidth: 80, color: 'var(--text)' }}>{s.name}</span>
                <span style={{ color: 'var(--muted)' }}>{s.vaddr}</span>
                <span style={{ color: 'var(--muted)' }}>{fmtSize(s.raw_size)}</span>
                <span style={{ color: s.entropy > 7 ? 'var(--crit)' : 'var(--muted)' }}>ent:{s.entropy}</span>
              </div>
            ))}
          </div>
        </Section>
      )}
      {r.imports && Object.keys(r.imports).length > 0 && (
        <Section title={`Imports (${Object.keys(r.imports).length} DLLs)`}>
          <div style={{ maxHeight: 200, overflowY: 'auto', fontFamily: 'var(--font-mono)', fontSize: 10 }}>
            {Object.entries(r.imports).slice(0, 20).map(([dll, fns]) => (
              <div key={dll} style={{ marginBottom: 4 }}>
                <span style={{ color: 'var(--accent)' }}>{dll}</span>
                <span style={{ color: 'var(--dim)', marginLeft: 8 }}>{fns.slice(0, 10).join(', ')}{fns.length > 10 ? ` +${fns.length - 10}` : ''}</span>
              </div>
            ))}
          </div>
        </Section>
      )}
    </div>
  )
}

function OfficeResult({ r }) {
  const riskColor = r.risk === 'high' ? 'var(--crit)' : r.risk === 'medium' ? 'var(--high)' : 'var(--ok)'
  return (
    <div>
      <div style={{ display: 'flex', gap: 12, alignItems: 'center', marginBottom: 12 }}>
        <Pill color={riskColor}>MACRO RISK: {r.risk?.toUpperCase()}</Pill>
        <span style={{ fontSize: 11, color: 'var(--muted)' }}>{r.has_macros ? `${r.macro_count} macro module${r.macro_count !== 1 ? 's' : ''}` : 'No macros'}</span>
      </div>
      {r.all_indicators?.length > 0 && (
        <Section title="Suspicious indicators">
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {r.all_indicators.map(i => <Pill key={i} color="var(--high)">{i}</Pill>)}
          </div>
        </Section>
      )}
      {r.macros?.map((m, i) => (
        <Section key={i} title={`Module: ${m.vba_file || m.stream}`}>
          <pre style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text)', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: 8, maxHeight: 250, overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>
            {m.code}
          </pre>
        </Section>
      ))}
    </div>
  )
}

function PDFResult({ r }) {
  const riskColor = r.risk === 'high' ? 'var(--crit)' : r.risk === 'medium' ? 'var(--high)' : 'var(--ok)'
  return (
    <div>
      <Pill color={riskColor}>RISK: {r.risk?.toUpperCase()}</Pill>
      {Object.keys(r.suspicious_keywords || {}).length > 0 && (
        <Section title="Suspicious keywords">
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4, marginTop: 8 }}>
            {Object.entries(r.suspicious_keywords).map(([kw, cnt]) => (
              <Pill key={kw} color="var(--high)">{kw} ×{cnt}</Pill>
            ))}
          </div>
        </Section>
      )}
      {r.text_preview && (
        <Section title="Text preview">
          <pre style={{ fontSize: 10, fontFamily: 'var(--font-mono)', color: 'var(--text)', background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: 8, maxHeight: 200, overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all', margin: 0 }}>
            {r.text_preview}
          </pre>
        </Section>
      )}
    </div>
  )
}

function ExifResult({ r }) {
  if (!r.fields || Object.keys(r.fields).length === 0) {
    return <div style={{ fontSize: 12, color: 'var(--dim)' }}>No metadata found (tool: {r.tool || 'none'}).</div>
  }
  const sensitive = new Set(r.sensitive_fields || [])
  return (
    <div>
      {r.sensitive_fields?.length > 0 && (
        <div style={{ fontSize: 12, color: 'var(--high)', marginBottom: 12, fontWeight: 600 }}>
          ⚠ {r.sensitive_fields.length} sensitive field{r.sensitive_fields.length !== 1 ? 's' : ''} found
        </div>
      )}
      <div style={{ maxHeight: 300, overflowY: 'auto' }}>
        {Object.entries(r.fields).map(([k, v]) => (
          <KV key={k} label={k} value={
            sensitive.has(k) ? <span style={{ color: 'var(--high)' }}>{String(v)}</span> : String(v)
          } mono />
        ))}
      </div>
    </div>
  )
}

function HexResult({ r }) {
  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 8 }}>
        Offset {r.offset}, {r.length} bytes of {fmtSize(r.file_size)}
      </div>
      <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, background: 'var(--bg)', border: '1px solid var(--border)', borderRadius: 'var(--radius-sm)', padding: 8, maxHeight: 300, overflowY: 'auto', overflowX: 'auto' }}>
        {(r.lines || []).map((line, i) => (
          <div key={i} style={{ display: 'flex', gap: 16, lineHeight: 1.8 }}>
            <span style={{ color: 'var(--dim)', minWidth: 70 }}>{line.offset}</span>
            <span style={{ color: 'var(--muted)', minWidth: 280 }}>{line.hex.padEnd(47)}</span>
            <span style={{ color: 'var(--text)' }}>{line.ascii}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function YaraResult({ r }) {
  if (r.error) return <div style={{ fontSize: 12, color: 'var(--high)' }}>{r.error}</div>
  return (
    <div>
      <div style={{ fontSize: 12, color: 'var(--muted)', marginBottom: 12 }}>
        {r.rules_loaded} rule files loaded · {r.matches?.length || 0} match{r.matches?.length !== 1 ? 'es' : ''}
        {r.note && <span style={{ color: 'var(--dim)', marginLeft: 8 }}>{r.note}</span>}
      </div>
      {(r.matches || []).map((m, i) => (
        <div key={i} style={{ background: 'var(--surface)', border: '1px solid var(--border)', borderLeft: '3px solid var(--crit)', borderRadius: 'var(--radius)', padding: 'var(--space-2)', marginBottom: 8 }}>
          <div style={{ fontWeight: 700, fontSize: 12, color: 'var(--crit)', marginBottom: 4 }}>{m.rule}</div>
          <div style={{ fontSize: 11, color: 'var(--muted)', marginBottom: 4 }}>{m.namespace}</div>
          {m.tags?.length > 0 && <div style={{ display: 'flex', gap: 4, marginBottom: 4 }}>{m.tags.map(t => <Pill key={t}>{t}</Pill>)}</div>}
          {m.strings?.length > 0 && (
            <div style={{ fontFamily: 'var(--font-mono)', fontSize: 10, color: 'var(--dim)' }}>
              {m.strings.map((s, j) => (
                <div key={j}>{s.identifier} @ 0x{s.offset?.toString(16)}: {s.data}</div>
              ))}
            </div>
          )}
        </div>
      ))}
      {r.matches?.length === 0 && <div style={{ fontSize: 12, color: 'var(--dim)' }}>No YARA rules matched.</div>}
    </div>
  )
}
