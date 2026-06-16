import { useCallback, useEffect, useState } from 'react'
import { api } from '../../api/client.js'
import { formatLocal } from '../../lib/datetime.js'

function formatBytes(bytes) {
  if (bytes < 1024)           return `${bytes} B`
  if (bytes < 1024 * 1024)   return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

// Parse date from filename: fenrir_backup_YYYY-MM-DD_HH-MM-SS.sql.gz
function parseFilenameDate(filename) {
  const m = filename.match(/fenrir_backup_(\d{4}-\d{2}-\d{2})_(\d{2}-\d{2}-\d{2})/)
  if (!m) return null
  return `${m[1]}T${m[2].replace(/-/g, ':')}Z`
}

export default function Backup() {
  const [backups,    setBackups]    = useState([])
  const [isRunning,  setIsRunning]  = useState(false)
  const [loading,    setLoading]    = useState(true)
  const [error,      setError]      = useState(null)
  const [runError,     setRunError]     = useState(null)
  const [lastRun,      setLastRun]      = useState(null)
  const [runStartedAt, setRunStartedAt] = useState(null)

  const load = useCallback(async () => {
    setError(null)
    try {
      const res = await api.listBackups()
      setBackups(res.backups)
      setIsRunning(res.is_running)
      setLastRun(res.last_run || null)
    } catch (e) {
      setError(e.message || 'Could not load backup status')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  // Poll while a backup is running
  useEffect(() => {
    if (!isRunning) return
    const t = setInterval(load, 3000)
    return () => clearInterval(t)
  }, [isRunning, load])

  async function triggerBackup() {
    setRunError(null)
    try {
      const res = await api.runBackup()
      setRunStartedAt(res?.started_at || null)
      setIsRunning(true)
      // First poll after a short delay to give pg_dump a moment to start
      setTimeout(load, 2000)
    } catch (e) {
      setRunError(e.message || 'Failed to start backup')
    }
  }

  // Show the terminal outcome of the run we triggered (or, on first load, the
  // backend's last recorded run). Gated on finished_at >= our started_at so a
  // stale earlier result never masquerades as this run's.
  const showResult = lastRun
    && (lastRun.state === 'success' || lastRun.state === 'error')
    && (!runStartedAt || (lastRun.finished_at && lastRun.finished_at >= runStartedAt))

  const lastBackup = backups[0]

  return (
    <div>
      <div style={{ marginBottom: 'var(--space-4)' }}>
        <h2 style={{ margin: 0, fontSize: 18, fontFamily: 'var(--font-heading)' }}>Backup Status</h2>
        <p style={{ color: 'var(--muted)', fontSize: 13, marginTop: 'var(--space-1)', marginBottom: 0 }}>
          PostgreSQL backups run automatically every 24 hours. Files are gzip-compressed SQL dumps
          retained for 14 days. A manual backup can be triggered at any time.
        </p>
      </div>

      {/* What's in / not in this backup */}
      <div style={{
        display: 'flex', gap: 'var(--space-2)',
        background: 'var(--surface-2)', border: '1px solid var(--border)',
        borderLeft: '3px solid var(--accent)', borderRadius: 'var(--radius)',
        padding: 'var(--space-3)', marginBottom: 'var(--space-4)',
        fontSize: 12, color: 'var(--muted)', lineHeight: 1.55,
      }}>
        <span aria-hidden="true" style={{ color: 'var(--accent)', flexShrink: 0 }}>ℹ</span>
        <div>
          <strong style={{ color: 'var(--text)' }}>What this backup contains.</strong>{' '}
          A complete dump of the <strong>PostgreSQL database</strong> — incidents, IOCs, timeline,
          entities, the audit log and user records. It is small because it is text that compresses
          well, not because anything is missing. It does <strong>not</strong> include your{' '}
          <strong>evidence files</strong> (mirrored separately as encrypted blobs under{' '}
          <code style={{ fontFamily: 'var(--font-mono)' }}>evidence-mirror/</code>) or any{' '}
          <strong>secrets</strong> — the{' '}
          <code style={{ fontFamily: 'var(--font-mono)' }}>EVIDENCE_KEK</code> and other keys live in{' '}
          <code style={{ fontFamily: 'var(--font-mono)' }}>.env</code>, never in a backup. A full
          restore needs all three: this DB dump <strong>+</strong> the evidence mirror{' '}
          <strong>+</strong> the{' '}
          <code style={{ fontFamily: 'var(--font-mono)' }}>EVIDENCE_KEK</code>/secrets.
        </div>
      </div>

      {error && (
        <div className="alert error" role="alert" style={{ marginBottom: 'var(--space-3)' }}>
          <span className="alert-icon">!</span><span>{error}</span>
        </div>
      )}

      {/* Status summary card */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: 'var(--space-3)',
        background: 'var(--surface)',
        border: '1px solid var(--border)',
        borderRadius: 'var(--radius)',
        padding: 'var(--space-4)',
        marginBottom: 'var(--space-4)',
      }}>
        <div style={{ display: 'flex', gap: 'var(--space-5)', flexWrap: 'wrap' }}>
          <div>
            <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Last backup</div>
            <div style={{ fontSize: 14, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
              {loading ? '—' : lastBackup ? formatLocal(lastBackup.created_at) : 'None found'}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Backups on disk</div>
            <div style={{ fontSize: 14, fontFamily: 'var(--font-mono)', color: 'var(--text)' }}>
              {loading ? '—' : backups.length}
            </div>
          </div>
          <div>
            <div style={{ fontSize: 11, color: 'var(--muted)', textTransform: 'uppercase', letterSpacing: '0.05em', marginBottom: 4 }}>Status</div>
            <div style={{ fontSize: 13, display: 'flex', alignItems: 'center', gap: 6 }}>
              {isRunning ? (
                <>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent)', display: 'inline-block', animation: 'pulse 1s infinite' }} />
                  <span style={{ color: 'var(--accent)' }}>Running…</span>
                </>
              ) : (
                <>
                  <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--ok)', display: 'inline-block' }} />
                  <span style={{ color: 'var(--ok)' }}>Idle</span>
                </>
              )}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 'var(--space-1)' }}>
          <button
            className="btn primary"
            onClick={triggerBackup}
            disabled={isRunning || loading}
          >
            {isRunning ? 'Backup running…' : 'Run backup now'}
          </button>
          {runError && (
            <span style={{ fontSize: 12, color: 'var(--crit)' }}>{runError}</span>
          )}
          {!runError && !isRunning && showResult && lastRun.state === 'success' && (
            <span style={{ fontSize: 12, color: 'var(--ok)' }}>
              ✓ Completed {formatLocal(lastRun.finished_at)}
            </span>
          )}
          {!runError && !isRunning && showResult && lastRun.state === 'error' && (
            <span style={{ fontSize: 12, color: 'var(--crit)' }}>
              ✕ Backup failed: {lastRun.error}
            </span>
          )}
        </div>
      </div>

      {/* Backup file list */}
      {loading ? (
        <div className="panel-empty"><div>Loading…</div></div>
      ) : backups.length === 0 ? (
        <div className="panel-empty">
          <div className="panel-empty-mark" aria-hidden="true">◌</div>
          <div>No backups found.</div>
          <div style={{ color: 'var(--dim)', fontSize: 12 }}>
            The automatic backup runs 24 h after container start, or trigger one manually above.
          </div>
        </div>
      ) : (
        <table className="settings-table">
          <thead>
            <tr>
              <th>Filename</th>
              <th style={{ width: 160 }}>Created</th>
              <th style={{ width: 100, textAlign: 'right' }}>Size</th>
            </tr>
          </thead>
          <tbody>
            {backups.map(b => (
              <tr key={b.filename}>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12 }}>{b.filename}</td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, color: 'var(--muted)' }}>
                  {formatLocal(b.created_at)}
                </td>
                <td style={{ fontFamily: 'var(--font-mono)', fontSize: 12, textAlign: 'right', color: 'var(--muted)' }}>
                  {formatBytes(b.size_bytes)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  )
}
