import { useCallback, useEffect, useRef, useState } from 'react'
import { useOutletContext } from 'react-router-dom'
import { api } from '../../../api/client.js'
import { formatLocal } from '../../../lib/datetime.js'

// ─── Shared ───────────────────────────────────────────────────────────────────

const TABS = ['YARA Rules', 'Scan Results', 'Detection Queries']

const SAMPLE_RULE = `rule SuspiciousPowerShell {
    meta:
        description = "Detects suspicious PowerShell encoded/download patterns"
        author = "DFIR-FENRIR"
    strings:
        $enc = "EncodedCommand" nocase
        $iex = "IEX" nocase
        $dl  = "DownloadString" nocase
    condition:
        any of them
}`

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)
  function copy() {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }
  return (
    <button className="btn ghost det-copy-btn" onClick={copy}>
      {copied ? '✓ Copied' : 'Copy'}
    </button>
  )
}

// ─── Tab 1: YARA Rules ────────────────────────────────────────────────────────

function RuleCard({ rule, onToggle, onDelete }) {
  const [expanded, setExpanded] = useState(false)
  return (
    <div className={`det-rule-card${rule.is_active ? '' : ' det-rule-inactive'}`}
         style={{ borderLeftColor: rule.is_active ? 'var(--ok)' : 'var(--border)' }}>
      <div className="det-rule-head">
        <div className="det-rule-info">
          <span className="det-rule-name">{rule.name}</span>
          {rule.match_count > 0 && (
            <span className="det-hit-badge">{rule.match_count} hit{rule.match_count !== 1 ? 's' : ''}</span>
          )}
          {!rule.is_active && <span className="det-disabled-badge">disabled</span>}
        </div>
        <div className="det-rule-meta">
          {rule.author && <span>By: {rule.author}</span>}
          {rule.description && <span className="det-rule-desc">{rule.description.slice(0, 80)}</span>}
          {rule.last_matched_at && (
            <span style={{ color: 'var(--high)' }}>Last hit: {formatLocal(rule.last_matched_at).slice(0, 10)}</span>
          )}
        </div>
        {rule.tags?.length > 0 && (
          <div className="det-rule-tags">
            {rule.tags.map(t => <span key={t} className="det-tag">{t}</span>)}
          </div>
        )}
      </div>
      <div className="det-rule-actions">
        <button className="btn ghost det-action-btn" onClick={() => setExpanded(e => !e)}>
          {expanded ? '▲' : '▼'} Rule
        </button>
        <button className="btn ghost det-action-btn" onClick={() => onToggle(rule)}
                style={{ color: rule.is_active ? 'var(--med)' : 'var(--ok)' }}>
          {rule.is_active ? 'Disable' : 'Enable'}
        </button>
        <button className="btn ghost det-action-btn" style={{ color: 'var(--crit)' }}
                onClick={() => onDelete(rule.id)}>✕</button>
      </div>
      {expanded && (
        <pre className="det-rule-content">{rule.rule_content}</pre>
      )}
    </div>
  )
}

function YaraRules() {
  const [rules,       setRules]       = useState([])
  const [loading,     setLoading]     = useState(true)
  const [showAdd,     setShowAdd]     = useState(false)
  const [mode,        setMode]        = useState('paste') // paste | upload
  const [ruleText,    setRuleText]    = useState(SAMPLE_RULE)
  const [ruleName,    setRuleName]    = useState('')
  const [ruleAuthor,  setRuleAuthor]  = useState('')
  const [ruleDesc,    setRuleDesc]    = useState('')
  const [busy,        setBusy]        = useState(false)
  const [error,       setError]       = useState(null)
  const fileRef = useRef()

  const load = useCallback(async () => {
    try {
      const data = await api.listYaraRules()
      setRules(data.items || [])
    } catch { /* empty */ }
    setLoading(false)
  }, [])

  useEffect(() => { load() }, [load])

  async function addRule() {
    if (!ruleText.trim()) return
    setBusy(true); setError(null)
    try {
      const r = await api.createYaraRule({
        name: ruleName, author: ruleAuthor, description: ruleDesc,
        rule_content: ruleText, tags: [],
      })
      setRules(prev => [...prev, r])
      setShowAdd(false); setRuleText(SAMPLE_RULE); setRuleName(''); setRuleAuthor(''); setRuleDesc('')
    } catch (e) { setError(e.message || 'Failed to add rule') }
    setBusy(false)
  }

  async function uploadFile(file) {
    setBusy(true); setError(null)
    try {
      const r = await api.uploadYaraRule(file)
      setRules(prev => [...prev, r])
      setShowAdd(false)
    } catch (e) { setError(e.message || 'Upload failed') }
    setBusy(false)
  }

  async function toggle(rule) {
    try {
      const updated = await api.updateYaraRule(rule.id, { is_active: !rule.is_active })
      setRules(prev => prev.map(r => r.id === updated.id ? updated : r))
    } catch { /* leave as-is */ }
  }

  async function deleteRule(id) {
    try {
      await api.deleteYaraRule(id)
      setRules(prev => prev.filter(r => r.id !== id))
    } catch { /* leave as-is */ }
  }

  const active   = rules.filter(r => r.is_active).length
  const inactive = rules.length - active

  return (
    <div className="det-section">
      <div className="det-section-head">
        <div className="det-section-stats">
          <span>{rules.length} rule{rules.length !== 1 ? 's' : ''}</span>
          {active > 0   && <span className="det-stat-ok">{active} active</span>}
          {inactive > 0 && <span className="det-stat-muted">{inactive} disabled</span>}
        </div>
        <button className="btn primary det-add-btn" onClick={() => setShowAdd(s => !s)}>
          {showAdd ? 'Cancel' : '+ Add Rule'}
        </button>
      </div>

      {showAdd && (
        <div className="det-add-panel">
          <div className="det-add-tabs">
            <button className={`det-mode-btn${mode === 'paste' ? ' active' : ''}`} onClick={() => setMode('paste')}>Paste rule</button>
            <button className={`det-mode-btn${mode === 'upload' ? ' active' : ''}`} onClick={() => setMode('upload')}>Upload .yar file</button>
          </div>

          {mode === 'paste' ? (
            <>
              <div className="det-form-row">
                <input className="input det-input-sm" placeholder="Rule name (auto-parsed if blank)" value={ruleName} onChange={e => setRuleName(e.target.value)} />
                <input className="input det-input-sm" placeholder="Author" value={ruleAuthor} onChange={e => setRuleAuthor(e.target.value)} />
              </div>
              <input className="input" placeholder="Description" value={ruleDesc} onChange={e => setRuleDesc(e.target.value)} style={{ marginBottom: 'var(--space-2)' }} />
              <textarea className="det-rule-editor" rows={12} value={ruleText} onChange={e => setRuleText(e.target.value)} spellCheck={false} />
              {error && <div className="det-error">{error}</div>}
              <div className="det-add-foot">
                <button className="btn primary" onClick={addRule} disabled={busy || !ruleText.trim()}>
                  {busy ? 'Adding…' : 'Add Rule'}
                </button>
              </div>
            </>
          ) : (
            <>
              <div className="det-upload-zone" onClick={() => fileRef.current?.click()}>
                <div className="det-upload-icon">📄</div>
                <div className="det-upload-label">Click to select a .yar / .yara file</div>
                <input ref={fileRef} type="file" accept=".yar,.yara,.rules" style={{ display: 'none' }}
                       onChange={e => e.target.files?.[0] && uploadFile(e.target.files[0])} />
              </div>
              {busy && <div className="det-loading">Uploading…</div>}
              {error && <div className="det-error">{error}</div>}
            </>
          )}
        </div>
      )}

      {loading ? (
        <div className="det-loading">Loading rules…</div>
      ) : rules.length === 0 ? (
        <div className="det-empty">No YARA rules in library yet. Add one above.</div>
      ) : (
        <div className="det-rule-list">
          {rules.map(r => (
            <RuleCard key={r.id} rule={r} onToggle={toggle} onDelete={deleteRule} />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Tab 2: Scan Results ──────────────────────────────────────────────────────

function MatchCard({ match, incidentId, onAction }) {
  const [expanded, setExpanded] = useState(false)
  const [busy,     setBusy]     = useState('')

  async function promote(action) {
    setBusy(action)
    try {
      if (action === 'timeline') await api.yaraMatchTimeline(incidentId, match.id)
      else                       await api.yaraMatchIoc(incidentId, match.id)
      onAction(match.id, action)
    } catch { /* leave as-is */ }
    setBusy('')
  }

  return (
    <div className="det-match-card">
      <div className="det-match-head">
        <span className="det-match-rule">{match.rule_name}</span>
        <span className="det-match-arrow">→</span>
        <span className="det-match-artifact">{match.artifact_name || 'unknown artifact'}</span>
        <span className="det-match-count">{match.matched_strings?.length || 0} string{match.matched_strings?.length !== 1 ? 's' : ''}</span>
      </div>
      <div className="det-match-actions">
        <button className="btn ghost det-action-btn" onClick={() => setExpanded(e => !e)}>
          {expanded ? '▲' : '▼'} strings
        </button>
        <button className="btn ghost det-action-btn" onClick={() => promote('timeline')}
                disabled={!!busy} style={{ color: 'var(--accent)' }}>
          {busy === 'timeline' ? '…' : '→ Timeline'}
        </button>
        <button className="btn ghost det-action-btn" onClick={() => promote('ioc')}
                disabled={!!busy} style={{ color: 'var(--high)' }}>
          {busy === 'ioc' ? '…' : '→ IOC (SHA256)'}
        </button>
      </div>
      {expanded && match.matched_strings?.length > 0 && (
        <pre className="det-match-strings">
          {match.matched_strings.map((s, i) => (
            `${s.identifier || '?'} @ 0x${(s.offset || 0).toString(16)}: ${s.data || ''}`
          )).join('\n')}
        </pre>
      )}
      <div className="det-match-ts">{formatLocal(match.created_at)}</div>
    </div>
  )
}

function ScanResults({ inc }) {
  const [matches,  setMatches]  = useState([])
  const [loading,  setLoading]  = useState(true)
  const [scanning, setScanning] = useState(false)
  const [lastScan, setLastScan] = useState(null)
  const [error,    setError]    = useState(null)

  const load = useCallback(async () => {
    try {
      const data = await api.listYaraMatches(inc.id)
      setMatches(data.items || [])
    } catch { /* empty */ }
    setLoading(false)
  }, [inc.id])

  useEffect(() => { load() }, [load])

  async function runScan() {
    setScanning(true); setError(null)
    try {
      const result = await api.yaraRunScan(inc.id)
      setLastScan(result)
      await load()
    } catch (e) { setError(e.message || 'Scan failed') }
    setScanning(false)
  }

  async function clearAll() {
    try {
      await api.clearYaraMatches(inc.id)
      setMatches([])
    } catch { /* empty */ }
  }

  function handleAction(matchId, action) {
    // On success, don't remove the match — just visual feedback is enough
  }

  return (
    <div className="det-section">
      <div className="det-section-head">
        <div className="det-section-stats">
          <span>{matches.length} match{matches.length !== 1 ? 'es' : ''}</span>
          {lastScan && (
            <span className="det-stat-muted">
              Last scan: {lastScan.artifacts_scanned} artifacts, {lastScan.matches_found} new
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)' }}>
          {matches.length > 0 && (
            <button className="btn ghost" onClick={clearAll} style={{ color: 'var(--muted)', fontSize: 12 }}>
              Clear all
            </button>
          )}
          <button className="btn primary det-add-btn" onClick={runScan} disabled={scanning}>
            {scanning ? 'Scanning…' : '▶ Run YARA Scan'}
          </button>
        </div>
      </div>

      {lastScan?.errors?.length > 0 && (
        <div className="det-scan-errors">
          {lastScan.errors.map((e, i) => <div key={i} className="det-error-row">{e}</div>)}
        </div>
      )}
      {error && <div className="det-error">{error}</div>}

      {loading ? (
        <div className="det-loading">Loading matches…</div>
      ) : matches.length === 0 ? (
        <div className="det-empty">No YARA matches yet. Run a scan after uploading artifacts and adding rules.</div>
      ) : (
        <div className="det-match-list">
          {matches.map(m => (
            <MatchCard key={m.id} match={m} incidentId={inc.id} onAction={handleAction} />
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Tab 3: Detection Queries ─────────────────────────────────────────────────

const PLATFORM_ORDER = ['kql', 'eql', 'spl', 'xql', 'cs']
const PLATFORM_LABELS = { kql: 'Defender / Sentinel', eql: 'Elastic', spl: 'Splunk', xql: 'Cortex XDR', cs: 'CrowdStrike' }
const CATEGORY_ORDER  = ['Indicator', 'Behavioral', 'Hunt']
const CONFIDENCE_COLOR = { HIGH: 'var(--crit)', MEDIUM: 'var(--high)', LOW: 'var(--low)' }

function QueryCard({ q }) {
  return (
    <div className="det-query-card">
      <div className="det-query-head">
        <span className="det-query-label">{q.label}</span>
        <span className="det-conf-pill" style={{ color: CONFIDENCE_COLOR[q.confidence] || 'var(--muted)' }}>
          {q.confidence}
        </span>
        <CopyButton text={q.query} />
      </div>
      <pre className="det-query-pre">{q.query}</pre>
    </div>
  )
}

function DetectionQueries({ inc }) {
  const [bundle,   setBundle]   = useState(null)
  const [loading,  setLoading]  = useState(true)
  const [platform, setPlatform] = useState('kql')
  const [category, setCategory] = useState('all')

  useEffect(() => {
    api.getDetections(inc.id)
      .then(setBundle)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [inc.id])

  if (loading) return <div className="det-loading">Generating detection queries…</div>
  if (!bundle)  return <div className="det-error">Failed to load detection queries.</div>

  const platData = bundle.platforms.find(p => p.platform === platform)
  const queries  = (platData?.queries || []).filter(q => category === 'all' || q.category === category)

  function copyAll() {
    const text = queries.map(q => `// [${q.confidence}] [${q.category}] ${q.label}\n${q.query}`).join('\n\n')
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="det-section">
      <div className="det-section-head" style={{ flexWrap: 'wrap', gap: 'var(--space-2)' }}>
        <div className="det-platform-bar">
          {PLATFORM_ORDER.map(key => (
            <button key={key}
                    className={`det-plat-btn${platform === key ? ' active' : ''}`}
                    onClick={() => setPlatform(key)}>
              {PLATFORM_LABELS[key]}
            </button>
          ))}
        </div>
        <div style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center' }}>
          <select className="select det-cat-select"
                  value={category} onChange={e => setCategory(e.target.value)}>
            <option value="all">All categories</option>
            {CATEGORY_ORDER.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          {queries.length > 0 && (
            <button className="btn ghost" style={{ fontSize: 12 }} onClick={copyAll}>Copy all</button>
          )}
          <a href={api.detectionsDownloadUrl(inc.id)} download
             className="btn ghost" style={{ fontSize: 12, textDecoration: 'none' }}>
            ↓ ZIP
          </a>
        </div>
      </div>

      <div className="det-query-stats">
        <span>{queries.length} quer{queries.length !== 1 ? 'ies' : 'y'}</span>
        {bundle.total > queries.length && (
          <span className="det-stat-muted">({bundle.total} total across all platforms)</span>
        )}
      </div>

      {queries.length === 0 ? (
        <div className="det-empty">
          No queries for this platform and category. Add IOCs or MITRE-mapped timeline events to generate more.
        </div>
      ) : (
        <div className="det-query-list">
          {CATEGORY_ORDER.filter(c => category === 'all' || c === category).map(cat => {
            const catQ = queries.filter(q => q.category === cat)
            if (!catQ.length) return null
            return (
              <div key={cat} className="det-category-group">
                <div className="det-category-label">{cat}</div>
                {catQ.map((q, i) => <QueryCard key={i} q={q} />)}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Page root ────────────────────────────────────────────────────────────────

export default function Detections() {
  const { inc } = useOutletContext()
  const [tab, setTab] = useState(0)

  return (
    <div className="det-root">
      <div className="det-tab-bar">
        {TABS.map((t, i) => (
          <button key={t} className={`det-tab${tab === i ? ' det-tab-active' : ''}`} onClick={() => setTab(i)}>
            {t}
          </button>
        ))}
      </div>
      <div className="det-content">
        {tab === 0 && <YaraRules />}
        {tab === 1 && <ScanResults inc={inc} />}
        {tab === 2 && <DetectionQueries inc={inc} />}
      </div>
    </div>
  )
}
