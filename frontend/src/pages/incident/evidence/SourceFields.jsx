import { Fragment } from 'react'
import LocalDateTimePicker from '../../../components/LocalDateTimePicker.jsx'
import { formatLocal } from '../../../lib/datetime.js'

// S2 (EG-1/2/3/5) — the source location record: the device and where on it the bytes were, as recorded (the
// acquisition tool's report or the DEFR), never the upload's own name. The API checks it (backend
// evidence/source.py: path style, NUL, length, the MACB basis rule) and derives source_path_norm; this file only
// collects and shows it. The source path, source system and unknown-reason are sent exactly as typed: never
// .trim() them (leading / trailing spaces are part of what was recorded).

export const PATH_STYLES = [
  { value: 'windows',    label: 'Windows (C:\\… or \\\\?\\…)' },
  { value: 'unc',        label: 'UNC share (\\\\server\\share\\…)' },
  { value: 'posix',      label: 'Linux / Unix (/…)' },
  { value: 'macos',      label: 'macOS (/…)' },
  { value: 'android',    label: 'Android (/…)' },
  { value: 'ios',        label: 'iOS (/… or Domain-path)' },
  { value: 'cloud_uri',  label: 'Cloud URI (https, s3, gs, az, abfss)' },
  { value: 'mail_store', label: 'Mailbox / mail store folder' },
  { value: 'device',     label: 'Device (\\\\.\\PhysicalDrive0, /dev/sda)' },
  { value: 'other',      label: 'Other (explain in the note)' },
]
const STYLE_LABEL = Object.fromEntries(PATH_STYLES.map(s => [s.value, s.label]))
const MACB = [['m', 'Modified'], ['a', 'Accessed'], ['c', 'Metadata changed'], ['b', 'Born (created)']]
const MONO = { fontFamily: 'var(--font-mono)' }

export function sourceStateFrom(ex = {}) {
  return {
    make: ex.make || '', model: ex.model || '', serial: ex.serial || '',
    physical_location: ex.physical_location || '',
    source_system: ex.source_system ?? '', source_path: ex.source_path ?? '',
    source_path_style: ex.source_path_style || '', source_unknown_reason: ex.source_unknown_reason ?? '',
    details: ex.source_details || {},       // kept whole, so keys set through the API survive an edit here
  }
}

// Empty strings, nulls and empty objects are left out (the API stores only what is given; v=1 is its default).
function prune(o) {
  if (o === null || o === undefined || o === '') return undefined
  if (typeof o !== 'object' || Array.isArray(o)) return o
  const out = {}
  for (const [k, v] of Object.entries(o)) {
    const p = prune(v)
    if (p !== undefined) out[k] = p
  }
  return Object.keys(out).length ? out : undefined
}

function setIn(obj, path, value) {
  const [k, ...rest] = path
  return { ...(obj || {}), [k]: rest.length ? setIn(obj?.[k], rest, value) : value }
}

// The API fields for the source record (null = not recorded). A physical item has no path (HLD §3.3).
export function sourcePayload(s, kind) {
  const ids = { make: s.make.trim() || null, model: s.model.trim() || null, serial: s.serial.trim() || null,
                source_system: s.source_system || null }
  if (kind === 'physical_item') return ids
  return {
    ...ids,
    source_path: s.source_path || null,
    source_path_style: s.source_path ? (s.source_path_style || null) : null,
    source_unknown_reason: s.source_unknown_reason || null,
    source_details: prune({ ...s.details, v: undefined }) || null,     // nothing but v left = no details
  }
}

function Text({ id, label, value, onChange, max = 256, mono, placeholder }) {
  return (
    <div className="field">
      <label className="field-label" htmlFor={id}>{label}</label>
      <input id={id} className="input" value={value ?? ''} onChange={e => onChange(e.target.value)} maxLength={max}
             placeholder={placeholder} spellCheck={false} autoComplete="off" style={mono ? MONO : undefined} />
    </div>
  )
}

// The Identify step's Source section (digital) or Device section (physical). `showLocation`: the physical item's
// storage location (a create only; the acquisition record does not carry it).
export function SourceSection({ kind, value: s, onChange, showLocation = false, prefix = 'src' }) {
  const set = (k, v) => onChange({ ...s, [k]: v })
  const setD = (path, v) => onChange({ ...s, details: setIn(s.details, path, v) })
  const d = s.details || {}
  const physical = kind === 'physical_item'
  return (
    <fieldset className="field" style={{ border: 0, padding: 0, margin: 0, minWidth: 0 }} data-testid={`${prefix}-section`}>
      <legend className="panel-h" style={{ marginBottom: 'var(--space-2)' }}>
        {physical ? 'Device' : 'Source'}{' '}
        <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>
          · ISO 27037 {physical ? '§7.1.1.1' : '§5.4.2, §7.1.3.4'}
        </span>
      </legend>
      {!physical && (
        <div className="field-hint" style={{ marginBottom: 'var(--space-2)' }}>
          Where the bytes were, as the acquisition tool or your notes record it, not the name of the file you upload.
        </div>
      )}
      <div className="form-row">
        <Text id={`${prefix}-make`} label={physical ? 'Make' : 'Source device make'} value={s.make} onChange={v => set('make', v)} max={128} />
        <Text id={`${prefix}-model`} label={physical ? 'Model' : 'Source device model'} value={s.model} onChange={v => set('model', v)} max={128} />
      </div>
      <div className="form-row">
        <Text id={`${prefix}-serial`} label={physical ? 'Serial' : 'Source device serial'} value={s.serial} onChange={v => set('serial', v)} max={128} mono />
        <Text id={`${prefix}-system`} label={physical ? 'Device name (optional)' : 'Source system'} value={s.source_system}
              onChange={v => set('source_system', v)} mono
              placeholder={physical ? 'e.g. LAPTOP-JDOE' : 'e.g. WS-FIN-017.contoso.local, a tenant or mailbox owner'} />
      </div>
      {physical && showLocation && (
        <Text id={`${prefix}-physloc`} label="Stored at (physical location)" value={s.physical_location}
              onChange={v => set('physical_location', v)} placeholder="e.g. Evidence locker B-12, tamper seal #4471" />
      )}
      {!physical && (
        <>
          <div className="field">
            <label className="field-label" htmlFor={`${prefix}-path`}>Source path</label>
            <input id={`${prefix}-path`} className="input" value={s.source_path} maxLength={32768}
                   onChange={e => set('source_path', e.target.value)} spellCheck={false} autoComplete="off"
                   placeholder="e.g. C:\Users\jdoe\Desktop\Q3.xlsx" style={MONO} />
            <div className="field-hint">Exactly as recorded: spaces, case and Unicode are kept. A folder taken as one container: its root folder.</div>
          </div>
          <div className="form-row">
            <div className="field">
              <label className="field-label" htmlFor={`${prefix}-style`}>Path style{s.source_path ? ' *' : ''}</label>
              <select id={`${prefix}-style`} className="select" value={s.source_path_style}
                      onChange={e => set('source_path_style', e.target.value)}>
                <option value="">— select —</option>
                {PATH_STYLES.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
              </select>
            </div>
            <Text id={`${prefix}-fname`} label="Filename on source" value={d.filename_on_source}
                  onChange={v => setD(['filename_on_source'], v)} max={1024} mono />
          </div>
          <div className="field">
            <label className="field-label" htmlFor={`${prefix}-unknown`}>Unknown source — reason</label>
            <textarea id={`${prefix}-unknown`} className="input" rows={2} maxLength={4096} value={s.source_unknown_reason}
                      onChange={e => set('source_unknown_reason', e.target.value)}
                      placeholder="e.g. File emailed to the SOC by the user; the original device and path are unknown" />
            <div className="field-hint">Only when the device or path can&rsquo;t be stated (at least 10 characters).</div>
          </div>
          <details>
            <summary style={{ cursor: 'pointer', fontSize: 13, color: 'var(--muted)' }}>More source details</summary>
            <div style={{ marginTop: 'var(--space-2)' }}>
              <div className="form-row">
                <Text id={`${prefix}-vlabel`} label="Volume label" value={d.volume?.label} onChange={v => setD(['volume', 'label'], v)} max={128} />
                <Text id={`${prefix}-vserial`} label="Volume serial" value={d.volume?.serial} onChange={v => setD(['volume', 'serial'], v)} max={128} mono />
              </div>
              <div className="form-row">
                <Text id={`${prefix}-vfs`} label="File system" value={d.volume?.filesystem} onChange={v => setD(['volume', 'filesystem'], v)} max={64} />
                <Text id={`${prefix}-vpart`} label="Partition" value={d.volume?.partition} onChange={v => setD(['volume', 'partition'], v)} max={128} />
              </div>
              <div className="form-row">
                <Text id={`${prefix}-os`} label="Operating system" value={d.os} onChange={v => setD(['os'], v)} />
                <Text id={`${prefix}-asset`} label="Asset tag" value={d.asset_tag} onChange={v => setD(['asset_tag'], v)} max={128} mono />
              </div>

              <span className="field-label">Source times (MACB, as found)</span>
              <div className="field-hint" style={{ marginBottom: 'var(--space-2)' }}>
                Optional. Never adjusted by the clock offset. Any time needs its basis and the tool that read it.
              </div>
              {MACB.map(([k, label]) => (
                <div className="form-row" key={k}>
                  <div className="field">
                    <label className="field-label" htmlFor={`${prefix}-t${k}`}>{label} (UTC)</label>
                    <LocalDateTimePicker id={`${prefix}-t${k}`} value={d.times?.[k]?.utc || ''} clearable hint={false}
                                         onChange={v => setD(['times', k, 'utc'], v)} />
                  </div>
                  <Text id={`${prefix}-t${k}-rec`} label="As recorded" value={d.times?.[k]?.as_recorded}
                        onChange={v => setD(['times', k, 'as_recorded'], v)} max={128} mono />
                </div>
              ))}
              <div className="form-row">
                <Text id={`${prefix}-tbasis`} label="Times basis" value={d.times?.basis} onChange={v => setD(['times', 'basis'], v)}
                      placeholder="e.g. NTFS $STANDARD_INFORMATION" />
                <Text id={`${prefix}-treadby`} label="Read by (tool + version)" value={d.times?.read_by}
                      onChange={v => setD(['times', 'read_by'], v)} placeholder="e.g. MFTECmd 1.2.2.1" />
              </div>
              <Text id={`${prefix}-ttz`} label="Timezone basis" value={d.times?.tz_basis} onChange={v => setD(['times', 'tz_basis'], v)} max={128}
                    placeholder="e.g. UTC (NTFS), device local time (FAT)" />

              <div className="form-row">
                <Text id={`${prefix}-oid`} label="Owner id (SID / uid)" value={d.owner?.id} onChange={v => setD(['owner', 'id'], v)} mono />
                <Text id={`${prefix}-oname`} label="Owner name" value={d.owner?.name} onChange={v => setD(['owner', 'name'], v)} />
              </div>
              <div className="form-row">
                <Text id={`${prefix}-stream`} label="Alternate data stream" value={d.stream} onChange={v => setD(['stream'], v)} max={1024} mono />
                <Text id={`${prefix}-link`} label="Link target (which one was copied)" value={d.link_target}
                      onChange={v => setD(['link_target'], v)} max={32768} mono />
              </div>

              <span className="field-label">Cloud provider</span>
              <div className="form-row">
                <Text id={`${prefix}-prov`} label="Provider" value={d.provider?.provider} onChange={v => setD(['provider', 'provider'], v)} max={128}
                      placeholder="e.g. SharePoint, S3" />
                <Text id={`${prefix}-tenant`} label="Tenant / account" value={d.provider?.tenant_or_account}
                      onChange={v => setD(['provider', 'tenant_or_account'], v)} />
              </div>
              <div className="form-row">
                <Text id={`${prefix}-site`} label="Site / bucket" value={d.provider?.site_or_bucket} onChange={v => setD(['provider', 'site_or_bucket'], v)} max={1024} />
                <Text id={`${prefix}-item`} label="Item id" value={d.provider?.item_id} onChange={v => setD(['provider', 'item_id'], v)} max={1024} mono />
              </div>
              <div className="form-row">
                <Text id={`${prefix}-ver`} label="Version id" value={d.provider?.version_id} onChange={v => setD(['provider', 'version_id'], v)} mono />
                <Text id={`${prefix}-etag`} label="ETag" value={d.provider?.etag} onChange={v => setD(['provider', 'etag'], v)} mono />
              </div>
              <div className="form-row">
                <Text id={`${prefix}-export`} label="Export id" value={d.provider?.export_id} onChange={v => setD(['provider', 'export_id'], v)} mono />
                <Text id={`${prefix}-phalg`} label="Provider hash algorithm" value={d.provider?.provider_hash?.algorithm}
                      onChange={v => setD(['provider', 'provider_hash', 'algorithm'], v)} max={32} placeholder="e.g. MD5, QuickXorHash" />
              </div>
              <Text id={`${prefix}-phval`} label="Provider hash value (as given)" value={d.provider?.provider_hash?.value}
                    onChange={v => setD(['provider', 'provider_hash', 'value'], v)} mono />

              <span className="field-label">Mail</span>
              <div className="form-row">
                <Text id={`${prefix}-mbox`} label="Mailbox" value={d.mail?.mailbox} onChange={v => setD(['mail', 'mailbox'], v)} max={320} />
                <Text id={`${prefix}-mfolder`} label="Folder path" value={d.mail?.folder_path} onChange={v => setD(['mail', 'folder_path'], v)} max={2048} />
              </div>
              <div className="form-row">
                <Text id={`${prefix}-mid`} label="Message-ID" value={d.mail?.message_id} onChange={v => setD(['mail', 'message_id'], v)} max={998} mono />
                <Text id={`${prefix}-mitem`} label="Mail item id" value={d.mail?.item_id} onChange={v => setD(['mail', 'item_id'], v)} max={1024} mono />
              </div>
              <div className="field">
                <label className="field-label" htmlFor={`${prefix}-note`}>Note</label>
                <textarea id={`${prefix}-note`} className="input" rows={2} maxLength={4096} value={d.note || ''}
                          onChange={e => setD(['note'], e.target.value)} />
              </div>
            </div>
          </details>
        </>
      )}
    </fieldset>
  )
}

// Control characters are shown escaped (\xNN); everything else, spaces included, exactly as recorded.
const shown = (v) => String(v).replace(/[\u0000-\u001f\u007f]/g, c => `\\x${c.charCodeAt(0).toString(16).padStart(2, '0')}`)
const join = (...xs) => xs.filter(x => x !== null && x !== undefined && x !== '').join(' · ') || null

// Exhibit detail: the source record, read-only.
export function SourceRecord({ item }) {
  const d = item.source_details || {}
  const physical = item.kind === 'physical_item'
  const t = d.times || {}
  const rows = [
    [physical ? 'Device name' : 'Source system', item.source_system, true],
    ...(physical ? [] : [['Source device', join(item.make, item.model, item.serial && `S/N ${item.serial}`)]]),
    ['Source path', item.source_path, true],
    ['Path style', item.source_path_style && (STYLE_LABEL[item.source_path_style] || item.source_path_style)],
    ['Search form', item.source_path_norm !== item.source_path ? item.source_path_norm : null, true],
    ['Filename on source', d.filename_on_source, true],
    ['Unknown source', item.source_unknown_reason],
    ['Volume', join(d.volume?.label, d.volume?.serial, d.volume?.filesystem, d.volume?.partition)],
    ['Operating system', d.os],
    ['Asset tag', d.asset_tag, true],
    ...MACB.map(([k, label]) => [label, t[k] && join(t[k].utc && formatLocal(t[k].utc), t[k].as_recorded && `as recorded: ${t[k].as_recorded}`)]),
    ['Times basis', join(t.basis, t.tz_basis)],
    ['Times read by', join(t.read_by, t.read_at && formatLocal(t.read_at))],
    ['Owner', join(d.owner?.name, d.owner?.id)],
    ['Stream', d.stream, true],
    ['Link target', d.link_target, true],
    ['Cloud provider', join(d.provider?.provider, d.provider?.tenant_or_account, d.provider?.site_or_bucket)],
    ['Provider ids', join(d.provider?.item_id && `item ${d.provider.item_id}`, d.provider?.version_id && `version ${d.provider.version_id}`,
                          d.provider?.etag && `ETag ${d.provider.etag}`, d.provider?.export_id && `export ${d.provider.export_id}`), true],
    ['Provider hash', d.provider?.provider_hash && join(d.provider.provider_hash.algorithm, d.provider.provider_hash.value), true],
    ['Mail', join(d.mail?.mailbox, d.mail?.folder_path)],
    ['Mail ids', join(d.mail?.message_id, d.mail?.item_id), true],
    ['Namespace', d.namespace, true],
    ['Raw path (base64)', d.path_raw_b64, true],
    ['Note', d.note],
  ].filter(([, v]) => v !== null && v !== undefined && v !== '')

  return (
    <section data-testid="ev-source-record">
      <h3 className="panel-h" style={{ marginTop: 'var(--space-4)' }}>
        Source{' '}
        <span style={{ fontWeight: 400, color: 'var(--muted)', fontSize: 12 }}>· ISO 27037 §5.4.2, §6.6, §7.1.3.4</span>
      </h3>
      {rows.length === 0 ? (
        <div style={{ color: 'var(--muted)', fontSize: 13 }}>No source location recorded.</div>
      ) : (
        <dl className="kv">
          {rows.map(([k, v, mono]) => (
            <Fragment key={k}><dt>{k}</dt><dd style={mono ? { ...MONO, fontSize: 12, whiteSpace: 'pre-wrap', wordBreak: 'break-all' } : { whiteSpace: 'pre-wrap' }}>{shown(v)}</dd></Fragment>
          ))}
        </dl>
      )}
    </section>
  )
}
