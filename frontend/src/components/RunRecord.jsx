import { formatLocal } from '../lib/datetime.js'
import { fmtOffset } from './ClockOffset.jsx'
import { DraftBadge } from './ExhibitPicker.jsx'

// G3 — the run record of an Email / PCAP / Browser history analysis: the exhibit it analysed (and
// whether that is still an unsealed draft), the SHA-256 of the bytes analysed, the analyser + version,
// how the exhibit was linked, who ran it when, and the clock offset applied. Analyses made before G3
// have none (they analysed an upload first and kept a quarantine copy).

const LINK = {
  registered:    'registered as a draft exhibit by the upload',
  sha256_match:  'the upload matched this exhibit’s SHA-256 (no second copy)',
  from_evidence: 'analysed from the registered exhibit (hash re-verified)',
}

export default function RunRecord({
  testid = 'run-record', filename, evidenceIdentifier, evidenceSealed, inputSha256, analyserName,
  analyserVersion, exhibitLink, at, by, clockOffsetSeconds, offsetNote,
}) {
  const recorded = !!analyserVersion
  return (
    <dl className="kv" data-testid={testid} style={{
      padding: 'var(--space-3)', background: 'var(--surface-2)', borderRadius: 'var(--radius)',
      marginBottom: 'var(--space-3)', fontSize: 13,
    }}>
      <dt>Input</dt>
      <dd style={{ display: 'flex', gap: 'var(--space-2)', alignItems: 'center', flexWrap: 'wrap', minWidth: 0 }}>
        {filename && <span style={{ fontFamily: 'var(--font-mono)', overflowWrap: 'anywhere' }}>{filename}</span>}
        {evidenceIdentifier && (
          <span className="pill" data-testid={`${testid}-exhibit`} style={{ fontSize: 11, fontFamily: 'var(--font-mono)' }}
                title="The registered exhibit this run analysed">⛁ {evidenceIdentifier}</span>
        )}
        {evidenceIdentifier && evidenceSealed === false && <DraftBadge />}
      </dd>
      {recorded ? (
        <>
          <dt>Exhibit link</dt>
          <dd data-testid={`${testid}-link`}>{LINK[exhibitLink] || exhibitLink || '—'}</dd>
          <dt>Input SHA-256</dt>
          <dd data-testid={`${testid}-sha256`} style={{ fontFamily: 'var(--font-mono)', fontSize: 11, wordBreak: 'break-all' }}>
            {inputSha256 || '—'}
          </dd>
          <dt>Analyser</dt>
          <dd data-testid={`${testid}-analyser`}>{analyserName || '—'} {analyserVersion}</dd>
        </>
      ) : (
        <>
          <dt>Run record</dt>
          <dd data-testid={`${testid}-legacy`} style={{ color: 'var(--muted)' }}>
            Not recorded — analysed before uploads were registered as exhibits.
          </dd>
        </>
      )}
      {at && (<><dt>Run</dt><dd>{formatLocal(at)}{by ? ` by ${by}` : ''}</dd></>)}
      {recorded && offsetNote !== false && (
        <>
          <dt>Clock offset</dt>
          <dd data-testid={`${testid}-offset`}>
            {clockOffsetSeconds !== null && clockOffsetSeconds !== undefined
              ? <>{fmtOffset(clockOffsetSeconds)} applied to times put on the Timeline</>
              : <span style={{ color: 'var(--muted)' }}>{offsetNote || 'none recorded on the exhibit'}</span>}
          </dd>
        </>
      )}
    </dl>
  )
}
