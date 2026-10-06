import { useEffect, useRef, useState } from 'react'

// H3 — manual outbound lookups (OSINT, IOC enrichment, the email domain check) on a
// Dark Operation or TLP:RED incident. The API decides: it answers 409
// `outbound_confirmation_required` with a `reason`; this asks the analyst and resends with
// confirm_outbound=true (the API audits it as `outbound_manual_lookup`).
const WHY = {
  tlp_red:        'This incident is TLP:RED. Automatic outbound (Teams, Slack, alert email, automatic DNS checks) is suppressed.',
  dark_operation: 'Dark Operation is on. Automatic outbound (Teams, Slack, alert email, automatic DNS checks) is suppressed.',
}

export class OutboundCancelled extends Error {
  constructor() { super('Lookup cancelled — nothing was sent.'); this.cancelled = true }
}

// `withConfirm(call)`: runs `call(false)`; on 409 outbound_confirmation_required shows the
// dialog and, if confirmed, returns `call(true)`; if cancelled, throws OutboundCancelled.
export function useOutboundConfirm() {
  const [pending, setPending] = useState(null)   // { reason, resolve }

  const withConfirm = async (call) => {
    try {
      return await call(false)
    } catch (e) {
      if (e.code !== 'outbound_confirmation_required') throw e
      const ok = await new Promise(resolve => setPending({ reason: e.data?.reason, resolve }))
      if (!ok) throw new OutboundCancelled()
      return await call(true)
    }
  }

  const answer = (ok) => { pending?.resolve(ok); setPending(null) }
  const dialog = pending ? <OutboundConfirmModal reason={pending.reason} onAnswer={answer} /> : null
  return { withConfirm, dialog }
}

function OutboundConfirmModal({ reason, onAnswer }) {
  const cancelRef = useRef(null)
  const answerRef = useRef(onAnswer)
  answerRef.current = onAnswer
  useEffect(() => {
    cancelRef.current?.focus()
    const onKey = (e) => { if (e.key === 'Escape') answerRef.current(false) }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  return (
    <div className="modal-backdrop">
      <div className="modal" role="alertdialog" aria-modal="true"
           aria-labelledby="outbound-confirm-title" aria-describedby="outbound-confirm-body">
        <div className="modal-head">
          <h2 id="outbound-confirm-title">Send this lookup outside?</h2>
          <button type="button" className="modal-close" onClick={() => onAnswer(false)} aria-label="Close">×</button>
        </div>
        <div className="modal-body" id="outbound-confirm-body">
          <div className="alert error" role="note">
            <span className="alert-icon">!</span>
            <span>{WHY[reason] || WHY.tlp_red}</span>
          </div>
          <p style={{ color: 'var(--muted)', marginTop: 'var(--space-3)' }}>
            This lookup sends the indicator to outside services (OSINT providers or public DNS), where
            an attacker watching them may notice. Continue only if that is acceptable. The lookup is
            listed in the incident audit log as <code>outbound_manual_lookup</code>.
          </p>
        </div>
        <div className="modal-foot">
          <button type="button" className="btn ghost" ref={cancelRef} onClick={() => onAnswer(false)}>Cancel</button>
          <button type="button" className="btn primary" onClick={() => onAnswer(true)}>Send lookup</button>
        </div>
      </div>
    </div>
  )
}
