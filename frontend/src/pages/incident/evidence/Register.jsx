import { useEffect, useState } from 'react'
import { useNavigate, useOutletContext } from 'react-router-dom'
import { useAuth } from '../../../hooks/useAuth.jsx'
import { api } from '../../../api/client.js'
import AcquisitionWizard from './AcquisitionWizard.jsx'
import { AddEvidenceModal } from './Items.jsx'

// Evidence › Register (K1, R36): the first step of the evidence lifecycle. The acquisition wizard registers
// and seals an exhibit (ISO/IEC 27037); Quick add registers an unsealed draft to complete and seal later
// on Exhibits. Both land on Exhibits when saved.
export default function Register() {
  const { inc, bumpRail } = useOutletContext()
  const { user } = useAuth()
  const navigate = useNavigate()
  const isClosed = inc?.status === 'closed'
  const canWrite = !!user && user.role !== 'viewer'
  const [mode, setMode] = useState(null)          // null | 'wizard' | 'quick'
  const [users, setUsers] = useState([])
  const [entities, setEntities] = useState([])

  useEffect(() => {
    let cancelled = false
    api.listAssignableUsers().then(u => { if (!cancelled) setUsers(u || []) }).catch(() => {})
    api.listAllEntities(inc.id).then(all => { if (!cancelled) setEntities(all) }).catch(() => {})
    return () => { cancelled = true }
  }, [inc.id])

  const saved = () => { setMode(null); bumpRail?.(); navigate('../exhibits') }
  const blocked = !canWrite ? 'Viewers can’t register exhibits.' : isClosed ? 'Closed incidents are read-only.' : null

  return (
    <section className="panel" data-testid="ev-register">
      <div className="panel-toolbar">
        <h2 className="panel-h">Register an exhibit</h2>
      </div>
      {blocked && (
        <div className="alert info" role="status"><span className="alert-icon">i</span><span>{blocked}</span></div>
      )}
      <div className="register-options">
        <div className="register-option">
          <h3>Acquisition wizard</h3>
          <p>
            Court-grade registration (ISO/IEC 27037): lawful basis, device type, the collect-or-acquire
            decision, acquisition hashes and a witness. The exhibit is sealed when you finish.
          </p>
          <button type="button" className="btn primary" onClick={() => setMode('wizard')} disabled={!!blocked}>
            Start the wizard
          </button>
        </div>
        <div className="register-option">
          <h3>Quick add (unsealed draft)</h3>
          <p>
            Register a file or a physical item now and finish its acquisition record later with
            “Complete &amp; seal” on Exhibits. A draft is left out of disclosure packages unless you include drafts.
          </p>
          <button type="button" className="btn ghost" onClick={() => setMode('quick')} disabled={!!blocked}>
            Quick add
          </button>
        </div>
      </div>

      {mode === 'wizard' && (
        <AcquisitionWizard incidentId={inc.id} entities={entities} users={users}
                           onClose={() => setMode(null)} onSaved={saved} />
      )}
      {mode === 'quick' && (
        <AddEvidenceModal incidentId={inc.id} entities={entities} onClose={() => setMode(null)} onSaved={saved} />
      )}
    </section>
  )
}
