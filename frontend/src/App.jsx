import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { ThemeProvider } from './hooks/useTheme.jsx'
import { AuthProvider, useAuth } from './hooks/useAuth.jsx'
import { TitleManager } from './hooks/useDocumentTitle.jsx'
import AppShell from './layouts/AppShell.jsx'
import Setup from './pages/Setup.jsx'
import Login from './pages/Login.jsx'
import TotpVerify from './pages/TotpVerify.jsx'
import AcknowledgeHandoff from './pages/public/AcknowledgeHandoff.jsx'
import TotpEnrol from './pages/TotpEnrol.jsx'
import Correlations from './pages/Correlations.jsx'
import ThreatIntelHub from './pages/ThreatIntelHub.jsx'
import ThreatActors from './pages/ThreatActors.jsx'
import Metrics from './pages/Metrics.jsx'
import Dashboard from './pages/Dashboard.jsx'
import Incidents from './pages/Incidents.jsx'
import Playbooks from './pages/Playbooks.jsx'
import IncidentDetail from './pages/IncidentDetail.jsx'
import Settings from './pages/Settings.jsx'
import Account from './pages/settings/Account.jsx'
import Teams from './pages/settings/Teams.jsx'
import OperationalRoles from './pages/settings/OperationalRoles.jsx'
import APIKeys from './pages/settings/APIKeys.jsx'
import ThreatIntel from './pages/settings/ThreatIntel.jsx'
import Integrations from './pages/settings/Integrations.jsx'
import Backup from './pages/settings/Backup.jsx'
import Users from './pages/settings/Users.jsx'
import ValidatedTools from './pages/settings/ValidatedTools.jsx'
import Admin from './pages/Admin.jsx'
import GlobalAuditLog from './pages/admin/GlobalAuditLog.jsx'
import AuditExports from './pages/admin/AuditExports.jsx'
import AdminStorage from './pages/admin/Storage.jsx'
import AdminSessions from './pages/admin/Sessions.jsx'
import AdminAPIDocs from './pages/admin/APIDocs.jsx'
import Details from './pages/incident/Details.jsx'
import Playbook from './pages/incident/Playbook.jsx'
import Timeline from './pages/incident/Timeline.jsx'
import Entities from './pages/incident/Entities.jsx'
import Evidence from './pages/incident/Evidence.jsx'
import EvidenceItems from './pages/incident/evidence/Items.jsx'
import EvidenceCustodyLog from './pages/incident/evidence/CustodyLog.jsx'
import EvidenceAuditChain from './pages/incident/evidence/AuditChain.jsx'
import EvidenceExport from './pages/incident/evidence/Export.jsx'
import EvidenceSOP from './pages/incident/evidence/SOP.jsx'
import Forensic from './pages/incident/Forensic.jsx'
import IOCs from './pages/incident/forensic/IOCs.jsx'
import Detections from './pages/incident/forensic/Detections.jsx'
import Attribution from './pages/incident/forensic/Attribution.jsx'
import LOLBins from './pages/incident/forensic/LOLBins.jsx'
import PCAP from './pages/incident/forensic/PCAP.jsx'
import EmailAnalyzer from './pages/incident/forensic/EmailAnalyzer.jsx'
import Sandbox from './pages/incident/forensic/Sandbox.jsx'
import TimelineImport from './pages/incident/forensic/TimelineImport.jsx'
import OSINTLookup from './pages/incident/forensic/OSINT.jsx'
import Artifacts from './pages/incident/forensic/Artifacts.jsx'
import Collections from './pages/incident/forensic/Collections.jsx'
import Respond from './pages/incident/Respond.jsx'
import Comms from './pages/incident/Comms.jsx'
import Legal from './pages/incident/Legal.jsx'
import Mitre from './pages/incident/Mitre.jsx'
import CommsComments from './pages/incident/comms/Comments.jsx'
import CommsOOB from './pages/incident/comms/OOB.jsx'
import CommsStakeholders from './pages/incident/comms/Stakeholders.jsx'
import StakeholderMatrix from './pages/settings/StakeholderMatrix.jsx'
import PostIncident from './pages/incident/PostIncident.jsx'
import AuditLog from './pages/incident/AuditLog.jsx'
import Assignments from './pages/incident/Assignments.jsx'
import IncidentHandoffs from './pages/incident/Handoffs.jsx'
import OnCall from './pages/OnCall.jsx'
import Handoffs from './pages/Handoffs.jsx'
import Roster from './pages/Roster.jsx'
import Help from './pages/Help.jsx'
import MitreCoverage from './pages/MitreCoverage.jsx'

function Loading() {
  return (
    <main className="auth-page">
      <div className="auth-shell">
        <div className="auth-card" style={{ textAlign: 'center', color: 'var(--muted)' }}>
          Loading…
        </div>
      </div>
    </main>
  )
}

function RequireAuth({ children }) {
  const { status, user, needsSetup } = useAuth()
  const loc = useLocation()
  if (status === 'loading') return <Loading />
  if (needsSetup)           return <Navigate to="/setup" replace />
  if (status !== 'user')    return <Navigate to={`/login?next=${encodeURIComponent(loc.pathname)}`} replace />
  if (user?.force_totp_enrol && loc.pathname !== '/totp/enrol') {
    return <Navigate to="/totp/enrol" replace />
  }
  return children
}

function RequireAdmin({ children }) {
  const { user } = useAuth()
  if (user?.role !== 'admin') return <Navigate to="/settings/account" replace />
  return children
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <BrowserRouter>
          <TitleManager />
          <Routes>
            {/* Pre-auth standalone routes (no shell) */}
            <Route path="/setup"      element={<Setup />} />
            <Route path="/login"      element={<Login />} />
            <Route path="/login/totp" element={<TotpVerify />} />
            <Route path="/totp/enrol" element={<RequireAuth><TotpEnrol /></RequireAuth>} />

            {/* Public LE-package acknowledgment — single-use token, no auth */}
            <Route path="/le-package-ack/:token" element={<AcknowledgeHandoff />} />

            {/* Authenticated routes — wrapped in the app shell */}
            <Route element={<RequireAuth><AppShell /></RequireAuth>}>
              <Route path="/"                  element={<Dashboard />} />
              <Route path="/incidents"         element={<Incidents />} />
              <Route path="/playbooks"         element={<Playbooks />} />
              <Route path="/correlations"      element={<Correlations />} />
              <Route path="/threat-intel"     element={<ThreatIntelHub />} />
              <Route path="/threat-actors"    element={<ThreatActors />} />
              <Route path="/mitre"            element={<MitreCoverage />} />
              <Route path="/incidents/:id" element={<IncidentDetail />}>
                <Route index                  element={<Navigate to="details" replace />} />
                <Route path="details"         element={<Details />} />
                <Route path="playbook"        element={<Playbook />} />
                <Route path="timeline"        element={<Timeline />} />
                <Route path="entities"        element={<Entities />} />
                <Route path="evidence" element={<Evidence />}>
                  <Route index               element={<Navigate to="items" replace />} />
                  <Route path="items"        element={<EvidenceItems />} />
                  <Route path="custody-log"  element={<EvidenceCustodyLog />} />
                  <Route path="audit-chain"  element={<EvidenceAuditChain />} />
                  <Route path="export"       element={<EvidenceExport />} />
                  <Route path="sop"          element={<EvidenceSOP />} />
                </Route>
                <Route path="forensic" element={<Forensic />}>
                  <Route index               element={<Navigate to="iocs" replace />} />
                  <Route path="iocs"         element={<IOCs />} />
                  <Route path="detections"   element={<Detections />} />
                  <Route path="attribution"  element={<Attribution />} />
                  <Route path="lolbins"      element={<LOLBins />} />
                  <Route path="pcap"         element={<PCAP />} />
                  <Route path="email"        element={<EmailAnalyzer />} />
                  <Route path="sandbox"          element={<Sandbox />} />
                  <Route path="timeline-import" element={<TimelineImport />} />
                  <Route path="osint"           element={<OSINTLookup />} />
                  <Route path="artifacts"      element={<Artifacts />} />
                  <Route path="collections"    element={<Collections />} />
                </Route>
                <Route path="respond"         element={<Respond />} />
                <Route path="comms" element={<Comms />}>
                  <Route index                   element={<Navigate to="comments" replace />} />
                  <Route path="comments"         element={<CommsComments />} />
                  <Route path="oob"              element={<CommsOOB />} />
                  <Route path="stakeholders"     element={<CommsStakeholders />} />
                </Route>
                <Route path="legal"           element={<Legal />} />
                <Route path="mitre"           element={<Mitre />} />
                <Route path="post-incident"   element={<PostIncident />} />
                <Route path="assignments"     element={<Assignments />} />
                <Route path="handoffs"        element={<IncidentHandoffs />} />
                <Route path="audit-log"       element={<RequireAdmin><AuditLog /></RequireAdmin>} />
              </Route>
              <Route path="/admin" element={<RequireAdmin><Admin /></RequireAdmin>}>
                <Route index             element={<Navigate to="audit-log" replace />} />
                <Route path="audit-log"     element={<GlobalAuditLog />} />
                <Route path="audit-exports" element={<AuditExports />} />
                <Route path="sessions"      element={<AdminSessions />} />
                <Route path="storage"    element={<AdminStorage />} />
                <Route path="metrics"    element={<Metrics />} />
                <Route path="backup"     element={<Backup />} />
                <Route path="api-docs"   element={<AdminAPIDocs />} />
              </Route>
              <Route path="/on-call"           element={<OnCall />} />
              <Route path="/handoffs"          element={<Handoffs />} />
              <Route path="/roster"            element={<Roster />} />
              <Route path="/help"              element={<Help />} />
              <Route path="/settings" element={<Settings />}>
                <Route index                    element={<Navigate to="account" replace />} />
                <Route path="account"           element={<Account />} />
                <Route path="teams"             element={<RequireAdmin><Teams /></RequireAdmin>} />
                <Route path="operational-roles" element={<RequireAdmin><OperationalRoles /></RequireAdmin>} />
                <Route path="stakeholder-matrix" element={<RequireAdmin><StakeholderMatrix /></RequireAdmin>} />
                <Route path="api-keys"          element={<RequireAdmin><APIKeys /></RequireAdmin>} />
                <Route path="threat-intel"      element={<RequireAdmin><ThreatIntel /></RequireAdmin>} />
                <Route path="integrations"      element={<RequireAdmin><Integrations /></RequireAdmin>} />
                <Route path="users"             element={<RequireAdmin><Users /></RequireAdmin>} />
                <Route path="validated-tools"   element={<RequireAdmin><ValidatedTools /></RequireAdmin>} />
              </Route>
            </Route>

            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </AuthProvider>
    </ThemeProvider>
  )
}
