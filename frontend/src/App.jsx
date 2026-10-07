import { BrowserRouter, Routes, Route, Navigate, useLocation, useOutletContext, useParams } from 'react-router-dom'
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
import Readiness from './pages/Readiness.jsx'
import Contacts from './pages/Contacts.jsx'
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
import IncidentReference from './pages/settings/IncidentReference.jsx'
import Admin from './pages/Admin.jsx'
import GlobalAuditLog from './pages/admin/GlobalAuditLog.jsx'
import AuditExports from './pages/admin/AuditExports.jsx'
import AdminStorage from './pages/admin/Storage.jsx'
import AdminSessions from './pages/admin/Sessions.jsx'
import AdminApiTokens from './pages/admin/ApiTokens.jsx'
import AdminAPIDocs from './pages/admin/APIDocs.jsx'
import Situation from './pages/incident/Situation.jsx'
import Recovery from './pages/incident/Recovery.jsx'
import Details from './pages/incident/Details.jsx'
import Playbook from './pages/incident/Playbook.jsx'
import Timeline from './pages/incident/Timeline.jsx'
import Entities from './pages/incident/Entities.jsx'
import Files from './pages/incident/Files.jsx'
import Notes from './pages/incident/Notes.jsx'
import Evidence from './pages/incident/Evidence.jsx'
import EvidenceItems from './pages/incident/evidence/Items.jsx'
import EvidenceCustodyLog from './pages/incident/evidence/CustodyLog.jsx'
import EvidenceAuditChain from './pages/incident/evidence/AuditChain.jsx'
import EvidenceRegister from './pages/incident/evidence/Register.jsx'
import EvidenceDisclosure from './pages/incident/evidence/Disclosure.jsx'
import EvidenceSOP from './pages/incident/evidence/SOP.jsx'
import Forensic from './pages/incident/Forensic.jsx'
import IOCs from './pages/incident/IOCs.jsx'
import Detections from './pages/incident/forensic/Detections.jsx'
import Attribution from './pages/incident/forensic/Attribution.jsx'
import LOLBins from './pages/incident/forensic/LOLBins.jsx'
import PCAP from './pages/incident/forensic/PCAP.jsx'
import EmailAnalyzer from './pages/incident/forensic/EmailAnalyzer.jsx'
import WebBrowserHistory from './pages/incident/forensic/WebBrowserHistory.jsx'
import Sandbox from './pages/incident/forensic/Sandbox.jsx'
import TimelineImport from './pages/incident/forensic/TimelineImport.jsx'
import DefenderPdfImport from './pages/incident/forensic/DefenderPdfImport.jsx'
import OSINTLookup from './pages/incident/forensic/OSINT.jsx'
import Ransomware from './pages/incident/forensic/Ransomware.jsx'
import Artifacts from './pages/incident/forensic/Artifacts.jsx'
import Collections from './pages/incident/forensic/Collections.jsx'
import Respond from './pages/incident/Respond.jsx'
import Comms from './pages/incident/Comms.jsx'
import Legal from './pages/incident/Legal.jsx'
import Mitre from './pages/incident/Mitre.jsx'
import AttackLayout from './pages/incident/AttackLayout.jsx'
import CommsComments from './pages/incident/comms/Comments.jsx'
import CommsOOB from './pages/incident/comms/OOB.jsx'
import CommsStakeholders from './pages/incident/comms/Stakeholders.jsx'
import CommsNotifications from './pages/incident/comms/Notifications.jsx'
import StakeholderMatrix from './pages/settings/StakeholderMatrix.jsx'
import PostIncident, { AnalyticsTab as PIAnalytics, LessonsTab as PILessons,
         CostsTab as PICosts, ReportsTab as PIReports, ClosureTab as PIClosure } from './pages/incident/PostIncident.jsx'
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

// Matches the backend's require_analyst (admin + analyst); viewers are sent away.
function RequireAnalyst({ children }) {
  const { user } = useAuth()
  if (user?.role !== 'admin' && user?.role !== 'analyst') return <Navigate to="/settings/account" replace />
  return children
}

// "/" — Dashboard for admins and analysts. Viewers can't read the Dashboard API (require_analyst),
// so they land on the incident list instead; this also covers login's default next='/'.
function HomeRoute() {
  const { user } = useAuth()
  if (user?.role === 'viewer') return <Navigate to="/incidents" replace />
  return <Dashboard />
}

// Incident sub-page guard: follows the capabilities of GET /api/incidents/{id}/access
// (loaded by IncidentDetail), so the server decides. The API enforces it as well.
function RequireIncidentCapability({ cap, children }) {
  const { access } = useOutletContext()
  if (!access) return <div className="panel"><div className="panel-empty">Loading…</div></div>
  if (!access.capabilities.includes(cap)) return <Navigate to="../details" replace />
  return children
}

// Redirect to another page of the same incident, keeping ?query and #hash. The target
// is built as an absolute path from :id, so RR v7's relative-path rules for nested and
// index routes cannot resolve it somewhere else. Used for moved tabs (old bookmarks).
function RedirectTo({ to }) {
  const { id } = useParams()
  const { search, hash } = useLocation()
  return <Navigate to={`/incidents/${encodeURIComponent(id)}/${to}${search}${hash}`} replace />
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
              <Route path="/"                  element={<HomeRoute />} />
              <Route path="/incidents"         element={<Incidents />} />
              <Route path="/playbooks"         element={<Playbooks />} />
              <Route path="/correlations"      element={<Correlations />} />
              <Route path="/threat-intel"     element={<RequireAnalyst><ThreatIntelHub /></RequireAnalyst>} />
              <Route path="/threat-actors"    element={<ThreatActors />} />
              <Route path="/mitre"            element={<MitreCoverage />} />
              <Route path="/incidents/:id" element={<IncidentDetail />}>
                <Route index                  element={<Navigate to="situation" replace />} />
                <Route path="situation"       element={<Situation />} />
                <Route path="details"         element={<Details />} />
                <Route path="playbook"        element={<Playbook />} />
                <Route path="timeline"        element={<Timeline />} />
                <Route path="iocs"            element={<IOCs />} />
                {/* K2 (R38): Entities + Affected systems are one Scope list; the old path redirects. */}
                <Route path="scope"           element={<Entities />} />
                <Route path="entities"        element={<RedirectTo to="scope" />} />
                <Route path="files"           element={<RedirectTo to="evidence/documents" />} />
                <Route path="notes"           element={<Notes />} />
                {/* K1 (R36): Evidence sub-tabs in lifecycle order; the old paths redirect. */}
                <Route path="evidence" element={<Evidence />}>
                  <Route index               element={<Navigate to="exhibits" replace />} />
                  <Route path="register"     element={<EvidenceRegister />} />
                  <Route path="exhibits"     element={<EvidenceItems />} />
                  <Route path="custody-log"  element={<EvidenceCustodyLog />} />
                  <Route path="integrity"    element={<EvidenceAuditChain />} />
                  <Route path="disclosure"   element={<EvidenceDisclosure />} />
                  <Route path="sop"          element={<EvidenceSOP />} />
                  <Route path="documents"    element={<Files />} />
                  <Route path="items"        element={<RedirectTo to="evidence/exhibits" />} />
                  <Route path="audit-chain"  element={<RedirectTo to="evidence/integrity" />} />
                  <Route path="export"       element={<RedirectTo to="evidence/disclosure" />} />
                </Route>
                <Route path="forensic" element={<Forensic />}>
                  <Route index               element={<Navigate to="collections" replace />} />
                  <Route path="detections"   element={<Detections />} />
                  <Route path="attribution"  element={<RedirectTo to="mitre/attribution" />} />
                  <Route path="lolbins"      element={<LOLBins />} />
                  <Route path="pcap"         element={<PCAP />} />
                  <Route path="email"        element={<EmailAnalyzer />} />
                  <Route path="web-browser"  element={<WebBrowserHistory />} />
                  <Route path="sandbox"          element={<Sandbox />} />
                  <Route path="timeline-import" element={<TimelineImport />} />
                  <Route path="defender-pdf" element={<DefenderPdfImport />} />
                  <Route path="osint"           element={<OSINTLookup />} />
                  <Route path="ransomware"      element={<Ransomware />} />
                  <Route path="artifacts"      element={<Artifacts />} />
                  <Route path="collections"    element={<Collections />} />
                </Route>
                {/* K2 (R38): the Respond board is three rail pages; /respond (and ?new_action=…) redirects. */}
                <Route path="containment"          element={<Respond key="containment" view="containment" />} />
                <Route path="eradication-recovery" element={<Respond key="eradication_recovery" view="eradication_recovery" />} />
                <Route path="decisions"            element={<Respond key="decisions" view="decisions" />} />
                <Route path="respond"              element={<RedirectTo to="containment" />} />
                <Route path="recovery"        element={<Recovery />} />
                <Route path="comms" element={<Comms />}>
                  <Route index                   element={<Navigate to="comments" replace />} />
                  <Route path="comments"         element={<CommsComments />} />
                  <Route path="oob"              element={<CommsOOB />} />
                  <Route path="stakeholders"     element={<CommsStakeholders />} />
                  <Route path="notifications"    element={<CommsNotifications />} />
                </Route>
                <Route path="legal"           element={<Legal />} />
                <Route path="mitre" element={<AttackLayout />}>
                  <Route index               element={<Mitre />} />
                  <Route path="attribution"  element={<Attribution />} />
                </Route>
                <Route path="post-incident" element={<PostIncident />}>
                  <Route index               element={<Navigate to="analytics" replace />} />
                  <Route path="analytics"    element={<PIAnalytics />} />
                  <Route path="lessons"      element={<PILessons />} />
                  {/* K4: Attack Chain is folded into the ATT&CK view (mitre, under Coverage) */}
                  <Route path="attack-chain" element={<RedirectTo to="mitre" />} />
                  <Route path="costs"        element={<PICosts />} />
                  <Route path="reports"      element={<PIReports />} />
                  <Route path="closure"      element={<PIClosure />} />
                </Route>
                <Route path="assignments"     element={<Assignments />} />
                <Route path="handoffs"        element={<IncidentHandoffs />} />
                <Route path="audit-log"       element={<RequireIncidentCapability cap="read_audit_log"><AuditLog /></RequireIncidentCapability>} />
              </Route>
              <Route path="/admin" element={<RequireAdmin><Admin /></RequireAdmin>}>
                <Route index             element={<Navigate to="audit-log" replace />} />
                <Route path="audit-log"     element={<GlobalAuditLog />} />
                <Route path="audit-exports" element={<AuditExports />} />
                <Route path="sessions"      element={<AdminSessions />} />
                <Route path="api-tokens"    element={<AdminApiTokens />} />
                <Route path="storage"    element={<AdminStorage />} />
                <Route path="backup"     element={<Backup />} />
                <Route path="api-docs"   element={<AdminAPIDocs />} />
              </Route>
              {/* Metrics left Admin (D5); old bookmarks redirect. Outside RequireAdmin so analysts get through. */}
              <Route path="/admin/metrics"     element={<Navigate to="/metrics" replace />} />
              <Route path="/metrics"           element={<RequireAnalyst><Metrics /></RequireAnalyst>} />
              <Route path="/readiness"         element={<RequireAnalyst><Readiness /></RequireAnalyst>} />
              <Route path="/contacts"          element={<RequireAnalyst><Contacts /></RequireAnalyst>} />
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
                <Route path="incident-reference" element={<RequireAdmin><IncidentReference /></RequireAdmin>} />
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
