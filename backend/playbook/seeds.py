"""Seeded playbook templates.

System templates inserted on startup if missing (idempotent by `key`). The framework
baseline (per CLAUDE.md) plus common incident-type scaffolds:
  - nist_800_61_r3   — NIST SP 800-61 Rev. 3 standard handling
  - cisa_fed_ir      — CISA Federal Government Cybersecurity IR Playbook
  - cisa_vuln_resp   — CISA Vulnerability Response Playbook
  - incident-type scaffolds: ransomware, credential stuffing, phishing, data egress,
    OAuth abuse, insider exfiltration, DDoS, BEC, network intrusion, malware infection,
    data-breach notification (GDPR), cloud compromise

The task content is aligned to the public guidance from those frameworks but
is not a byte-perfect reproduction. Treat as starting scaffolds — operators
edit/add per-incident.

Phase values follow the 800-61 R3 schema vocabulary already used elsewhere:
  preparation / detection_and_analysis /
  containment_eradication_recovery / post_incident
"""
from __future__ import annotations

import uuid
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from models import PlaybookTemplate

# ─── NIST SP 800-61 R3 Standard ──────────────────────────────────────────────

NIST_800_61_R3 = {
    "key":      "nist_800_61_r3",
    "category": "IR Framework",
    "name": "NIST SP 800-61 R3 — Standard incident handling",
    "description": (
        "Baseline incident-handling tasks aligned to NIST SP 800-61 Rev. 3, "
        "covering the four-phase lifecycle. Use as the default starting scaffold."
    ),
    "tasks": [
        # Preparation
        {"phase": "preparation",                       "order": 10, "title": "Maintain IR policy + procedures",
         "description": "Confirm IR policy is current; procedures reflect today's tools + org structure."},
        {"phase": "preparation",                       "order": 20, "title": "Confirm IR team roster + on-call",
         "description": "Verify roster, on-call schedule, deputies and escalation chain are current."},
        {"phase": "preparation",                       "order": 30, "title": "Verify access to IR tooling",
         "description": "Forensics workstations, EDR consoles, log search, ticketing — all reachable with current creds."},
        {"phase": "preparation",                       "order": 40, "title": "Confirm out-of-band comms channel",
         "description": "Establish channel that doesn't depend on the impacted environment (Signal, separate Slack workspace, phones)."},
        {"phase": "preparation",                       "order": 50, "title": "Validate contact lists",
         "description": "Internal stakeholders, vendors, legal counsel, law enforcement, regulators, CSIRT partners."},
        {"phase": "preparation",                       "order": 60, "title": "Confirm evidence handling SOP",
         "description": "Chain-of-custody process + storage location accessible to the responder."},

        # Detection & Analysis
        {"phase": "detection_and_analysis",            "order": 10, "title": "Record initial detection signal",
         "description": "Source (alert / report), timestamp, observer identity, original artefacts."},
        {"phase": "detection_and_analysis",            "order": 20, "title": "Assign Incident Commander",
         "description": "Single accountable IC named; deputies identified."},
        {"phase": "detection_and_analysis",            "order": 30, "title": "Determine severity",
         "description": "Apply internal severity rubric; capture NCISS mapping for federal/regulator reporting."},
        {"phase": "detection_and_analysis",            "order": 40, "title": "Identify affected systems + scope",
         "description": "Hosts, users, services, networks. Document initial scope estimate + how it was determined."},
        {"phase": "detection_and_analysis",            "order": 50, "title": "Collect volatile evidence",
         "description": "Memory, running processes, network connections — before containment alters state."},
        {"phase": "detection_and_analysis",            "order": 60, "title": "Preliminary impact assessment",
         "description": "Confidentiality / integrity / availability impact; data classification of affected assets."},
        {"phase": "detection_and_analysis",            "order": 70, "title": "Notify required stakeholders",
         "description": "Per notification matrix: leadership, business owners, legal, comms. Document who + when."},

        # Containment, Eradication & Recovery
        {"phase": "containment_eradication_recovery",  "order": 10, "title": "Implement short-term containment",
         "description": "Isolate hosts, block IOCs at perimeter, disable compromised accounts. Reversible actions."},
        {"phase": "containment_eradication_recovery",  "order": 20, "title": "Acquire forensic copies before eradication",
         "description": "Image disks / capture memory of in-scope systems prior to destructive eradication steps."},
        {"phase": "containment_eradication_recovery",  "order": 30, "title": "Implement long-term containment",
         "description": "Credential rotation, patching, configuration changes, expanded monitoring."},
        {"phase": "containment_eradication_recovery",  "order": 40, "title": "Identify root cause",
         "description": "Initial access vector, exploitation technique, persistence + privilege-escalation path."},
        {"phase": "containment_eradication_recovery",  "order": 50, "title": "Eradicate",
         "description": "Remove malware, close exploited vulnerability, revoke abused privileges."},
        {"phase": "containment_eradication_recovery",  "order": 60, "title": "Verify eradication",
         "description": "Re-scan, monitor logs for re-occurrence, validate IoC absence across the estate."},
        {"phase": "containment_eradication_recovery",  "order": 70, "title": "Restore operations",
         "description": "Re-image / restore from known-good backups; bring systems back to production in a staged fashion."},
        {"phase": "containment_eradication_recovery",  "order": 80, "title": "Heightened monitoring window",
         "description": "Run elevated monitoring for a documented period after recovery to catch re-entry."},

        # Post-Incident Activity
        {"phase": "post_incident",                     "order": 10, "title": "Hold lessons-learned meeting",
         "description": "Within agreed SLA after incident closure; cover what worked, what didn't, what to change."},
        {"phase": "post_incident",                     "order": 20, "title": "Update detection rules + IOCs",
         "description": "Push new IOCs / hunt queries / detection rules derived from this incident into security tooling."},
        {"phase": "post_incident",                     "order": 30, "title": "Update IR playbooks",
         "description": "Refine procedures based on lessons learned; record changes + owner."},
        {"phase": "post_incident",                     "order": 40, "title": "Retain evidence per legal requirements",
         "description": "Confirm retention period; chain-of-custody preserved; final hashes recorded."},
        {"phase": "post_incident",                     "order": 50, "title": "Generate executive summary",
         "description": "Short, non-technical: what happened, impact, what was done, residual risk."},
        {"phase": "post_incident",                     "order": 60, "title": "Generate full incident report",
         "description": "Citing 800-61 R3 phases; technical detail; CSF coverage; recommendations."},
    ],
}


# ─── CISA Federal Government IR Playbook ─────────────────────────────────────

CISA_FED_IR = {
    "key":      "cisa_fed_ir",
    "category": "Federal IR",
    "name": "CISA Federal Government Cybersecurity Incident Response",
    "description": (
        "Tasks aligned to the CISA Federal Government Cybersecurity Incident and "
        "Vulnerability Response Playbook (Nov 2021). Federal-agency specific items "
        "(US-CERT/CISA reporting, OMB Major Incident criteria) are included; civilian "
        "teams can mark those skipped."
    ),
    "tasks": [
        # Preparation
        {"phase": "preparation",                       "order": 10, "title": "Designate IR team + leadership",
         "description": "Agency CIO/CISO sign-off; deputised IC; deputies; legal advisor identified."},
        {"phase": "preparation",                       "order": 20, "title": "Confirm CISA / US-CERT reporting procedure",
         "description": "Verify the agency's CISA reporting workflow is current + accessible."},
        {"phase": "preparation",                       "order": 30, "title": "Document agency IR roles + authorities",
         "description": "Which roles can authorise containment, eradication, communication; recorded in IR plan."},
        {"phase": "preparation",                       "order": 40, "title": "Maintain Memoranda of Agreement with partners",
         "description": "MOUs / MOAs with response partners (CISA, FBI, contracted IR firm) — confirm current."},

        # Detection & Analysis
        {"phase": "detection_and_analysis",            "order": 10, "title": "Validate incident vs. event",
         "description": "Confirm signal is a confirmed incident (not a false positive); document the basis."},
        {"phase": "detection_and_analysis",            "order": 20, "title": "Document detection details",
         "description": "Source, time, observer, initial indicators. Single source of truth for the case."},
        {"phase": "detection_and_analysis",            "order": 30, "title": "Notify CISA per reporting requirements",
         "description": "Per agency's CISA reporting workflow. Record CISA case number if assigned."},
        {"phase": "detection_and_analysis",            "order": 40, "title": "Categorise per NCISS",
         "description": "Apply National Cyber Incident Scoring System; record score + rationale."},
        {"phase": "detection_and_analysis",            "order": 50, "title": "Determine PII / sensitive-data involvement",
         "description": "If PII involved: trigger privacy-officer notification + applicable breach-notification workflow."},
        {"phase": "detection_and_analysis",            "order": 60, "title": "Evaluate Major Incident criteria",
         "description": "Apply OMB Major Incident criteria; if met, begin 8-hour Congressional notification clock."},

        # Containment, Eradication & Recovery
        {"phase": "containment_eradication_recovery",  "order": 10, "title": "Coordinate containment strategy with CISA",
         "description": "Share IOCs / TTPs; align on containment timing to preserve CISA's broader visibility."},
        {"phase": "containment_eradication_recovery",  "order": 20, "title": "Forensic acquisition before eradication",
         "description": "Acquire forensic copies (disk + memory) of in-scope systems. Chain of custody in place."},
        {"phase": "containment_eradication_recovery",  "order": 30, "title": "Implement containment with authority approval",
         "description": "Containment actions documented + authorised by the designated role per IR plan."},
        {"phase": "containment_eradication_recovery",  "order": 40, "title": "Implement eradication",
         "description": "Remove threat actor presence, close access vector, rotate credentials in scope."},
        {"phase": "containment_eradication_recovery",  "order": 50, "title": "Verify eradication via independent check",
         "description": "Validation by a party other than the eradicating responder (peer review or external)."},
        {"phase": "containment_eradication_recovery",  "order": 60, "title": "Restore operations",
         "description": "Phased restoration; confirm system integrity before traffic resumes."},
        {"phase": "containment_eradication_recovery",  "order": 70, "title": "Implement enhanced monitoring",
         "description": "Elevated logging + alerting on affected systems for a documented window after recovery."},

        # Post-Incident
        {"phase": "post_incident",                     "order": 10, "title": "Submit final report to CISA",
         "description": "Per agency reporting workflow; include actions taken + lessons learned."},
        {"phase": "post_incident",                     "order": 20, "title": "Coordinate with FBI if criminal",
         "description": "If criminal activity confirmed: liaise via established FBI Cyber field-office contact."},
        {"phase": "post_incident",                     "order": 30, "title": "Update OMB on Major Incident closure",
         "description": "Only if previously declared Major Incident; per OMB closure procedure."},
        {"phase": "post_incident",                     "order": 40, "title": "Hot-wash + lessons learned",
         "description": "Cross-team retrospective; capture process gaps + action items with owners."},
        {"phase": "post_incident",                     "order": 50, "title": "Update agency response procedures",
         "description": "Codify lessons learned into the agency's IR plan + supporting runbooks."},
    ],
}


# ─── CISA Vulnerability Response Playbook ────────────────────────────────────
# This playbook's native phases (Identification / Evaluation / Remediation /
# Reporting) are mapped onto the 800-61 R3 four-phase vocabulary so they sit
# inside the same incident-detail UI:
#   Identification → detection_and_analysis
#   Evaluation     → detection_and_analysis
#   Remediation    → containment_eradication_recovery
#   Reporting      → post_incident
# The original phase name is kept as the first word of each task title for
# clarity.

CISA_VULN_RESP = {
    "key":      "cisa_vuln_resp",
    "category": "Vulnerability",
    "name": "CISA Vulnerability Response Playbook",
    "description": (
        "Tasks aligned to the CISA Vulnerability Response Playbook. Use when "
        "the trigger is a discovered vulnerability rather than an active "
        "intrusion. Native phases (Identification / Evaluation / Remediation / "
        "Reporting) are mapped onto the 800-61 R3 four-phase model in the UI."
    ),
    "tasks": [
        # Preparation
        {"phase": "preparation",                       "order": 10, "title": "Vulnerability management process in place",
         "description": "Asset inventory + vuln scanning + patch management owners documented."},
        {"phase": "preparation",                       "order": 20, "title": "Subscribe to CISA KEV catalog updates",
         "description": "Known Exploited Vulnerabilities feed wired into the team's daily review."},

        # Identification + Evaluation → detection_and_analysis
        {"phase": "detection_and_analysis",            "order": 10, "title": "Identification: confirm CVE + advisory source",
         "description": "Capture CVE ID, advisory URL, CVSS v3.1 vector + score."},
        {"phase": "detection_and_analysis",            "order": 20, "title": "Identification: enumerate affected assets",
         "description": "Cross-reference advisory's affected products against the asset inventory."},
        {"phase": "detection_and_analysis",            "order": 30, "title": "Identification: check CISA KEV listing",
         "description": "If listed in Known Exploited Vulnerabilities, treat as priority + apply the KEV due date."},
        {"phase": "detection_and_analysis",            "order": 40, "title": "Evaluation: exploitability + exposure",
         "description": "Is it remotely exploitable, authenticated/unauthenticated, exposed to which networks."},
        {"phase": "detection_and_analysis",            "order": 50, "title": "Evaluation: business impact of remediation",
         "description": "Required outage window, dependency risks, rollback plan."},
        {"phase": "detection_and_analysis",            "order": 60, "title": "Evaluation: business impact of NOT remediating",
         "description": "Plausible attacker scenarios, value of assets at risk, compensating controls available."},

        # Remediation → containment_eradication_recovery
        {"phase": "containment_eradication_recovery",  "order": 10, "title": "Remediation: develop plan + change ticket",
         "description": "Approved change record; rollback plan; assigned owner."},
        {"phase": "containment_eradication_recovery",  "order": 20, "title": "Remediation: stage in non-prod",
         "description": "Test patch / config change in lower environment; capture any side-effects."},
        {"phase": "containment_eradication_recovery",  "order": 30, "title": "Remediation: apply in production",
         "description": "Within the scheduled window; per change record. Document any exceptions."},
        {"phase": "containment_eradication_recovery",  "order": 40, "title": "Remediation: verify",
         "description": "Re-scan affected assets to confirm vulnerability is no longer detected."},
        {"phase": "containment_eradication_recovery",  "order": 50, "title": "Remediation: residual-risk assessment",
         "description": "Any assets that could not be remediated — document compensating controls + accept-risk owner."},

        # Reporting + Notification → post_incident
        {"phase": "post_incident",                     "order": 10, "title": "Reporting: notify CISA if reportable",
         "description": "Per agency policy. Include CVE, scope, remediation status."},
        {"phase": "post_incident",                     "order": 20, "title": "Reporting: update POA&M",
         "description": "Plan of Action & Milestones updated with remediation evidence."},
        {"phase": "post_incident",                     "order": 30, "title": "Reporting: communicate to stakeholders",
         "description": "Closing summary to leadership + system owners; lessons learned recorded."},
    ],
}


# ─── Ransomware Containment ───────────────────────────────────────────────────

RANSOMWARE_CONTAINMENT = {
    "key":      "ransomware_containment",
    "category": "Malware",
    "name": "Ransomware Containment",
    "description": (
        "Isolate, snapshot, identify strain, notify legal, restore from clean backup. "
        "Covers network isolation, ransom demand assessment, decryptor research, and "
        "recovery sequencing with heightened monitoring."
    ),
    "tasks": [
        {"phase": "detection_and_analysis",           "order": 10, "title": "Confirm ransomware infection",
         "description": "Validate encrypted files, ransom note, and identify affected hosts. Confirm it is not a wiper."},
        {"phase": "detection_and_analysis",           "order": 20, "title": "Identify ransomware strain",
         "description": "Submit sample/note to ID Ransomware, Bleeping Computer forums, or vendor sandbox. Record family name and known decryptors."},
        {"phase": "detection_and_analysis",           "order": 30, "title": "Determine initial access vector",
         "description": "Review EDR, email gateway, VPN logs. Common vectors: phishing, RDP brute-force, vulnerable public-facing service."},
        {"phase": "detection_and_analysis",           "order": 40, "title": "Scope blast radius",
         "description": "Enumerate all affected hosts, shares, and cloud storage. Check for exfiltration indicators (data-theft ransomware)."},
        {"phase": "detection_and_analysis",           "order": 50, "title": "Notify legal and executive leadership",
         "description": "Brief General Counsel on potential regulatory reporting obligations (GDPR 72 h, HIPAA, state breach laws). Engage cyber insurer."},
        {"phase": "containment_eradication_recovery", "order": 10, "title": "Network-isolate affected systems",
         "description": "VLAN quarantine or firewall rule. Preserve connectivity for forensic collection but block lateral movement."},
        {"phase": "containment_eradication_recovery", "order": 20, "title": "Snapshot affected disks before eradication",
         "description": "Take forensic images or VM snapshots for evidence and potential future decryption. Chain of custody in place."},
        {"phase": "containment_eradication_recovery", "order": 30, "title": "Revoke and rotate all credentials in scope",
         "description": "Domain admin, service accounts, VPN, cloud IAM. Assume all credentials on affected hosts are compromised."},
        {"phase": "containment_eradication_recovery", "order": 40, "title": "Assess ransom demand — do not pay without approval",
         "description": "Escalate to leadership + legal before any payment consideration. Check OFAC sanctions list for threat-actor group."},
        {"phase": "containment_eradication_recovery", "order": 50, "title": "Restore from verified clean backups",
         "description": "Confirm backup integrity (hash check). Restore to clean, re-imaged hardware or fresh VMs. Stage restoration by priority."},
        {"phase": "containment_eradication_recovery", "order": 60, "title": "Patch the exploited vulnerability",
         "description": "Close the initial access vector before bringing systems online. Verify patch applied across the estate."},
        {"phase": "post_incident",                    "order": 10, "title": "Validate regulatory notification obligations",
         "description": "Determine if personal data was exfiltrated. File notifications within required windows."},
        {"phase": "post_incident",                    "order": 20, "title": "Update backup strategy and immutability controls",
         "description": "Ensure offline/immutable backups with tested restoration. Air-gap at least one backup tier."},
    ],
}


# ─── Credential Stuffing Response ─────────────────────────────────────────────

CREDENTIAL_STUFFING = {
    "key":      "credential_stuffing",
    "category": "Identity",
    "name": "Credential Stuffing Response",
    "description": (
        "Rate-limit, force MFA challenge, lock affected accounts, notify users. "
        "Covers velocity detection, account lockout, credential-breach cross-reference, "
        "and user notification cadence."
    ),
    "tasks": [
        {"phase": "detection_and_analysis",           "order": 10, "title": "Confirm credential stuffing vs. brute-force",
         "description": "Check for distributed source IPs, known breach-credential signatures in WAF/auth logs."},
        {"phase": "detection_and_analysis",           "order": 20, "title": "Identify affected accounts",
         "description": "Extract accounts with successful logins during the attack window. Cross-reference against HIBP or internal breach intelligence."},
        {"phase": "detection_and_analysis",           "order": 30, "title": "Assess account takeover (ATO) scope",
         "description": "For successfully authenticated sessions: review activity, data accessed, settings changed."},
        {"phase": "containment_eradication_recovery", "order": 10, "title": "Enable aggressive rate-limiting and CAPTCHA",
         "description": "Apply rate limits by IP and account. Enable CAPTCHA on login. Engage CDN/WAF provider if volumetric."},
        {"phase": "containment_eradication_recovery", "order": 20, "title": "Force MFA challenge on all users",
         "description": "Step-up authentication for all active sessions. Revoke sessions that cannot complete MFA."},
        {"phase": "containment_eradication_recovery", "order": 30, "title": "Lock confirmed-compromised accounts",
         "description": "Temporarily disable accounts with confirmed ATO. Log action for audit."},
        {"phase": "containment_eradication_recovery", "order": 40, "title": "Invalidate all active sessions for affected accounts",
         "description": "Force re-authentication. Revoke OAuth tokens and API keys issued to affected sessions."},
        {"phase": "containment_eradication_recovery", "order": 50, "title": "Notify affected users",
         "description": "Send user notification per privacy policy and legal requirements. Include password reset instructions and MFA enrolment link."},
        {"phase": "post_incident",                    "order": 10, "title": "Enrol users in MFA at scale",
         "description": "Use post-incident window to enforce MFA for all users, not just affected ones."},
        {"phase": "post_incident",                    "order": 20, "title": "Review and tune auth anomaly detection",
         "description": "Tighten velocity rules. Add breach-credential checking to login flow (HIBP API or equivalent)."},
    ],
}


# ─── Phishing Campaign Takedown ───────────────────────────────────────────────

PHISHING_TAKEDOWN = {
    "key":      "phishing_takedown",
    "category": "Email",
    "name": "Phishing Campaign Takedown",
    "description": (
        "Identify scope, pull messages, block sender, submit takedown to registrar. "
        "Covers internal message recall, domain abuse reporting, and user-awareness follow-up."
    ),
    "tasks": [
        {"phase": "detection_and_analysis",           "order": 10, "title": "Triage the reported phishing message",
         "description": "Examine headers, links, and attachments in a sandbox. Identify payload type (cred-harvesting, malware, BEC)."},
        {"phase": "detection_and_analysis",           "order": 20, "title": "Scope internal delivery",
         "description": "Query email gateway/SIEM for all recipients of matching sender/subject/attachment hash. Record count and timestamps."},
        {"phase": "detection_and_analysis",           "order": 30, "title": "Identify users who clicked or opened attachments",
         "description": "Correlate URL-click logs and attachment-open events. Treat as potentially compromised — escalate for investigation."},
        {"phase": "containment_eradication_recovery", "order": 10, "title": "Recall and purge phishing messages",
         "description": "Use email admin console (M365 purge, Google Vault) to delete messages from all inboxes."},
        {"phase": "containment_eradication_recovery", "order": 20, "title": "Block sender domain and IPs at mail gateway",
         "description": "Add to email blocklist. Submit domains to Google Safe Browsing, Microsoft SmartScreen, and your Secure Email Gateway."},
        {"phase": "containment_eradication_recovery", "order": 30, "title": "Submit phishing domain takedown request",
         "description": "Report to domain registrar abuse contact, hosting provider, and NCSC/CISA if state-nexus is suspected."},
        {"phase": "containment_eradication_recovery", "order": 40, "title": "Scan endpoints of users who engaged",
         "description": "Trigger EDR scan or manual investigation on hosts where users clicked. Collect forensic artefacts if malware found."},
        {"phase": "containment_eradication_recovery", "order": 50, "title": "Reset credentials for engaging users",
         "description": "Force password reset and MFA re-enrolment for any user who submitted credentials to the phishing page."},
        {"phase": "post_incident",                    "order": 10, "title": "Send internal awareness communication",
         "description": "Brief all-staff on the campaign characteristics without causing alarm. Reinforce reporting channel."},
        {"phase": "post_incident",                    "order": 20, "title": "Update email filtering rules and threat intel",
         "description": "Feed IOCs (domains, IPs, subject lines, attachment hashes) into mail gateway and SIEM rules."},
    ],
}


# ─── Anomalous Data Egress ────────────────────────────────────────────────────

ANOMALOUS_DATA_EGRESS = {
    "key":      "anomalous_data_egress",
    "category": "Data Loss",
    "name": "Anomalous Data Egress",
    "description": (
        "Quarantine role, snapshot bucket, correlate DLP, engage Legal/Privacy. "
        "Covers data classification, exfiltration path identification, cloud storage hardening, "
        "and regulatory breach notification assessment."
    ),
    "tasks": [
        {"phase": "detection_and_analysis",           "order": 10, "title": "Confirm and classify the data involved",
         "description": "Identify data categories (PII, PHI, IP, financial). Determine classification level and regulatory regime."},
        {"phase": "detection_and_analysis",           "order": 20, "title": "Trace the exfiltration path",
         "description": "Review DLP alerts, CASB logs, network egress logs. Identify destination (personal cloud, external email, USB, C2)."},
        {"phase": "detection_and_analysis",           "order": 30, "title": "Quantify volume and recency",
         "description": "Estimate bytes/records exfiltrated and timeframe. Critical for regulatory notification threshold assessment."},
        {"phase": "detection_and_analysis",           "order": 40, "title": "Engage Legal and Privacy Officer immediately",
         "description": "Brief in-house counsel and DPO/Privacy Officer. Do not delay — regulatory clocks (GDPR 72 h) may already be running."},
        {"phase": "containment_eradication_recovery", "order": 10, "title": "Revoke the exfiltrating account/role",
         "description": "Suspend the user or service account responsible. Preserve evidence before disabling."},
        {"phase": "containment_eradication_recovery", "order": 20, "title": "Snapshot or freeze affected storage",
         "description": "Cloud bucket versioning, S3 Object Lock, or filesystem snapshot. Prevent overwrite of evidence."},
        {"phase": "containment_eradication_recovery", "order": 30, "title": "Harden egress controls",
         "description": "Apply least-privilege on storage ACLs. Enable DLP policy enforcement. Block destination IP/domain at firewall."},
        {"phase": "containment_eradication_recovery", "order": 40, "title": "Correlate with insider-threat indicators",
         "description": "Review the user's recent access history, printing, cloud-sync activity, and HR status. Engage HR if insider is suspected."},
        {"phase": "post_incident",                    "order": 10, "title": "File regulatory notifications within deadlines",
         "description": "GDPR Art. 33 (72 h to SA), HIPAA (60 days), state breach laws. Document notification content and timestamp."},
        {"phase": "post_incident",                    "order": 20, "title": "Review DLP policy coverage and tuning",
         "description": "Assess whether existing DLP rules would have caught this earlier. Update keyword lists, file-type policies, and destinations."},
        {"phase": "post_incident",                    "order": 30, "title": "Implement data-access monitoring improvements",
         "description": "Enable UEBA/CASB alerts for bulk-download and abnormal access patterns. Review cloud-storage public-access settings."},
    ],
}


# ─── OAuth App Revocation ─────────────────────────────────────────────────────

OAUTH_APP_REVOCATION = {
    "key":      "oauth_app_revocation",
    "category": "Identity",
    "name": "OAuth App Revocation",
    "description": (
        "Identify grants, revoke tokens, block app, notify granting users. "
        "Covers consent-phishing detection, tenant-wide token revocation, "
        "and application allowlist enforcement."
    ),
    "tasks": [
        {"phase": "detection_and_analysis",           "order": 10, "title": "Identify the malicious OAuth application",
         "description": "Obtain app name, app ID, publisher, redirect URIs, and permission scopes from Entra ID / Google Workspace admin console."},
        {"phase": "detection_and_analysis",           "order": 20, "title": "Enumerate all users who granted consent",
         "description": "Pull consent grant report from IdP. Determine how many users are affected."},
        {"phase": "detection_and_analysis",           "order": 30, "title": "Review scopes requested",
         "description": "Assess what access was granted (mail.read, files.readwrite, etc.). Determine potential data exposure."},
        {"phase": "containment_eradication_recovery", "order": 10, "title": "Revoke all OAuth tokens for the malicious app",
         "description": "Use tenant admin tools to revoke all refresh and access tokens issued to the app. M365: Remove-AzureADOAuth2PermissionGrant."},
        {"phase": "containment_eradication_recovery", "order": 20, "title": "Block the application in the tenant",
         "description": "Disable the app registration or add to tenant blocklist. Prevent re-consent by any user."},
        {"phase": "containment_eradication_recovery", "order": 30, "title": "Notify all affected users",
         "description": "Explain what access was granted, what was revoked, and what actions users should take. Include MFA review guidance."},
        {"phase": "post_incident",                    "order": 10, "title": "Enforce OAuth app allowlisting",
         "description": "Set tenant policy to require admin approval for all third-party app consent. Review and approve legitimate apps."},
        {"phase": "post_incident",                    "order": 20, "title": "Audit all existing OAuth grants tenant-wide",
         "description": "Review all third-party app consents. Revoke excessive or unrecognised permissions. Document approved apps."},
    ],
}


# ─── Insider Data Exfiltration ────────────────────────────────────────────────

INSIDER_EXFILTRATION = {
    "key":      "insider_exfiltration",
    "category": "Insider",
    "name": "Insider Data Exfiltration",
    "description": (
        "Preserve evidence, engage HR/Legal, scope access, revoke and document. "
        "Covers legal hold, privileged-access review, HR coordination, and "
        "post-departure access hygiene."
    ),
    "tasks": [
        {"phase": "detection_and_analysis",           "order": 10, "title": "Validate insider threat signal",
         "description": "Confirm the activity is anomalous: compare to baseline, rule out authorised data transfer, corroborate across at least two log sources."},
        {"phase": "detection_and_analysis",           "order": 20, "title": "Scope data accessed and exfiltrated",
         "description": "Identify what data was accessed, copied, or sent. Classify it. Determine business impact of exposure."},
        {"phase": "detection_and_analysis",           "order": 30, "title": "Engage Legal and HR immediately",
         "description": "Loop in General Counsel and HR before confronting the employee. Determine if law enforcement referral is warranted."},
        {"phase": "detection_and_analysis",           "order": 40, "title": "Place relevant systems under legal hold",
         "description": "Preserve email, DLP logs, EDR telemetry, CASB logs, and access logs. Do not alter or delete any records."},
        {"phase": "containment_eradication_recovery", "order": 10, "title": "Forensic collection from suspect devices",
         "description": "Covertly image suspect workstation and mobile (if corporate-managed) with chain of custody. Coordinate with Legal on admissibility."},
        {"phase": "containment_eradication_recovery", "order": 20, "title": "Revoke access per HR/Legal instruction",
         "description": "Revoke at the agreed time (usually simultaneous with HR action). Document exact revocation timestamps."},
        {"phase": "containment_eradication_recovery", "order": 30, "title": "Identify and recover exfiltrated assets",
         "description": "Pursue recovery via legal channel (cease-and-desist, litigation hold on personal cloud). Engage counsel."},
        {"phase": "containment_eradication_recovery", "order": 40, "title": "Review and restrict privileged access controls",
         "description": "Audit access rights held by the individual and similar-role peers. Implement least-privilege corrections."},
        {"phase": "post_incident",                    "order": 10, "title": "File required regulatory notifications",
         "description": "Determine breach notification obligations based on data type exfiltrated. File within applicable deadlines."},
        {"phase": "post_incident",                    "order": 20, "title": "Implement departure-procedure improvements",
         "description": "Strengthen off-boarding checklist: pre-revocation monitoring, device return, account cleanup within 24 h."},
        {"phase": "post_incident",                    "order": 30, "title": "Tune UEBA / insider-threat detection rules",
         "description": "Update behavioural analytics with indicators from this case. Review watch-list coverage for high-risk roles."},
    ],
}


# ─── DDoS Mitigation ─────────────────────────────────────────────────────────

DDOS_MITIGATION = {
    "key":      "ddos_mitigation",
    "category": "Network",
    "name": "DDoS Mitigation",
    "description": (
        "Engage edge protection, raise rate limits, monitor origin saturation. "
        "Covers traffic classification, upstream scrubbing activation, "
        "and communication with ISP and CDN providers."
    ),
    "tasks": [
        {"phase": "detection_and_analysis",           "order": 10, "title": "Confirm DDoS and classify attack type",
         "description": "Distinguish volumetric (UDP flood, SYN flood), protocol (BGP hijack), or application-layer (HTTP flood, slow loris) attack."},
        {"phase": "detection_and_analysis",           "order": 20, "title": "Identify attack sources and target IPs/ports",
         "description": "Extract top attacking source IPs, ASNs, and destination ports from netflow/firewall. Assess amplification vectors."},
        {"phase": "detection_and_analysis",           "order": 30, "title": "Assess origin infrastructure saturation",
         "description": "Monitor origin server CPU, bandwidth, connection tables. Determine if origin is being reached or if edge is absorbing."},
        {"phase": "containment_eradication_recovery", "order": 10, "title": "Activate upstream DDoS scrubbing",
         "description": "Engage CDN DDoS protection (Cloudflare Under Attack, Akamai Prolexic, AWS Shield Advanced). Redirect traffic via scrubbing centre."},
        {"phase": "containment_eradication_recovery", "order": 20, "title": "Implement targeted IP and geo-blocking",
         "description": "Block top attacking source ASNs/IPs at edge. Apply geo-blocking if attack is regionally concentrated and business impact is acceptable."},
        {"phase": "containment_eradication_recovery", "order": 30, "title": "Enable rate limiting and challenge pages",
         "description": "Apply aggressive rate limits on attack vectors. Enable JS/CAPTCHA challenges for suspicious clients at the CDN layer."},
        {"phase": "containment_eradication_recovery", "order": 40, "title": "Notify upstream ISP / transit provider",
         "description": "Contact ISP for upstream BGP blackhole or RTBH if volumetric. Provide attack traffic signature for filtering."},
        {"phase": "post_incident",                    "order": 10, "title": "Review and tune DDoS protection thresholds",
         "description": "Update auto-mitigation trigger thresholds based on observed attack profile. Document baselines."},
        {"phase": "post_incident",                    "order": 20, "title": "Assess origin hardening opportunities",
         "description": "Ensure origin IPs are not publicly exposed. Restrict direct-to-origin access to CDN IP ranges only."},
    ],
}


# ─── Business Email Compromise ────────────────────────────────────────────────

BEC_RESPONSE = {
    "key":      "bec_response",
    "category": "Email",
    "name": "Business Email Compromise (BEC) Response",
    "description": (
        "Scope fraudulent communications, freeze transfers, notify financial institutions. "
        "Covers account takeover investigation, financial recovery procedures, "
        "and impersonation domain takedown."
    ),
    "tasks": [
        {"phase": "detection_and_analysis",           "order": 10, "title": "Confirm BEC type",
         "description": "Determine variant: account takeover (ATO) via compromised inbox, or external domain spoofing/impersonation. Different containment paths."},
        {"phase": "detection_and_analysis",           "order": 20, "title": "Identify scope of fraudulent emails sent/received",
         "description": "Search email logs for the compromised account's outbound messages. Review for fraudulent payment requests, credential requests, or rule changes."},
        {"phase": "detection_and_analysis",           "order": 30, "title": "Determine if fraudulent transfers were executed",
         "description": "Engage Finance to identify any wire transfers, invoice payments, or payroll changes that resulted from the fraud."},
        {"phase": "containment_eradication_recovery", "order": 10, "title": "Secure the compromised email account",
         "description": "Reset credentials, revoke all sessions, enrol MFA, remove inbox rules created by attacker, review mail-forwarding rules."},
        {"phase": "containment_eradication_recovery", "order": 20, "title": "Contact financial institutions to freeze/recall transfers",
         "description": "Contact the sending bank immediately. File a FinCEN/IC3 report. Time is critical — transfers may be recallable within hours."},
        {"phase": "containment_eradication_recovery", "order": 30, "title": "Report to FBI IC3 and relevant authorities",
         "description": "File at ic3.gov with full transaction details. If large transfer: contact FBI field office directly. Notify cyber insurer."},
        {"phase": "containment_eradication_recovery", "order": 40, "title": "Take down impersonation domains",
         "description": "Report lookalike domains to registrar abuse, hosting provider, and submit to Google/Microsoft Safe Browsing."},
        {"phase": "post_incident",                    "order": 10, "title": "Implement wire-transfer verification controls",
         "description": "Require out-of-band (phone) verification for all payment changes and transfers over defined threshold."},
        {"phase": "post_incident",                    "order": 20, "title": "Enable DMARC/DKIM/SPF enforcement",
         "description": "Move DMARC to p=reject. Verify DKIM signing on all outbound mail. Review SPF record completeness."},
        {"phase": "post_incident",                    "order": 30, "title": "Conduct targeted awareness training",
         "description": "Brief Finance, HR, and executive teams on BEC indicators. Simulate BEC scenarios in phishing exercises."},
    ],
}


# ─── Network Intrusion / Targeted Attack (APT, hands-on-keyboard) ─────────────

NETWORK_INTRUSION = {
    "key":      "network_intrusion",
    "category": "Intrusion",
    "name": "Network Intrusion / Targeted Attack",
    "description": (
        "Foundational targeted-intrusion response: scope lateral movement, identify "
        "initial access, persistence and C2, contain without tipping off the actor, "
        "eradicate footholds, recover and hunt. Map adversary activity to MITRE ATT&CK."
    ),
    "tasks": [
        {"phase": "detection_and_analysis",           "order": 10, "title": "Triage the intrusion alert",
         "description": "Validate true-positive. Record source, first-observed time, observer, and original artefacts."},
        {"phase": "detection_and_analysis",           "order": 20, "title": "Assign IC + establish out-of-band comms",
         "description": "Single accountable Incident Commander. Use comms that don't depend on the possibly-monitored environment."},
        {"phase": "detection_and_analysis",           "order": 30, "title": "Identify the initial access vector",
         "description": "Phishing, exploit of a public-facing service, valid-account abuse, supply chain. Anchor the timeline at first access."},
        {"phase": "detection_and_analysis",           "order": 40, "title": "Map adversary activity to MITRE ATT&CK",
         "description": "Catalogue observed TTPs, tooling and C2 infrastructure. Record technique IDs against the incident."},
        {"phase": "detection_and_analysis",           "order": 50, "title": "Scope lateral movement + compromised accounts",
         "description": "Auth logs, EDR telemetry, beaconing. Enumerate every host and identity the actor touched — assume more than first seen."},
        {"phase": "detection_and_analysis",           "order": 60, "title": "Identify persistence + privilege escalation",
         "description": "Scheduled tasks, services, new/registry run keys, rogue accounts, implants, escalation path to domain/admin."},
        {"phase": "detection_and_analysis",           "order": 70, "title": "Preserve volatile + host evidence before containment",
         "description": "Memory, running processes, network connections, key hosts imaged — before containment alters state. Chain of custody."},
        {"phase": "detection_and_analysis",           "order": 80, "title": "Assess data access + exfiltration",
         "description": "Look for staging, archiving, and egress. Determine what data the actor could read or took (feeds the breach playbook)."},
        {"phase": "containment_eradication_recovery", "order": 10, "title": "Plan coordinated containment",
         "description": "Sequence actions to cut access everywhere at once — premature isolation tips off the actor, who burns persistence and digs in."},
        {"phase": "containment_eradication_recovery", "order": 20, "title": "Isolate compromised hosts + block C2",
         "description": "Network-quarantine in-scope hosts; block C2 infrastructure + IOCs at perimeter and EDR. Preserve forensic connectivity."},
        {"phase": "containment_eradication_recovery", "order": 30, "title": "Revoke + rotate all in-scope credentials",
         "description": "Assume identity-tier compromise. Rotate user/service/admin creds; for AD, reset KRBTGT twice. Invalidate sessions/tokens."},
        {"phase": "containment_eradication_recovery", "order": 40, "title": "Remove persistence + implants",
         "description": "Delete rogue accounts, scheduled tasks, services, backdoors. Validate against the persistence inventory from analysis."},
        {"phase": "containment_eradication_recovery", "order": 50, "title": "Close the initial access vector",
         "description": "Patch/disable the exploited service, fix the misconfiguration, harden the abused identity path."},
        {"phase": "containment_eradication_recovery", "order": 60, "title": "Verify eradication estate-wide",
         "description": "Hunt for re-entry, validate IOC absence across the estate, confirm no remaining actor-controlled access."},
        {"phase": "containment_eradication_recovery", "order": 70, "title": "Restore + rebuild as needed",
         "description": "Restore from known-good; rebuild compromised identity infrastructure (e.g. tier-0/AD) where trust can't be assured."},
        {"phase": "containment_eradication_recovery", "order": 80, "title": "Heightened monitoring window",
         "description": "Elevated detection for a documented period; targeted actors frequently attempt to return."},
        {"phase": "post_incident",                    "order": 10, "title": "Document full attack timeline + ATT&CK mapping",
         "description": "End-to-end narrative from initial access to eradication, with technique IDs and evidence references."},
        {"phase": "post_incident",                    "order": 20, "title": "Push IOCs + detections",
         "description": "Operationalise indicators, hunt queries and detection rules derived from the intrusion."},
        {"phase": "post_incident",                    "order": 30, "title": "Lessons learned + hardening backlog",
         "description": "MFA, segmentation, least privilege, EDR coverage gaps. Assign owners + due dates."},
    ],
}


# ─── Malware Infection (general, non-ransomware) — NIST SP 800-83 ─────────────

MALWARE_INFECTION = {
    "key":      "malware_infection",
    "category": "Malware",
    "name": "Malware Infection (general)",
    "description": (
        "Commodity or targeted malware that isn't ransomware — trojans, RATs, loaders, "
        "worms. Confirm + classify, contain spread, analyse a sample safely, eradicate, "
        "recover. Aligned to NIST SP 800-83."
    ),
    "tasks": [
        {"phase": "detection_and_analysis",           "order": 10, "title": "Confirm + classify the malware",
         "description": "Validate the detection. Classify: commodity vs targeted; trojan/RAT/loader/worm. Self-propagating? (drives urgency)."},
        {"phase": "detection_and_analysis",           "order": 20, "title": "Identify affected hosts + spread",
         "description": "Enumerate infected hosts; for worms, determine propagation method and rate. Estimate scope + how it was determined."},
        {"phase": "detection_and_analysis",           "order": 30, "title": "Capture a sample safely + submit to analysis",
         "description": "Acquire the sample with chain of custody; detonate in the air-gapped analysis worker / sandbox — never on production."},
        {"phase": "detection_and_analysis",           "order": 40, "title": "Determine delivery + initial access",
         "description": "Email attachment/link, drive-by, USB/removable media, software supply chain. Feeds the control gap to fix."},
        {"phase": "detection_and_analysis",           "order": 50, "title": "Identify C2 + persistence indicators",
         "description": "Beaconing destinations, dropped files, run keys, scheduled tasks, services. Build the IOC + cleanup list."},
        {"phase": "detection_and_analysis",           "order": 60, "title": "Preserve volatile evidence on affected hosts",
         "description": "Memory + process + connection capture before remediation alters state, for at least representative hosts."},
        {"phase": "containment_eradication_recovery", "order": 10, "title": "Isolate infected hosts",
         "description": "Network-quarantine to halt propagation and C2 while preserving forensic access."},
        {"phase": "containment_eradication_recovery", "order": 20, "title": "Block C2 + IOCs at perimeter and EDR",
         "description": "Sinkhole/block C2 domains+IPs; push file/registry IOCs to EDR for detect-and-block across the estate."},
        {"phase": "containment_eradication_recovery", "order": 30, "title": "Disable propagation vectors",
         "description": "Tighten share permissions, enforce USB policy, disable the abused delivery path until eradication completes."},
        {"phase": "containment_eradication_recovery", "order": 40, "title": "Eradicate malware + persistence",
         "description": "EDR remediation or re-image. Remove dropped files, persistence, and any secondary payloads it pulled."},
        {"phase": "containment_eradication_recovery", "order": 50, "title": "Rotate credentials exposed on infected hosts",
         "description": "Assume creds entered/cached on infected hosts are stolen — rotate them and invalidate sessions."},
        {"phase": "containment_eradication_recovery", "order": 60, "title": "Verify clean + restore",
         "description": "Re-scan, monitor for re-occurrence, restore/re-image affected hosts to a known-good state."},
        {"phase": "post_incident",                    "order": 10, "title": "Update AV/EDR signatures + detections",
         "description": "Add the family's IOCs and behaviours to detection tooling; confirm coverage."},
        {"phase": "post_incident",                    "order": 20, "title": "Close the delivery control gap",
         "description": "User-awareness, mail filtering, attachment sandboxing, or USB controls depending on the delivery vector."},
        {"phase": "post_incident",                    "order": 30, "title": "Lessons learned + report",
         "description": "What allowed infection + spread; remediation owners; full report."},
    ],
}


# ─── Data Breach — Privacy Notification (GDPR Art. 33/34 + regulatory) ────────

DATA_BREACH_NOTIFICATION = {
    "key":      "data_breach_notification",
    "category": "Privacy",
    "name": "Data Breach — Privacy Notification (GDPR/Regulatory)",
    "description": (
        "Drives the regulatory notification clock when personal data is breached. "
        "Assess risk to individuals, notify the supervisory authority within 72 h "
        "where required (GDPR Art. 33), notify data subjects on high risk (Art. 34), "
        "and maintain the breach register (Art. 33(5)). Layer over the technical incident."
    ),
    "tasks": [
        {"phase": "detection_and_analysis",           "order": 10, "title": "Confirm a personal-data breach",
         "description": "A breach of confidentiality, integrity OR availability of personal data — not only exfiltration. Loss/destruction counts."},
        {"phase": "detection_and_analysis",           "order": 20, "title": "Record time of awareness (starts the 72 h clock)",
         "description": "GDPR Art. 33: notification is due within 72 h of becoming aware. Record exactly who became aware and when."},
        {"phase": "detection_and_analysis",           "order": 30, "title": "Engage DPO + Legal + Privacy immediately",
         "description": "Bring in the Data Protection Officer and counsel at the start — they own the notifiability decision and wording."},
        {"phase": "detection_and_analysis",           "order": 40, "title": "Determine data categories, volume + data subjects",
         "description": "What personal data, how many records, how many individuals. Flag special-category data, children, or cross-border subjects."},
        {"phase": "detection_and_analysis",           "order": 50, "title": "Assess risk to individuals' rights + freedoms",
         "description": "Likelihood + severity of harm (identity theft, financial loss, discrimination). This drives Art. 33 and Art. 34 decisions."},
        {"phase": "detection_and_analysis",           "order": 60, "title": "Preserve breach evidence + the assessment",
         "description": "Document the facts, effects and remedial action — auditable. The assessment itself is part of the breach record."},
        {"phase": "containment_eradication_recovery", "order": 10, "title": "Contain ongoing exposure",
         "description": "Stop continued exposure of personal data — revoke access, pull exposed data, secure the store. Coordinate with the technical IR."},
        {"phase": "containment_eradication_recovery", "order": 20, "title": "Assess mitigating factors",
         "description": "Was the data encrypted at rest, pseudonymised, or recoverable? Effective mitigation can lower the risk and notifiability."},
        {"phase": "containment_eradication_recovery", "order": 30, "title": "Decide supervisory-authority notifiability (Art. 33)",
         "description": "Notify the DPA unless the breach is unlikely to result in risk to individuals. Document the decision either way."},
        {"phase": "containment_eradication_recovery", "order": 40, "title": "Notify the supervisory authority within 72 h",
         "description": "If required, file within 72 h (or note the reasoned delay). Include nature, categories, approximate numbers, likely consequences, measures."},
        {"phase": "containment_eradication_recovery", "order": 50, "title": "Decide + execute data-subject notification (Art. 34)",
         "description": "If high risk to individuals, notify affected data subjects without undue delay, in clear language, with advice + a contact point."},
        {"phase": "containment_eradication_recovery", "order": 60, "title": "Notify other obligated parties",
         "description": "Controllers (if you are a processor), joint controllers, cyber insurer, and any sector regulators with their own clocks."},
        {"phase": "post_incident",                    "order": 10, "title": "Record in the breach register (Art. 33(5))",
         "description": "Every breach is documented regardless of notifiability — facts, effects, remedial action — for the supervisory authority."},
        {"phase": "post_incident",                    "order": 20, "title": "Remediate root cause + reassess DPIA",
         "description": "Fix what allowed the breach; revisit the Data Protection Impact Assessment and update controls."},
        {"phase": "post_incident",                    "order": 30, "title": "Lessons learned + update breach procedure",
         "description": "Tune the notification workflow and contact lists; record changes + owner."},
    ],
}


# ─── Cloud Account / Infrastructure Compromise ────────────────────────────────

CLOUD_COMPROMISE = {
    "key":      "cloud_compromise",
    "category": "Cloud",
    "name": "Cloud Account / Infrastructure Compromise",
    "description": (
        "Compromise of cloud control-plane credentials or resources (AWS/Azure/GCP) — "
        "distinct from SaaS OAuth abuse. Revoke credentials, scope via cloud audit logs, "
        "remove persistence (rogue IAM, keys, functions), repair config + logging, recover."
    ),
    "tasks": [
        {"phase": "detection_and_analysis",           "order": 10, "title": "Confirm the cloud compromise",
         "description": "Anomalous API calls, new principals, logins from unusual regions/IPs, sudden billing/usage spike. Validate true-positive."},
        {"phase": "detection_and_analysis",           "order": 20, "title": "Identify compromised credentials / principals",
         "description": "Which access keys, IAM users/roles, or federated identities were used. Long-lived access keys are the usual culprit."},
        {"phase": "detection_and_analysis",           "order": 30, "title": "Review cloud audit logs for actor actions",
         "description": "CloudTrail / Azure Activity + Entra sign-in / GCP Audit Logs. Reconstruct what the actor did, from first to last action."},
        {"phase": "detection_and_analysis",           "order": 40, "title": "Scope affected resources + blast radius",
         "description": "Compute, storage buckets, databases, secrets/KMS, and IAM changes. Note cross-account/subscription reach."},
        {"phase": "detection_and_analysis",           "order": 50, "title": "Check for resource abuse",
         "description": "Cryptomining instances, mass instance spin-up, snapshot sharing, and data egress from buckets/blob storage."},
        {"phase": "detection_and_analysis",           "order": 60, "title": "Identify persistence",
         "description": "New IAM users/keys, backdoor roles, altered trust policies, rogue serverless functions, modified login/MFA settings."},
        {"phase": "containment_eradication_recovery", "order": 10, "title": "Revoke + rotate compromised credentials",
         "description": "Disable/rotate access keys and reset principals immediately; revoke active sessions/tokens. Prioritise privileged identities."},
        {"phase": "containment_eradication_recovery", "order": 20, "title": "Quarantine affected resources",
         "description": "Isolate (security-group lockdown) and snapshot affected resources for forensics before changing them."},
        {"phase": "containment_eradication_recovery", "order": 30, "title": "Remove attacker persistence",
         "description": "Delete rogue IAM principals/keys/roles, revert tampered trust policies, remove backdoor functions."},
        {"phase": "containment_eradication_recovery", "order": 40, "title": "Revert unauthorised config changes",
         "description": "Restore security groups/NSGs, IAM policies, and resource configs the actor altered."},
        {"phase": "containment_eradication_recovery", "order": 50, "title": "Repair audit logging if tampered",
         "description": "Re-enable CloudTrail/Activity/Audit logging or delivery the actor disabled; confirm log integrity going forward."},
        {"phase": "containment_eradication_recovery", "order": 60, "title": "Restore + terminate rogue resources",
         "description": "Rebuild from clean IaC/backups; terminate attacker-spun instances and abusive workloads."},
        {"phase": "containment_eradication_recovery", "order": 70, "title": "Verify + heightened monitoring",
         "description": "Confirm clean state via GuardDuty/Defender for Cloud/SCC; run elevated anomaly monitoring for a documented window."},
        {"phase": "post_incident",                    "order": 10, "title": "Enforce least privilege, MFA + kill long-lived keys",
         "description": "Remove long-lived access keys (prefer short-lived/federated), require MFA, and tighten over-permissioned roles."},
        {"phase": "post_incident",                    "order": 20, "title": "Enable org-wide guardrails",
         "description": "SCPs / Azure Policy / Org Policy, Config rules, conditional access, and centralised, tamper-resistant logging."},
        {"phase": "post_incident",                    "order": 30, "title": "Lessons learned + report",
         "description": "How the credentials/principal were obtained; remediation owners; full report."},
    ],
}


_SEEDS = (
    NIST_800_61_R3,
    CISA_FED_IR,
    CISA_VULN_RESP,
    RANSOMWARE_CONTAINMENT,
    CREDENTIAL_STUFFING,
    PHISHING_TAKEDOWN,
    ANOMALOUS_DATA_EGRESS,
    OAUTH_APP_REVOCATION,
    INSIDER_EXFILTRATION,
    DDOS_MITIGATION,
    BEC_RESPONSE,
    NETWORK_INTRUSION,
    MALWARE_INFECTION,
    DATA_BREACH_NOTIFICATION,
    CLOUD_COMPROMISE,
)


async def seed_playbook_templates(db: AsyncSession) -> None:
    """Idempotently insert the system templates.

    Keyed by `key` so re-runs don't duplicate. Existing system rows are left
    alone — if a seeded template needs to change, bump its `key` so a fresh
    row is added (lets ops audit which version applied).
    """
    existing = await db.execute(select(PlaybookTemplate.key))
    have = {row[0] for row in existing.all()}

    for spec in _SEEDS:
        if spec["key"] in have:
            continue
        db.add(PlaybookTemplate(
            id=uuid.uuid4(),
            key=spec["key"],
            name=spec["name"],
            description=spec["description"],
            category=spec.get("category", ""),
            is_system=True,
            tasks=spec["tasks"],
        ))
    await db.commit()
