// Process-tree intelligence: rule-based detection that runs in the browser
// on each tree build. Two rule kinds:
//
//   • per-node rules         — image basename, full image path, cmdline pattern
//   • parent-child rules     — applied during forest walk; needs to see parent
//
// Each rule produces a `Finding` { name, severity, mitre, reason }. Findings
// are merged onto node.suspicious_reasons; node.suspicious becomes true if
// any finding fires.
//
// Severities:
//   high   — known-malicious tooling or unambiguous attacker tradecraft
//   medium — LOLBin abuse, suspicious download paths, anomalous parent chains
//   low    — informational; not currently used but reserved for future rules
//
// Adding a rule: drop another entry into one of the three arrays below. The
// engine is intentionally hardcoded — there's no UI/DB for rule editing yet.

// ── helpers ──────────────────────────────────────────────────────────────

function basename(p) {
  if (!p) return ''
  const i = Math.max(p.lastIndexOf('\\'), p.lastIndexOf('/'))
  return (i >= 0 ? p.slice(i + 1) : p).toLowerCase()
}

// Case-insensitive regex; we never use ^ / $ in rule patterns because the
// inputs (cmdline / image) are matched as substrings.
const r = (src) => new RegExp(src, 'i')

// ── per-node rules ───────────────────────────────────────────────────────
//
// Each: { test: (node) => bool, name, severity, mitre, reason }
//   node has: { image, cmdLine, user, hostname, eventTime, pid, ppid }

export const NODE_RULES = [
  // ── Credential dumpers ─────────────────────────────────────────────────
  {
    name: 'credential_dumper_image',
    severity: 'high',
    mitre: 'T1003',  // OS Credential Dumping
    test: (n) => /^(mimikatz|wce|pwdump|fgdump|gsecdump|procdump64?|hashdump)/.test(basename(n.image)),
    reason: 'Known credential-dumping binary by name',
  },
  {
    name: 'mimikatz_commands',
    severity: 'high',
    mitre: 'T1003.001',
    test: (n) => r('(sekurlsa::|lsadump::|kerberos::ptt|misc::memssp|privilege::debug)').test(n.cmdLine || ''),
    reason: 'Mimikatz command syntax in cmdline',
  },
  {
    name: 'procdump_lsass',
    severity: 'high',
    mitre: 'T1003.001',
    test: (n) => /procdump/.test(basename(n.image)) && /lsass/i.test(n.cmdLine || ''),
    reason: 'ProcDump targeting LSASS — credential extraction',
  },

  // ── Encoded / obfuscated PowerShell ────────────────────────────────────
  {
    name: 'powershell_encoded',
    severity: 'high',
    mitre: 'T1059.001',  // PowerShell
    test: (n) => /^(powershell|pwsh)\.exe$/.test(basename(n.image)) &&
                 r('(-enc(odedcommand)?|-e\\s)').test(n.cmdLine || ''),
    reason: 'PowerShell -EncodedCommand (Base64-wrapped payload)',
  },
  {
    name: 'powershell_download_cradle',
    severity: 'high',
    mitre: 'T1059.001',
    test: (n) => /^(powershell|pwsh)\.exe$/.test(basename(n.image)) &&
                 r('(downloadstring|downloadfile|invoke-(expression|webrequest)|iex\\s*\\(.*new-object.*net\\.webclient)').test(n.cmdLine || ''),
    reason: 'PowerShell download cradle (DownloadString / IEX / Invoke-WebRequest)',
  },
  {
    name: 'powershell_hidden_window',
    severity: 'medium',
    mitre: 'T1564.003',
    test: (n) => /^(powershell|pwsh)\.exe$/.test(basename(n.image)) &&
                 r('(-w(in(dow)?style)?\\s+hidden|-noni|-nop|-nopro(file)?)').test(n.cmdLine || ''),
    reason: 'PowerShell hidden / no-profile / non-interactive flags',
  },

  // ── LOLBin abuse ───────────────────────────────────────────────────────
  {
    name: 'certutil_url_decode',
    severity: 'high',
    mitre: 'T1140',
    test: (n) => /^certutil\.exe$/.test(basename(n.image)) &&
                 r('(-urlcache|-decode|-split|-encode)').test(n.cmdLine || ''),
    reason: 'certutil used as a downloader / decoder (LOLBin)',
  },
  {
    name: 'bitsadmin_transfer',
    severity: 'high',
    mitre: 'T1197',
    test: (n) => /^bitsadmin\.exe$/.test(basename(n.image)) &&
                 r('(/transfer|/download|/create|/addfile)').test(n.cmdLine || ''),
    reason: 'bitsadmin used to transfer files (LOLBin)',
  },
  {
    name: 'regsvr32_squiblydoo',
    severity: 'high',
    mitre: 'T1218.010',
    test: (n) => /^regsvr32\.exe$/.test(basename(n.image)) &&
                 r('(scrobj\\.dll|/i:https?://|/i:\\\\\\\\)').test(n.cmdLine || ''),
    reason: 'regsvr32 loading a remote/COM scriptlet (Squiblydoo)',
  },
  {
    name: 'rundll32_remote_or_script',
    severity: 'high',
    mitre: 'T1218.011',
    test: (n) => /^rundll32\.exe$/.test(basename(n.image)) &&
                 r('(javascript:|vbscript:|control_rundll|\\\\\\\\)').test(n.cmdLine || ''),
    reason: 'rundll32 invoking a script protocol or remote/Control_RunDLL',
  },
  {
    name: 'mshta_remote_script',
    severity: 'high',
    mitre: 'T1218.005',
    test: (n) => /^mshta\.exe$/.test(basename(n.image)) &&
                 r('(https?://|javascript:|vbscript:)').test(n.cmdLine || ''),
    reason: 'mshta executing a remote/script-protocol payload',
  },
  {
    name: 'wmic_remote_exec',
    severity: 'high',
    mitre: 'T1047',
    test: (n) => /^wmic\.exe$/.test(basename(n.image)) &&
                 r('(/node:|process\\s+call\\s+create)').test(n.cmdLine || ''),
    reason: 'wmic remote process creation (WMI lateral execution)',
  },

  // ── Lateral movement tooling ───────────────────────────────────────────
  {
    name: 'psexec_image',
    severity: 'medium',
    mitre: 'T1021.002',
    test: (n) => /^(psexec(64)?|paexec)\.exe$/.test(basename(n.image)),
    reason: 'PsExec / PaExec — Sysinternals lateral movement tool',
  },
  {
    name: 'psexec_service',
    severity: 'high',
    mitre: 'T1021.002',
    test: (n) => /psexesvc/i.test(n.cmdLine || '') ||
                 /psexesvc/i.test(n.image || ''),
    reason: 'PSEXESVC service binary running — incoming PsExec session',
  },

  // ── Exfil tooling ──────────────────────────────────────────────────────
  {
    name: 'rclone_exfil',
    severity: 'high',
    mitre: 'T1567.002',
    test: (n) => /^rclone\.exe$/.test(basename(n.image)) ||
                 (/^rclone$/.test(basename(n.image))),
    reason: 'rclone — common attacker exfil tool to cloud storage',
  },
  {
    name: 'mega_sync',
    severity: 'medium',
    mitre: 'T1567.002',
    test: (n) => /(megasync|megacmd|megaclient)/.test(basename(n.image)),
    reason: 'MEGA client — observed in ransomware exfil playbooks',
  },

  // ── Discovery commands ─────────────────────────────────────────────────
  {
    name: 'discovery_burst',
    severity: 'medium',
    mitre: 'T1087',
    test: (n) => /^(whoami|net|net1|nltest|tasklist|systeminfo|qwinsta|hostname|arp|route|ipconfig)\.exe$/.test(basename(n.image)) &&
                 r('(/all|/dclist|/domain_trusts|/trusted_domains|localgroup\\s+admin)').test(n.cmdLine || ''),
    reason: 'Discovery / recon command with elevated-info flags',
  },
  {
    name: 'user_add',
    severity: 'high',
    mitre: 'T1136.001',
    test: (n) => /^net1?\.exe$/.test(basename(n.image)) &&
                 r('(user\\s+\\S+\\s+\\S+\\s+/add|localgroup\\s+administrators\\s+\\S+\\s+/add)').test(n.cmdLine || ''),
    reason: 'Local account creation / admin group addition (persistence)',
  },

  // ── Suspicious execution paths ─────────────────────────────────────────
  {
    name: 'execution_from_user_writable',
    severity: 'medium',
    mitre: 'T1204',
    test: (n) => r('(\\\\appdata\\\\local\\\\temp\\\\|\\\\programdata\\\\(?!microsoft|chocolatey|package cache)|\\\\users\\\\public\\\\|\\\\temp\\\\)').test(n.image || ''),
    reason: 'Binary executing from a user-writable path',
  },

  // ── Linux post-compromise patterns ─────────────────────────────────────
  {
    name: 'linux_reverse_shell',
    severity: 'high',
    mitre: 'T1059.004',
    test: (n) => r('(bash\\s+-i\\s*>?&?\\s*/dev/tcp/|nc\\s+-e\\s|socat\\s+.+exec:|python.{0,30}socket\\.socket\\(.{0,200}connect)').test(n.cmdLine || ''),
    reason: 'Reverse-shell pattern (bash /dev/tcp, nc -e, socat exec:, python socket)',
  },
  {
    name: 'linux_curl_pipe_shell',
    severity: 'high',
    mitre: 'T1059.004',
    test: (n) => r('(curl|wget)\\s+[^|]{0,256}\\|\\s*(sh|bash|zsh)\\b').test(n.cmdLine || ''),
    reason: 'curl|sh pattern — direct remote-script execution',
  },
]

// ── parent-child rules ──────────────────────────────────────────────────
//
// Each: { test: (child, parent) => bool, name, severity, mitre, reason }
// Both child & parent are tree nodes (have .image, .cmdLine, etc.).

const OFFICE_PARENTS = /^(winword|excel|powerpnt|outlook|msaccess|mspub|onenote|visio)\.exe$/
const SCRIPT_SHELLS  = /^(powershell|pwsh|cmd|wscript|cscript|mshta|wmiprvse|rundll32|regsvr32|certutil|bitsadmin)\.exe$/

export const PARENT_CHILD_RULES = [
  {
    name: 'office_spawn_shell',
    severity: 'high',
    mitre: 'T1566.001',  // Spearphishing Attachment
    test: (c, p) => OFFICE_PARENTS.test(basename(p?.image)) &&
                    SCRIPT_SHELLS.test(basename(c.image)),
    reason: (c, p) => `Office app (${basename(p.image)}) spawned a script host (${basename(c.image)}) — macro initial access`,
  },
  {
    name: 'wmi_spawn_shell',
    severity: 'high',
    mitre: 'T1047',
    test: (c, p) => /^wmiprvse\.exe$/.test(basename(p?.image)) &&
                    /^(powershell|pwsh|cmd|wscript|cscript)\.exe$/.test(basename(c.image)),
    reason: () => 'WmiPrvSE spawned a shell — WMI-based execution / lateral movement',
  },
  {
    name: 'services_to_user_binary',
    severity: 'medium',
    mitre: 'T1543.003',
    test: (c, p) => {
      if (!/^services\.exe$/.test(basename(p?.image))) return false
      // Allow svchost children; flag anything else under services that doesn't
      // live under \Windows\.
      if (/^svchost\.exe$/.test(basename(c.image))) return false
      const img = (c.image || '').toLowerCase()
      return img && !img.includes('\\windows\\')
    },
    reason: (c) => `services.exe spawned a non-system binary (${basename(c.image)}) — possible service abuse`,
  },
  {
    name: 'powershell_chain',
    severity: 'medium',
    mitre: 'T1059.001',
    test: (c, p) => /^(powershell|pwsh)\.exe$/.test(basename(p?.image)) &&
                    /^(cmd|powershell|pwsh|wscript|cscript)\.exe$/.test(basename(c.image)),
    reason: () => 'PowerShell spawning another shell — chained execution',
  },
  {
    name: 'browser_spawn_shell',
    severity: 'medium',
    mitre: 'T1204.002',
    test: (c, p) => /^(chrome|firefox|msedge|iexplore|brave|opera)\.exe$/.test(basename(p?.image)) &&
                    /^(cmd|powershell|pwsh|wscript|cscript|mshta)\.exe$/.test(basename(c.image)),
    reason: (c, p) => `Browser (${basename(p.image)}) spawned a shell (${basename(c.image)}) — drive-by / browser exploit`,
  },
  {
    name: 'sshd_spawn_downloader',
    severity: 'medium',
    mitre: 'T1071.001',
    test: (c, p) => /sshd/.test(basename(p?.image)) &&
                    /^(curl|wget|fetch)$/.test(basename(c.image)),
    reason: () => 'sshd → curl/wget chain — possible post-compromise download',
  },
]

// ── Public API ──────────────────────────────────────────────────────────
//
// detectNode(node) — applies NODE_RULES. Returns merged
// { suspicious: bool, suspicious_reasons: Finding[], max_severity: string|null }.

const SEV_WEIGHT = { high: 3, medium: 2, low: 1 }

function maxSeverity(reasons) {
  let best = null
  for (const r of reasons) {
    if (!best || (SEV_WEIGHT[r.severity] || 0) > (SEV_WEIGHT[best] || 0)) {
      best = r.severity
    }
  }
  return best
}

export function detectNode(node) {
  const reasons = []
  for (const rule of NODE_RULES) {
    try {
      if (rule.test(node)) {
        reasons.push({
          name:     rule.name,
          severity: rule.severity,
          mitre:    rule.mitre || null,
          reason:   rule.reason,
        })
      }
    } catch { /* defensive — never let one bad rule break the tree */ }
  }
  return {
    suspicious:         reasons.length > 0,
    suspicious_reasons: reasons,
    max_severity:       maxSeverity(reasons),
  }
}

// detectForest(forest) — walks the forest and applies PARENT_CHILD_RULES.
// Mutates each child's findings in place. The caller should have already
// run detectNode on every node (i.e. via _extractProcess).

export function detectForest(forest) {
  const visit = (node, parent) => {
    if (parent) {
      for (const rule of PARENT_CHILD_RULES) {
        try {
          if (rule.test(node, parent)) {
            node.suspicious = true
            node.suspicious_reasons = node.suspicious_reasons || []
            node.suspicious_reasons.push({
              name:     rule.name,
              severity: rule.severity,
              mitre:    rule.mitre || null,
              reason:   typeof rule.reason === 'function' ? rule.reason(node, parent) : rule.reason,
            })
          }
        } catch { /* defensive */ }
      }
      node.max_severity = maxSeverity(node.suspicious_reasons || [])
    }
    for (const c of node.children) visit(c, node)
  }
  for (const root of forest) visit(root, null)
  return forest
}

// Severity → CSS variable (project palette). Used by the tree node to colour
// the ⚠ marker / row tint by severity.
export function severityColor(sev) {
  if (sev === 'high')   return 'var(--crit)'
  if (sev === 'medium') return 'var(--med)'
  if (sev === 'low')    return 'var(--low)'
  return 'var(--muted)'
}
