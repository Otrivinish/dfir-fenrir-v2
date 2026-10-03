// Predefined action templates for the Respond board.
// Grouped by category (containment / eradication / recovery)
// then by sub-category for display in the picker modal.
// Each template carries a targetHint shown as input placeholder.

// entityFilter / iocFilter: entity `type` / IOC `type` values offered in the
// Target picker. Entity types must match backend schemas.py EntityType; IOC
// types match IocType. null/absent = all types; [] = none. A template's own
// filter wins over its group's.
// Which templates set a containment state (isolated / disabled / blocked) is
// decided by the backend (respond/containment.py), not here. Those templates
// carry their own filter, a mirror of the backend's TEMPLATE_TARGET_TYPES
// (a link of another type is refused there: 422 target_type_mismatch), so the
// picker only offers targets the effect can apply to.
const HOST    = { entityFilter: ['host'],          iocFilter: [] }
const ACCOUNT = { entityFilter: ['user', 'email'], iocFilter: [] }

export const ACTION_TEMPLATES = {
  containment: [
    {
      group: 'Network',
      entityFilter: ['ip', 'domain', 'network_range', 'host'],
      iocFilter:    ['ip', 'domain', 'url', 'hash_md5', 'hash_sha1', 'hash_sha256'],
      items: [
        { id: 'isolate_host',    title: 'Isolate host from network',   targetHint: 'Hostname or IP address', ...HOST },
        { id: 'block_ip',        title: 'Block IP address',            targetHint: 'IP address',
          entityFilter: ['ip', 'network_range'], iocFilter: ['ip'] },
        { id: 'block_domain',    title: 'Block domain',                targetHint: 'Domain name',
          entityFilter: ['domain'], iocFilter: ['domain'] },
        { id: 'block_url',       title: 'Block URL',                   targetHint: 'URL',
          entityFilter: [], iocFilter: ['url'] },
        { id: 'block_hash',      title: 'Block file hash',             targetHint: 'MD5 / SHA-1 / SHA-256',
          entityFilter: [], iocFilter: ['hash_md5', 'hash_sha1', 'hash_sha256'] },
        { id: 'firewall_rule',   title: 'Apply firewall rule',         targetHint: 'Rule description / port / direction' },
      ],
    },
    {
      group: 'Identity',
      items: [
        { id: 'disable_account',  title: 'Disable account',            targetHint: 'Username or UPN', ...ACCOUNT },
        { id: 'reset_creds',      title: 'Reset credentials',          targetHint: 'Username or UPN', ...ACCOUNT },
        { id: 'revoke_sessions',  title: 'Revoke active sessions',     targetHint: 'Username or UPN', ...ACCOUNT },
        { id: 'revoke_mfa',       title: 'Revoke MFA tokens',          targetHint: 'Username or UPN', ...ACCOUNT },
        { id: 'revoke_tokens',    title: 'Revoke API / OAuth tokens',  targetHint: 'Application or service name', ...ACCOUNT },
      ],
    },
    {
      group: 'Endpoint',
      entityFilter: ['host', 'service', 'ip'],
      iocFilter:    ['ip', 'file_path'],
      items: [
        { id: 'take_offline',    title: 'Take system offline',         targetHint: 'Hostname', ...HOST },
        { id: 'kill_process',    title: 'Kill process',                targetHint: 'Process name or PID' },
        { id: 'quarantine_ep',   title: 'Quarantine endpoint (EDR)',   targetHint: 'Hostname', ...HOST },
        { id: 'patch_emergency', title: 'Apply emergency patch',       targetHint: 'System name / CVE ID' },
        { id: 'snapshot_memory', title: 'Capture memory snapshot',     targetHint: 'Hostname' },
      ],
    },
    {
      group: 'Email',
      entityFilter: ['email', 'domain'],
      iocFilter:    ['email', 'domain', 'url'],
      items: [
        { id: 'quarantine_email', title: 'Quarantine email(s)',        targetHint: 'Subject line or sender address' },
        { id: 'delete_rule',      title: 'Remove malicious inbox rule', targetHint: 'Rule name or mailbox' },
        { id: 'block_sender',     title: 'Block sender domain/address', targetHint: 'Sender address or domain',
          entityFilter: ['email', 'domain'], iocFilter: ['email', 'domain'] },
      ],
    },
  ],

  eradication: [
    {
      group: 'Malware removal',
      entityFilter: ['host', 'service'],
      iocFilter:    ['file_path', 'registry_key', 'hash_md5', 'hash_sha1', 'hash_sha256'],
      items: [
        { id: 'remove_malware',  title: 'Remove malware and attacker tools',  targetHint: 'Hostname(s) / tool name' },
        { id: 'delete_files',    title: 'Delete malicious files',             targetHint: 'File path(s) or hash' },
        { id: 'remove_persist',  title: 'Remove persistence mechanism',       targetHint: 'Type (registry / service / cron / etc.) + location' },
        { id: 'remove_backdoor', title: 'Remove backdoor / implant',          targetHint: 'Hostname / location' },
        { id: 'clean_artifacts', title: 'Clean attacker artifacts',           targetHint: 'Hostname / artifact type' },
      ],
    },
    {
      group: 'Systems',
      entityFilter: ['host', 'service', 'network_range'],
      iocFilter:    [],
      items: [
        { id: 'patch_vuln',      title: 'Patch exploited vulnerability',      targetHint: 'CVE ID / affected system(s)' },
        { id: 'rebuild_system',  title: 'Rebuild system from known-good baseline', targetHint: 'Hostname' },
        { id: 'reimage',         title: 'Re-image compromised host',           targetHint: 'Hostname' },
        { id: 'config_harden',   title: 'Harden configuration',               targetHint: 'System / service' },
      ],
    },
    {
      group: 'Accounts',
      entityFilter: ['user', 'email'],
      iocFilter:    ['email'],
      items: [
        { id: 'reset_all_creds', title: 'Reset all compromised credentials',  targetHint: 'Account(s) or scope' },
        { id: 'revoke_certs',    title: 'Revoke and reissue certificates',     targetHint: 'Certificate / CA' },
        { id: 'audit_privs',     title: 'Audit and trim privilege assignments', targetHint: 'Account or group' },
      ],
    },
  ],

  recovery: [
    {
      group: 'Restore',
      entityFilter: ['host', 'service', 'network_range'],
      iocFilter:    [],
      items: [
        { id: 'restore_backup',  title: 'Restore from clean backup',          targetHint: 'System / data set / backup date' },
        { id: 'restore_data',    title: 'Restore data from backup',           targetHint: 'Data store / path' },
        { id: 'restore_network', title: 'Restore network connectivity',       targetHint: 'System or network segment' },
        { id: 'return_prod',     title: 'Return host to production',          targetHint: 'Hostname' },
        { id: 'reenable_service', title: 'Re-enable service',                 targetHint: 'Service name' },
      ],
    },
    {
      group: 'Validation',
      items: [
        { id: 'validate_integrity', title: 'Validate system integrity',       targetHint: 'Hostname / baseline hash' },
        { id: 'verify_recovery',    title: 'Verify recovery completeness',    targetHint: 'System / checklist' },
        { id: 'monitor_reinfect',   title: 'Monitor for reinfection',         targetHint: 'IOC(s) or system to watch' },
        { id: 'pen_test_limited',   title: 'Run limited penetration test',    targetHint: 'Scope' },
      ],
    },
    {
      group: 'Hardening',
      items: [
        { id: 'update_detections',  title: 'Update detection rules / signatures', targetHint: 'Ruleset / SIEM / EDR platform' },
        { id: 'enable_logging',     title: 'Enable / enhance logging',            targetHint: 'System or log category' },
        { id: 'mfa_enforce',        title: 'Enforce MFA on affected accounts',    targetHint: 'Account(s) or group' },
        { id: 'change_passwords',   title: 'Change all privileged passwords',     targetHint: 'Scope / tier' },
      ],
    },
  ],
}

// Flat lookup: template id → { title, targetHint, category, entityFilter, iocFilter }
export const TEMPLATE_BY_ID = {}
for (const [category, groups] of Object.entries(ACTION_TEMPLATES)) {
  for (const g of groups) {
    for (const item of g.items) {
      TEMPLATE_BY_ID[item.id] = { ...item, category,
        entityFilter: item.entityFilter ?? g.entityFilter ?? null, iocFilter: item.iocFilter ?? g.iocFilter ?? null }
    }
  }
}
