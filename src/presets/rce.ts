import type { WafRule } from '@/domain/rules';

/** High-signal Unix / Windows command separators + dangerous binaries (CRS 932 PL1-ish). */
const UNIX_CMD_INJECTION =
  /(?:;|\||`|\$\(|&&|\n)\s*(?:cat|chmod|chown|curl|wget|bash|dash|zsh|sh|nc|ncat|python[23]?|perl|ruby|php|id|whoami|uname|ls|rm|kill|sleep|ping|telnet|ftp)\b/i;

/** PowerShell / cmd.exe probes (CRS 932). */
const WINDOWS_RCE =
  /\b(?:cmd(?:\.exe)?\b[^&\n|]*\s\/[ck]\b|powershell(?:\.exe)?\b[^&\n|]*-(?:encodedcommand|e(?:c)?|command|c)\b|invoke-expression\b|\biex\s*\()/i;

/** Shellshock bash function export (CRS 932170/171). */
const SHELLSHOCK = /\(\s*\)\s*\{/;

/** SSTI with execution indicators (CRS 934200 simplified). */
const SSTI =
  /\{\{[^}]{0,80}?(?:\*|__|\()[^}]{0,80}?\}\}|#\{[^}]{0,80}?(?:\*|__|\()[^}]{0,80}?\}|<%[=]?[^%]{0,80}?(?:\*|__|\()[^%]{0,80}?%>/i;

/** Cloud metadata / link-local SSRF targets (CRS 934110 subset). */
const SSRF_METADATA =
  /(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|192\.0\.0\.192|instance-data\/latest|computeMetadata\/v1|169\.254\.170\.2\/v2)/i;

const PAYLOAD_FIELDS = ['query', 'body', 'cookies'] as const;

function anyField(
  fields: readonly ('query' | 'body' | 'cookies' | 'path' | 'headers')[],
  pattern: RegExp,
): WafRule['when'] {
  return {
    anyOf: fields.map((field) => ({ field, matches: pattern })),
  };
}

/**
 * Derived from OWASP CRS REQUEST-932 / 934.
 * Shell RCE, SSTI and cloud-metadata SSRF — complements PHP RCE in `rfi`.
 */
export const rceRules: readonly WafRule[] = [
  {
    id: 'preset-rce-shellshock',
    priority: 40,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible Shellshock (CVE-2014-6271) probe',
    when: anyField([...PAYLOAD_FIELDS, 'headers'], SHELLSHOCK),
  },
  {
    id: 'preset-rce-unix-cmd',
    priority: 50,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible Unix command injection',
    when: anyField(PAYLOAD_FIELDS, UNIX_CMD_INJECTION),
  },
  {
    id: 'preset-rce-windows',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible Windows / PowerShell command injection',
    when: anyField(PAYLOAD_FIELDS, WINDOWS_RCE),
  },
  {
    id: 'preset-rce-ssrf-metadata',
    priority: 48,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible SSRF to cloud instance metadata',
    when: anyField([...PAYLOAD_FIELDS, 'path'], SSRF_METADATA),
  },
  {
    id: 'preset-rce-ssti',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible server-side template injection',
    when: anyField(PAYLOAD_FIELDS, SSTI),
  },
  {
    id: 'preset-rce-nodejs',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible Node.js child_process / require injection',
    when: anyField(
      PAYLOAD_FIELDS,
      /\brequire\s*\(\s*['"]child_process['"]|\bchild_process\b[\s\S]{0,40}\b(?:exec(?:Sync)?|spawn(?:Sync)?)\s*\(/i,
    ),
  },
  {
    id: 'preset-rce-shell-expression',
    priority: 55,
    action: 'block',
    minLevel: 'high',
    reason: 'Unix shell expression / substitution',
    when: anyField(PAYLOAD_FIELDS, /\$\([^)]{1,120}\)|\$\{[^}]{1,120}\}|<\([^)]{1,80}\)/),
  },
  {
    id: 'preset-rce-fork-bomb',
    priority: 55,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible shell fork bomb',
    when: anyField(PAYLOAD_FIELDS, /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:/),
  },
];
