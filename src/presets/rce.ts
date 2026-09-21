import type { WafRule } from '@/domain/rules';
import { PAYLOAD_FIELDS, anyFieldMatches } from '@/presets/fields';

/**
 * Unix command injection (CRS 932 PL1-ish).
 *
 * Two arms, because separator strength differs:
 * 1. an unambiguous separator (`;`, backtick, `$(`, `&&`, `||`, newline)
 *    followed by any shell binary;
 * 2. a bare `|`, which also shows up in ordinary pipe-delimited values
 *    (`rails|php|node`), so it additionally requires a non-ambiguous binary
 *    **and** an argument after it.
 */
const UNIX_CMD_INJECTION =
  /(?:[;`\n]|\$\(|&&|\|\|)\s*\/?(?:\w+\/)*(?:cat|chmod|chown|curl|wget|bash|dash|zsh|sh|nc|ncat|netcat|python[23]?|perl|ruby|php|id|whoami|uname|ls|rm|kill|sleep|ping|telnet|ftp|busybox|xterm|crontab|nohup|getent|dig|nslookup)\b|\|\s*\/?(?:\w+\/)*(?:chmod|chown|curl|wget|nc|ncat|netcat|whoami|uname|busybox|xterm|telnet|crontab|nohup|bash|sh|python[23]?|perl|getent)\s+[-\w'"/]/i;

/** PowerShell / cmd.exe probes (CRS 932). */
const WINDOWS_RCE =
  /\b(?:cmd(?:\.exe)?\b[^&\n|]*\s\/[ck]\b|powershell(?:\.exe)?\b[^&\n|]*-(?:encodedcommand|e(?:c)?|command|c)\b|invoke-expression\b|\biex\s*\()/i;

/**
 * Living-off-the-land Windows binaries used to stage a payload (CRS 932).
 * Each arm requires the flag that makes the binary dangerous, so ordinary
 * text mentioning `certutil` or `rundll32` does not match.
 */
const WINDOWS_LOLBIN =
  /\b(?:certutil(?:\.exe)?\b[^\n]{0,80}-(?:urlcache|decode|encode)\b|bitsadmin(?:\.exe)?\b[^\n]{0,60}\/transfer\b|mshta(?:\.exe)?\s+(?:https?|javascript|vbscript)\s*:|regsvr32(?:\.exe)?\b[^\n]{0,60}\/i\s*:|wmic\b[^\n]{0,60}\bprocess\b[^\n]{0,40}\bcall\b[^\n]{0,20}\bcreate\b|msiexec(?:\.exe)?\b[^\n]{0,40}\/i\s+https?\s*:)/i;

/** Shellshock bash function export (CRS 932170/171). */
const SHELLSHOCK = /\(\s*\)\s*\{/;

/**
 * JNDI / Log4Shell style lookup, including the nested `${${lower:j}ndi:`
 * obfuscation. No legitimate user input carries these.
 */
const JNDI_LOOKUP =
  /\$\{\s*(?:jndi|ctx|env|sys|lower|upper|date|main|java|base64|url|spring)\s*:|\$\{[^}]{0,40}\$\{/i;

/** Reverse / bind shell staging (CRS 932). */
const REVERSE_SHELL =
  /\/dev\/(?:tcp|udp)\/|\b(?:nc|ncat|netcat)\b[^\n]{0,60}\s-[a-z]{0,3}e\b|\b(?:ba|z|k)?sh\s+-[a-z]{0,3}i\b[^\n]{0,20}>\s*&|\bsocat\b[^\n]{0,60}\bexec\s*:|\bmkfifo\b[^\n]{0,60}\bn(?:c|cat)\b|\bmsfvenom\b/i;

/** Fetch-and-run: `curl … | sh`, `base64 -d | bash`, `python -c '…'`. */
const DOWNLOAD_EXEC =
  /\b(?:curl|wget|fetch)\b[^\n|]{0,160}\|\s*(?:sudo\s+)?(?:ba|z|da|k)?sh\b|\bbase64\s+(?:-d|--decode)\b[^\n|]{0,60}\|\s*(?:ba)?sh\b|\b(?:python[23]?|perl|ruby|node|php)\s+-(?:c|e|r)\s+["'`]/i;

/** SSTI with execution indicators (CRS 934200 simplified). */
const SSTI =
  /\{\{[^}]{0,80}?(?:\*|__|\()[^}]{0,80}?\}\}|#\{[^}]{0,80}?(?:\*|__|\()[^}]{0,80}?\}|<%[=]?[^%]{0,80}?(?:\*|__|\()[^%]{0,80}?%>/i;

/** Cloud metadata / link-local SSRF targets (CRS 934110 subset). */
const SSRF_METADATA =
  /(?:169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200|192\.0\.0\.192|instance-data\/latest|computeMetadata\/v1|169\.254\.170\.2\/v2)/i;

/**
 * SSRF to a private (RFC 1918) / loopback host through a URL scheme —
 * `http://127.0.0.1`, `gopher://10.0.0.5`, `dict://192.168.1.1`. `paranoid`:
 * legitimate internal webhooks and dev callbacks look the same, so this only
 * runs at the highest tier; the `://` prefilter keeps it off ordinary values.
 */
const SSRF_INTERNAL =
  /\b(?:https?|ftp|gopher|dict|ldap):\/\/(?:[^/\s@]{0,80}@)?(?:127\.\d{1,3}\.\d{1,3}\.\d{1,3}|0\.0\.0\.0|localhost|\[?::1\]?|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})/i;

/**
 * VBScript / ASP string-concatenation obfuscation — `Ex"&"e"&"cute`,
 * `e'+'v'+'al` — rebuilding a keyword past a literal filter. Two or more
 * adjacent quote-operator-quote groups. `paranoid`: ordinary quoted text can
 * carry `"&"`, so the tight `"&"` / `"+"` prefilter is what makes it cheap.
 */
const ASP_STRING_CONCAT = /(?:["'][&+]["'][a-z0-9]{0,3}){2,}/i;

/** Node.js `child_process` / dynamic `require` injection. */
const NODE_RCE =
  /\brequire\s*\(\s*['"]child_process['"]|\bchild_process\b[\s\S]{0,40}\b(?:exec(?:Sync)?|spawn(?:Sync)?)\s*\(/i;

/**
 * Language-level process execution APIs (Python, Java, Ruby).
 * Kept at `balanced` — snippet-sharing apps may legitimately post these.
 */
const LANG_EXEC =
  /\bos\s*\.\s*(?:system|popen|execv?p?e?)\s*\(|\bsubprocess\s*\.\s*(?:Popen|call|run|check_output|check_call)\s*\(|\bRuntime\s*\.\s*getRuntime\s*\(\s*\)\s*\.\s*exec\s*\(|\bProcessBuilder\s*\(|\b__import__\s*\(\s*["']os["']|\bcommands\s*\.\s*getoutput\s*\(|\bIO\s*\.\s*popen\s*\(/i;

/** Serialized-object payloads that lead to gadget-chain RCE. */
const DESERIALIZATION =
  /\brO0AB[A-Za-z0-9+/]{4}|\baced0005\b|\bO:\d{1,3}:"[A-Za-z_\\][\w\\]{0,60}":\d{1,4}:\{|\ba:\d{1,4}:\{[is]:\d|\bpickle\s*\.\s*loads\s*\(|\byaml\s*\.\s*(?:unsafe_)?load\s*\(|\b__reduce__\b/i;

/**
 * Shell parameter expansion / process substitution.
 * Narrowed so ordinary `${name}` interpolation in i18n or price templates is
 * not flagged: a bare `${identifier}` needs an expansion operator to match.
 */
const SHELL_EXPANSION =
  /\$\([^)]{1,120}\)|<\([^)]{1,80}\)|\$\{IFS\}|\$\{[!#]|\$\{\w{1,32}[:#%/^,][^}]{0,80}\}/;

/** Fork bomb. */
const FORK_BOMB = /:\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;?\s*:/;

/**
 * FreeMarker template injection — `<#assign … = …?new(…)>`, the
 * `freemarker.template.utility.Execute` gadget, `<@…>` user directives. None
 * of these directive tokens has a legitimate meaning in request input.
 */
const FREEMARKER =
  /<#\s*(?:assign|list|if|include|import|macro|function|global|local|setting)\b|freemarker\.template\.utility\.(?:Execute|ObjectConstructor)|\?\s*new\s*\(\s*["'][\w.]*(?:Execute|ObjectConstructor)/i;

/**
 * Unsafe deserialization tags for Python (PyYAML) and Ruby YAML —
 * `!!python/object/apply:os.system`, `!!python/object/new:`, `--- !ruby/object`.
 * The `safe_load` path never emits these, so their presence in input is a
 * gadget-chain probe.
 */
const YAML_UNSAFE_TAG =
  /!!python\/(?:object|module|name)\b|!ruby\/(?:object|hash|struct|marshal|range)\b|!!(?:java|javax)\./i;

const PAYLOAD_AND_HEADERS = [...PAYLOAD_FIELDS, 'headers'] as const;
const PAYLOAD_AND_PATH = [...PAYLOAD_FIELDS, 'path'] as const;

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
    when: anyFieldMatches(PAYLOAD_AND_HEADERS, SHELLSHOCK),
  },
  {
    id: 'preset-rce-jndi',
    priority: 40,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible JNDI / Log4Shell lookup injection',
    when: anyFieldMatches(PAYLOAD_AND_HEADERS, JNDI_LOOKUP, ['${']),
  },
  {
    id: 'preset-rce-unix-cmd',
    priority: 50,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible Unix command injection',
    when: anyFieldMatches(PAYLOAD_AND_PATH, UNIX_CMD_INJECTION, [
      ';',
      '`',
      '\n',
      '$(',
      '&&',
      '|',
    ]),
  },
  {
    id: 'preset-rce-reverse-shell',
    priority: 45,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible reverse / bind shell payload',
    when: anyFieldMatches(PAYLOAD_AND_HEADERS, REVERSE_SHELL, [
      '/dev/',
      'nc',
      'sh',
      'socat',
      'mkfifo',
      'msfvenom',
    ]),
  },
  {
    id: 'preset-rce-download-exec',
    priority: 45,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible fetch-and-execute payload',
    when: anyFieldMatches(PAYLOAD_FIELDS, DOWNLOAD_EXEC, [
      'curl',
      'wget',
      'fetch',
      'base64',
      'python',
      'perl',
      'ruby',
      'node',
      'php',
    ]),
  },
  {
    id: 'preset-rce-windows-lolbin',
    priority: 45,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible Windows living-off-the-land binary abuse',
    when: anyFieldMatches(PAYLOAD_FIELDS, WINDOWS_LOLBIN, [
      'certutil',
      'bitsadmin',
      'mshta',
      'regsvr32',
      'wmic',
      'msiexec',
    ]),
  },
  {
    id: 'preset-rce-ssrf-metadata',
    priority: 48,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible SSRF to cloud instance metadata',
    when: anyFieldMatches(PAYLOAD_AND_PATH, SSRF_METADATA, [
      '169.254',
      'metadata.google',
      '100.100.100.200',
      '192.0.0.192',
      'instance-data',
      'computemetadata',
    ]),
  },
  {
    id: 'preset-rce-windows',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible Windows / PowerShell command injection',
    when: anyFieldMatches(PAYLOAD_FIELDS, WINDOWS_RCE, [
      'cmd',
      'powershell',
      'invoke-expression',
      'iex',
    ]),
  },
  {
    id: 'preset-rce-ssti',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible server-side template injection',
    when: anyFieldMatches(PAYLOAD_AND_PATH, SSTI, ['{{', '#{', '<%']),
  },
  {
    id: 'preset-rce-freemarker',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible FreeMarker template injection',
    when: anyFieldMatches(PAYLOAD_AND_PATH, FREEMARKER, ['<#', 'freemarker', '?new']),
  },
  {
    id: 'preset-rce-yaml-deserialization',
    priority: 52,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible unsafe YAML deserialization (Python / Ruby / Java tag)',
    when: anyFieldMatches(PAYLOAD_FIELDS, YAML_UNSAFE_TAG, ['!!python', '!ruby/', '!!java', '!!javax']),
  },
  {
    id: 'preset-rce-nodejs',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible Node.js child_process / require injection',
    when: anyFieldMatches(PAYLOAD_FIELDS, NODE_RCE, ['child_process']),
  },
  {
    id: 'preset-rce-lang-exec',
    priority: 52,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible process execution via language runtime API',
    when: anyFieldMatches(PAYLOAD_FIELDS, LANG_EXEC, [
      'system',
      'popen',
      'exec',
      'subprocess',
      'runtime',
      'processbuilder',
      '__import__',
      'getoutput',
    ]),
  },
  {
    id: 'preset-rce-deserialization',
    priority: 52,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible insecure deserialization payload',
    when: anyFieldMatches(PAYLOAD_FIELDS, DESERIALIZATION),
  },
  {
    id: 'preset-rce-shell-expression',
    priority: 55,
    action: 'block',
    minLevel: 'high',
    reason: 'Unix shell expression / substitution',
    when: anyFieldMatches(PAYLOAD_FIELDS, SHELL_EXPANSION, [
      '$(',
      '<(',
      '${',
    ]),
  },
  {
    id: 'preset-rce-fork-bomb',
    priority: 55,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible shell fork bomb',
    when: anyFieldMatches(PAYLOAD_FIELDS, FORK_BOMB, [':(']),
  },
  {
    id: 'preset-ssrf-internal',
    priority: 58,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Possible SSRF to a private / loopback host',
    when: anyFieldMatches(PAYLOAD_AND_PATH, SSRF_INTERNAL, ['://']),
  },
  {
    id: 'preset-rce-asp-concat',
    priority: 58,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Possible ASP / VBScript string-concatenation obfuscation',
    when: anyFieldMatches(PAYLOAD_FIELDS, ASP_STRING_CONCAT, [
      '"&"',
      "'&'",
      '"+"',
      "'+'",
    ]),
  },
];
