import type { WafRule } from '@/domain/rules';
import { isHostIpLiteral } from '@/utils/ip';
import { anyFieldMatches } from '@/presets/fields';

/**
 * Derived from OWASP CRS REQUEST-920 / 921 / 943.
 * Practical HTTP protocol & session-fixation heuristics (not ModSecurity verbatim).
 */
export const protocolRules: readonly WafRule[] = [
  {
    id: 'preset-protocol-response-splitting',
    priority: 45,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible HTTP response splitting',
    when: anyFieldMatches(
      ['query', 'body', 'cookies', 'path'],
      /[\r\n][^0-9A-Za-z_]*?(?:content-(?:type|length)|set-cookie|location)\s*:/i,
      ['\r', '\n'],
    ),
  },
  {
    id: 'preset-protocol-request-smuggling',
    priority: 45,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible HTTP request smuggling probe',
    when: anyFieldMatches(['query', 'body'], /\b(?:get|p(?:ost|ut|atch)|head|options|delete|connect|trace)\s+\S+\s+http\/[0-9]/i, ['http/']),
  },
  {
    id: 'preset-protocol-crlf-path',
    priority: 45,
    action: 'block',
    minLevel: 'balanced',
    reason: 'CR/LF in request path',
    when: {
      field: 'path',
      matches: /[\r\n]/,
      requires: ['\r', '\n'],
    },
  },
  {
    id: 'preset-protocol-crlf-encoded-path',
    priority: 45,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Percent-encoded CR/LF in path or URL (response splitting)',
    when: anyFieldMatches(
      ['path', 'url'],
      /%0[dD]%0[aA]|%0[aA]%0[dD]|%0[aAdD][^&#]{0,64}?(?:set-cookie|content-(?:type|length|disposition)|location|refresh)\s*:/i,
      ['%0'],
    ),
  },
  {
    id: 'preset-protocol-crlf-double-encoded',
    priority: 45,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Double-encoded or overlong CR/LF in path or URL',
    when: anyFieldMatches(
      ['path', 'url'],
      /%25(?:25)*(?:0[dDaA]|30[dDaA]|3[45])|%25%30%4[14]|%c0%8[aAdD]|%e0%80%8[aAdD]|%e5%98%8[aAdD]|%u000[aAdD]/i,
      ['%25', '%c0', '%e0', '%e5', '%u00'],
    ),
  },
  {
    id: 'preset-protocol-mail-command',
    priority: 45,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible SMTP / IMAP command injection via CR/LF',
    when: anyFieldMatches(
      ['query', 'body', 'cookies'],
      /(?:[\r\n]|%0[aAdD]){1,3}\s*(?:RCPT\s+TO|MAIL\s+FROM|EHLO|HELO|AUTH\s+LOGIN|STARTTLS|CAPABILITY|BDAT)\b/i,
      ['\r', '\n', '%0'],
    ),
  },
  {
    id: 'preset-protocol-imap-command',
    priority: 45,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible IMAP command injection via CR/LF',
    // Real IMAP client traffic is `<tag> COMMAND`, where the tag is a short
    // alphanumeric counter (`V100`, `a001`, `*`). The anchored
    // `preset-protocol-mail-command` never sees these because the tag sits
    // between the CR/LF and the verb. Requiring a *digit-bearing* tag after the
    // CR/LF keeps ordinary multi-line prose ("...\nplease fetch the file") out,
    // and the verb list is limited to non-English IMAP keywords. `high`: mail /
    // IMAP header injection is inherently FP-prone on free-text form fields.
    when: anyFieldMatches(
      ['query', 'body', 'cookies'],
      /(?:[\r\n]|%0[aAdD]){1,3}[ \t]*(?:[A-Za-z0-9]*\d[A-Za-z0-9]*|\*)[ \t]+(?:CAPABILITY|FETCH|LOGIN|LOGOUT|STARTTLS|AUTHENTICATE|NAMESPACE|LSUB|EXPUNGE|UID)\b/i,
      ['\r', '\n', '%0'],
    ),
  },
  {
    id: 'preset-protocol-mail-teardown',
    priority: 46,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible mail session teardown (QUIT) via CR/LF',
    // `\r\nQUIT\r\n` as sent to SMTP / POP3 / IMAP. `QUIT` is an English word,
    // so it only matches when it is the *entire* line (CR/LF or end on both
    // sides), never mid-sentence ("please quit smoking").
    when: anyFieldMatches(
      ['query', 'body', 'cookies'],
      /(?:[\r\n]|%0[aAdD])[ \t]*QUIT[ \t]*(?:[\r\n]|%0[aAdD]|$)/i,
      ['quit'],
    ),
  },
  {
    id: 'preset-protocol-header-injection',
    priority: 45,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible header injection via CR/LF in query',
    when: {
      field: 'query',
      matches:
        /[\r\n]+(?:[\t ]|location|refresh|(?:set-)?cookie|host|via|x-forwarded-(?:for|host|proto))\s*:/i,
      requires: ['\r', '\n'],
    },
  },
  {
    id: 'preset-protocol-cl-te-conflict',
    priority: 40,
    action: 'block',
    minLevel: 'high',
    reason: 'Content-Length and Transfer-Encoding both present',
    when: {
      all: [
        { field: 'headers.content-length', matches: /\S/ },
        { field: 'headers.transfer-encoding', matches: /\S/ },
      ],
    },
  },
  {
    id: 'preset-protocol-host-ip',
    priority: 48,
    action: 'block',
    minLevel: 'high',
    reason: 'Host header is a raw IP address',
    when: {
      field: 'headers.host',
      matches: isHostIpLiteral,
    },
  },
  {
    id: 'preset-session-fixation-cookie-html',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible session fixation via cookie HTML attributes',
    when: anyFieldMatches(['query', 'body'], /\.cookie\b[^;]*;\s*(?:expires|domain)\s*=|\bhttp-equiv\s*=\s*["']?set-cookie\b/i, [
      '.cookie',
      'http-equiv',
    ]),
  },
  {
    id: 'preset-session-id-in-url',
    priority: 55,
    action: 'block',
    minLevel: 'high',
    reason: 'Session identifier passed in URL query',
    when: {
      field: 'url',
      matches:
        /[?&](?:phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|laravel_session|_session_id|sessionid)=/i,
      requires: [
        'sessid',
        'sessionid',
        'connect.sid',
        'laravel_session',
        '_session_id',
      ],
    },
  },
  {
    id: 'preset-protocol-mail-verb',
    priority: 46,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'SMTP / IMAP command verb in request input',
    when: anyFieldMatches(
      ['query', 'body'],
      /\bRCPT\s+TO\s*:|\bMAIL\s+FROM\s*:|\bEHLO\s+[\w.-]|\bHELO\s+[\w.-]|\bAUTH\s+LOGIN\b/i,
      ['rcpt', 'mail from', 'ehlo', 'helo', 'auth login'],
    ),
  },
  {
    id: 'preset-protocol-empty-ua',
    priority: 60,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Empty or missing User-Agent',
    when: {
      field: 'headers.user-agent',
      equals: '',
    },
  },
];
