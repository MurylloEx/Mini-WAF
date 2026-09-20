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
      ['query', 'body', 'cookies'],
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
