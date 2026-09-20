import type { WafRule } from '@/domain/rules';
import { anyFieldMatches } from '@/presets/fields';

/** Known scanners, exploit kits, DoS heuristics and generic attack probes. */
export const scannerRules: readonly WafRule[] = [
  {
    id: 'preset-scanners-ua',
    priority: 40,
    action: 'block',
    minLevel: 'low',
    reason: 'Known scanner or exploit tool',
    when: {
      field: 'headers.user-agent',
      matches:
        /(?:sqlmap|nikto|nmap|masscan|acunetix|nessus|burpsuite|w3af|dirbuster|owasp_dirbuster|havij|openvas|zgrab|nuclei)/i,
    },
  },
  {
    id: 'preset-scanners-ua-broad',
    priority: 42,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Broad scanner / scraper user-agent list',
    when: {
      field: 'headers.user-agent',
      matches:
        /(?:morfeus|pmafind|httrack|blackwidow|wget|libwww-perl|python-requests|scrapy|go-http-client|java\/|curl\/)/i,
    },
  },
  {
    id: 'preset-null-byte',
    priority: 45,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Null-byte injection attempt',
    when: anyFieldMatches(
      ['query', 'path', 'body', 'headers'],
      /\x00/,
      ['\x00'],
    ),
  },
  {
    id: 'preset-data-exposure',
    priority: 48,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible data-exposure probe',
    when: {
      anyOf: [
        {
          field: 'path',
          matches: /phpinfo\.php/i,
          requires: ['phpinfo.php'],
        },
        {
          field: 'query',
          matches: /phpinfo\.php|HTTP_RAW_POST_DATA|HTTP_(?:POS|GE)T_VARS/i,
          requires: ['phpinfo.php', 'http_raw_post_data', 'http_'],
        },
        {
          field: 'body',
          matches: /HTTP_RAW_POST_DATA|HTTP_(?:POS|GE)T_VARS/i,
          requires: ['http_raw_post_data', 'http_'],
        },
      ],
    },
  },
  {
    id: 'preset-prototype-pollution',
    priority: 48,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible prototype pollution',
    when: anyFieldMatches(
      ['query', 'body', 'cookies'],
      /(?:__proto__|constructor\s*\[\s*['"]prototype['"]\s*\])/i,
      ['__proto__', 'constructor'],
    ),
  },
  {
    id: 'preset-hex-flood',
    priority: 48,
    action: 'block',
    minLevel: 'high',
    reason: 'Excessive hexadecimal escape sequence',
    when: anyFieldMatches(
      ['query', 'body'],
      /(?:\\x[a-f0-9]{2,4}){25}/i,
      ['\\x'],
    ),
  },
  {
    id: 'preset-excessive-header',
    priority: 45,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Excessive header length',
    when: {
      field: 'headers',
      matches: /^[\s\S]{2048,}/,
    },
  },
  {
    id: 'preset-shebang',
    priority: 48,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Shell shebang in request payload',
    when: anyFieldMatches(
      ['query', 'body'],
      /#!\/(?:bin|usr\/bin)\//,
      ['#!/'],
    ),
  },
  {
    id: 'preset-dos-rate-limit',
    priority: 90,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible Denial of Service — request rate exceeded',
    when: {
      field: 'ip',
      rateLimit: {
        max: 120,
        windowMs: 60_000,
        keyPrefix: 'preset-dos',
      },
    },
  },
];
