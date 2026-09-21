import type { WafRule } from '@/domain/rules';
import { PAYLOAD_PATH_FIELDS, anyFieldMatches } from '@/presets/fields';

/**
 * LDAP filter injection — `*)(uid=*`, `(&(objectClass=*))`,
 * `admin)(|(userPassword=*`. Two-signal by construction: a match needs either
 * an LDAP filter grouping (`(&(`, `*)(|`) or an attribute assigned a wildcard,
 * so ordinary parenthesised prose and Markdown links do not match.
 */
const LDAP_INJECTION =
  /\(\s*[&|!]\s*\(|[*)]\s*\)\s*\(\s*[|&]|\(\s*(?:uid|cn|sn|mail|objectclass|userpassword|givenname|member(?:of)?)\s*=\s*[*)]/i;

/**
 * LDAP extensible-match / OID matching-rule injection — `attr:2.5.13.5:=x`,
 * `(cn:1.2.840.113556.1.4.803:=2)`. The dotted OID followed by `:=` is the
 * signature; a bare `x := 5` assignment has no multi-part OID before it.
 */
const LDAP_MATCHING_RULE =
  /(?:\d+\.){3,}\d+\s*:\s*=|:\s*(?:caseignorematch|caseexactmatch|integermatch|distinguishednamematch)\s*:\s*=/i;

/**
 * GraphQL schema introspection probe — `__schema`, `IntrospectionQuery`,
 * `__type(name:`. `paranoid` because dev tooling (GraphiQL, codegen) issues the
 * same query legitimately; `__typename`, which real clients send constantly, is
 * deliberately **not** matched. The `__schema` / `__type` prefilter is tight.
 */
const GRAPHQL_INTROSPECTION =
  /\b__schema\b|\bIntrospectionQuery\b|\b__type\s*\(\s*name\s*:/i;

/** Known scanners, exploit kits, DoS heuristics and generic attack probes. */
export const scannerRules: readonly WafRule[] = [
  {
    id: 'preset-ldap-filter',
    priority: 50,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible LDAP filter injection',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, LDAP_INJECTION, ['(']),
  },
  {
    id: 'preset-ldap-matching-rule',
    priority: 50,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible LDAP extensible-match (OID matching rule) injection',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, LDAP_MATCHING_RULE, [':=']),
  },
  {
    id: 'preset-scanners-ua',
    priority: 40,
    action: 'block',
    minLevel: 'low',
    reason: 'Known scanner or exploit tool',
    when: {
      field: 'headers.user-agent',
      matches:
        /(?:sqlmap|nikto|nmap|masscan|acunetix|nessus|burpsuite|w3af|dirbuster|owasp_dirbuster|havij|openvas|zgrab|nuclei|ffuf|fuzz faster|feroxbuster|gobuster|wfuzz|dirsearch|wpscan|arachni|sqlninja|wafw00f|whatweb)/i,
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
    id: 'preset-graphql-introspection',
    priority: 48,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Possible GraphQL schema introspection probe',
    when: anyFieldMatches(['query', 'body'], GRAPHQL_INTROSPECTION, [
      '__schema',
      'introspectionquery',
      '__type',
    ]),
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
