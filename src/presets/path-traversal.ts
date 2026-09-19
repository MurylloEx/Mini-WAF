import type { WafRule } from '@/domain/rules';

/** Classic `../` and encoded variants (CRS 930100/110 simplified). */
const PATH_TRAVERSAL = /(\.\.(\/|\\)|\.\.%(2[fF]|5[cC])|\.\.;(?:\/|\\))+/;

/**
 * Sensitive OS / app paths often probed in LFI (CRS 930120/130 subset).
 * Kept compact — not the full CRS data files.
 */
const OS_FILE_ACCESS =
  /(?:\/etc\/(?:passwd|shadow|hosts|issue|crontab)|(?:^|[\\/])(?:boot|win)\.ini\b|\/proc\/(?:self|version)|\/windows\/system32\/|\\windows\\system32\\)/i;

/** VCS / secrets / backup files in the path (CRS 930130-ish). */
const RESTRICTED_PATH =
  /(?:\/|^)(?:\.git(?:\/|$)|\.env(?:\.|$)|\.htaccess|\.htpasswd|\.DS_Store|wp-config\.php|web\.config|composer\.(?:json|lock)|id_rsa(?:\.pub)?)/i;

export const pathTraversalRules: readonly WafRule[] = [
  {
    id: 'preset-path-traversal',
    priority: 50,
    action: 'block',
    minLevel: 'low',
    reason: 'Path traversal attempt',
    when: {
      anyOf: [
        { field: 'query', matches: PATH_TRAVERSAL },
        { field: 'path', matches: PATH_TRAVERSAL },
        { field: 'body', matches: PATH_TRAVERSAL },
        { field: 'cookies', matches: PATH_TRAVERSAL },
      ],
    },
  },
  {
    id: 'preset-lfi-os-files',
    priority: 50,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible local file inclusion of OS path',
    when: {
      anyOf: [
        { field: 'query', matches: OS_FILE_ACCESS },
        { field: 'path', matches: OS_FILE_ACCESS },
        { field: 'body', matches: OS_FILE_ACCESS },
        { field: 'cookies', matches: OS_FILE_ACCESS },
      ],
    },
  },
  {
    id: 'preset-lfi-restricted-files',
    priority: 48,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Restricted or sensitive file path probe',
    when: {
      anyOf: [
        { field: 'path', matches: RESTRICTED_PATH },
        { field: 'query', matches: RESTRICTED_PATH },
        { field: 'url', matches: RESTRICTED_PATH },
      ],
    },
  },
];
