import type { WafRule } from '@/domain/rules';
import { PAYLOAD_PATH_FIELDS, anyFieldMatches } from '@/presets/fields';

/** Classic `../` and encoded variants (CRS 930100/110 simplified). */
const PATH_TRAVERSAL = /(\.\.(\/|\\)|\.\.%(2[fF]|5[cC])|\.\.;(?:\/|\\))+/;

/**
 * Percent-encoded, double-encoded and overlong-UTF-8 traversal (CRS 930100).
 *
 * This matters because adapters expose `path` exactly as it arrived on the
 * wire — still encoded — so `%2e%2e%2f` never reaches {@link PATH_TRAVERSAL}.
 * On `query`, whose values the framework already decoded, a surviving `%2e%2e`
 * means the client double-encoded it.
 */
const ENCODED_TRAVERSAL =
  /%(?:25)?2[eE]%(?:25)?2[eE]|\.%(?:25)?2[eE]|%(?:25)?2[eE]\.|%c0%a[ef]|%c1%9c|%e0%80%a[ef]|%u2216|%uff0e/i;

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
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, PATH_TRAVERSAL, ['..']),
  },
  {
    id: 'preset-path-traversal-encoded',
    priority: 50,
    action: 'block',
    minLevel: 'low',
    reason: 'Encoded or double-encoded path traversal attempt',
    when: anyFieldMatches(
      ['path', 'query', 'cookies'],
      ENCODED_TRAVERSAL,
      ['%'],
    ),
  },
  {
    id: 'preset-lfi-os-files',
    priority: 50,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible local file inclusion of OS path',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, OS_FILE_ACCESS, [
      '/etc/',
      '.ini',
      '/proc/',
      'system32',
    ]),
  },
  {
    id: 'preset-lfi-restricted-files',
    priority: 48,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Restricted or sensitive file path probe',
    when: anyFieldMatches(['path', 'query', 'url'], RESTRICTED_PATH, [
      '.git',
      '.env',
      '.htaccess',
      '.htpasswd',
      '.ds_store',
      'wp-config.php',
      'web.config',
      'composer.',
      'id_rsa',
    ]),
  },
];
