import type { WafRule } from '@/domain/rules';

/** Remote / local file inclusion, PHP RCE probes and dangerous uploads. */
export const rfiRules: readonly WafRule[] = [
  {
    id: 'preset-rfi',
    priority: 50,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible remote / local file inclusion',
    when: {
      anyOf: [
        {
          field: 'query',
          matches:
            /(INCLUDE|REQUIRE)(?:_ONCE)?|(?:php|data|expect|file|ftp|https?):\/\//i,
        },
        {
          field: 'path',
          matches:
            /(INCLUDE|REQUIRE)(?:_ONCE)?|(?:php|data|expect|file|ftp):\/\//i,
        },
        {
          field: 'body',
          matches:
            /(INCLUDE|REQUIRE)(?:_ONCE)?|(?:php|data|expect|file):\/\//i,
        },
      ],
    },
  },
  {
    id: 'preset-rce-php',
    priority: 50,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible remote code execution payload',
    when: {
      anyOf: [
        {
          field: 'query',
          matches:
            /\b(?:eval)\s*\(\s*(?:base64_decode|exec|file_get_contents|gzinflate|passthru|shell_exec|system)\s*\(|\b(?:XDEBUG_SESSION_START|invokefunction|call_user_func_array)\b/i,
        },
        {
          field: 'body',
          matches:
            /\b(?:eval)\s*\(\s*(?:base64_decode|exec|file_get_contents|gzinflate|passthru|shell_exec|system)\s*\(|\b(?:XDEBUG_SESSION_START|invokefunction|call_user_func_array)\b/i,
        },
        {
          field: 'cookies',
          matches:
            /\b(?:eval)\s*\(\s*(?:base64_decode|exec|file_get_contents|gzinflate|passthru|shell_exec|system)\s*\(|\b(?:XDEBUG_SESSION_START|invokefunction|call_user_func_array)\b/i,
        },
      ],
    },
  },
  {
    id: 'preset-dangerous-upload',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Dangerous executable upload extension',
    when: {
      field: 'files',
      matches: /\.(?:php\d?|phtml|phar|aspx?|asa|cer|jspx?)$/i,
    },
  },
];
