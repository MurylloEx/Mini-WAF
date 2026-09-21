import type { WafRule } from '@/domain/rules';
import {
  PAYLOAD_FIELDS,
  PAYLOAD_PATH_FIELDS,
  anyFieldMatches,
} from '@/presets/fields';

/**
 * PHP / stream wrappers (CRS 931110-ish). None of these schemes has a
 * legitimate meaning in client input, so the rule stays at `low`.
 */
const STREAM_WRAPPER =
  /\b(?:php|data|expect|zip|phar|glob|ogg|rar|zlib|input|compress\.(?:zlib|bzip2))\s*:\/\/|\bfile\s*:\/\/\/|\bphp:\/\/filter\b|\ballow_url_(?:include|fopen)\b/i;

/**
 * Remote inclusion of a server-side script: an absolute URL whose path ends
 * in an executable web extension, or the CRS 931130 trailing-`?` trick used
 * to truncate the appended local suffix.
 *
 * Deliberately narrow — matching every `https://…` would block OAuth
 * `redirect_uri`, CDN links and webhook callbacks. `.txt` is included because
 * a remote `shell.txt` is the canonical RFI payload; pass the URL in the body
 * or disable this rule id if your API legitimately fetches remote text files.
 */
const REMOTE_INCLUDE =
  /(?:^|[=,(\s"'])(?:https?|ftps?):\/\/[^\s'"<>]{1,200}?(?:\.(?:php\d?|phtml|phps|pht|inc|txt|asp|aspx|jsp|jspx|cgi|pl)\b|\?\s*$)/i;

/**
 * PHP inclusion syntax. The quote/paren/variable after the keyword is what
 * separates `include('shell.txt')` from the English word or a JSON
 * `"include": true` / `"required": []` key.
 */
const INCLUDE_SYNTAX =
  /\b(?:include|require)(?:_once)?\b\s*(?:\(\s*['"$]|\s+['"$])/i;

/** PHP execution sinks and known RCE entry points (CRS 933). */
const PHP_RCE =
  /\b(?:eval|assert|preg_replace)\s*\(\s*(?:base64_decode|exec|file_get_contents|gzinflate|passthru|shell_exec|system|str_rot13)?\s*\(?|\b(?:XDEBUG_SESSION_START|invokefunction|call_user_func(?:_array)?|create_function|proc_open|popen|pcntl_exec)\b|\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER)\s*\[/i;

/**
 * XML external entity (XXE) — a `<!ENTITY … SYSTEM …>` external reference, a
 * `<!DOCTYPE>` that declares an entity, or a `SYSTEM`/`PUBLIC` identifier
 * pointing at a file/URL scheme. Bare `<!DOCTYPE html>` (ubiquitous in benign
 * HTML) is deliberately **not** matched: a hit needs the entity/SYSTEM gadget.
 */
const XXE_ENTITY =
  /<!ENTITY\b[\s\S]{0,200}?\b(?:SYSTEM|PUBLIC)\b|<!DOCTYPE\b[\s\S]{0,200}?<!ENTITY\b|<!DOCTYPE\b[^>]{0,200}?\bSYSTEM\s+["'](?!about:legacy-compat)|\b(?:SYSTEM|PUBLIC)\s+["'](?:file|https?|ftp|php|expect|jar|netdoc|gopher|data):/i;

/** Server-executable upload extensions. */
const DANGEROUS_UPLOAD =
  /\.(?:php\d?|phtml|phps|pht|phar|aspx?|asa|asax|cer|cdx|jspx?|jsw|jsv|shtml?|cgi|pl|py|rb|sh|bash|exe|dll|jar|war|bat|cmd|ps1|htaccess|htpasswd)$/i;

/**
 * Double extension (`shell.php.jpg`) and null-byte truncation — both used to
 * defeat extension allowlists (CRS 933-adjacent).
 */
const UPLOAD_EXTENSION_BYPASS =
  /\.(?:php\d?|phtml|phps|pht|phar|aspx?|jspx?|shtml?|cgi|exe|sh)(?:\.[a-z0-9]{1,6})+$|\.(?:php\d?|aspx?|jspx?)\x00/i;

/** Remote / local file inclusion, PHP RCE probes and dangerous uploads. */
export const rfiRules: readonly WafRule[] = [
  {
    id: 'preset-rfi',
    priority: 50,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible file inclusion via stream wrapper',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, STREAM_WRAPPER, [
      '://',
      'allow_url_',
    ]),
  },
  {
    id: 'preset-rce-php',
    priority: 50,
    action: 'block',
    minLevel: 'low',
    reason: 'Possible remote code execution payload',
    when: anyFieldMatches(PAYLOAD_FIELDS, PHP_RCE, [
      'eval',
      'assert',
      'preg_replace',
      'xdebug_session_start',
      'invokefunction',
      'call_user_func',
      'create_function',
      'proc_open',
      'popen',
      'pcntl_exec',
      '$_',
    ]),
  },
  {
    id: 'preset-rfi-remote-url',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible remote file inclusion of a server-side script',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, REMOTE_INCLUDE, ['://']),
  },
  {
    id: 'preset-rfi-include-syntax',
    priority: 52,
    action: 'block',
    minLevel: 'balanced',
    reason: 'PHP include / require syntax in request input',
    when: anyFieldMatches(PAYLOAD_FIELDS, INCLUDE_SYNTAX, [
      'include',
      'require',
    ]),
  },
  {
    id: 'preset-xxe-doctype',
    priority: 50,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible XML external entity (XXE) injection',
    when: anyFieldMatches(['body', 'query'], XXE_ENTITY, [
      '<!entity',
      'system',
      'public',
    ]),
  },
  {
    id: 'preset-dangerous-upload',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Dangerous executable upload extension',
    when: { field: 'files', matches: DANGEROUS_UPLOAD },
  },
  {
    id: 'preset-upload-extension-bypass',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Upload extension bypass (double extension / null byte)',
    when: { field: 'files', matches: UPLOAD_EXTENSION_BYPASS },
  },
];
