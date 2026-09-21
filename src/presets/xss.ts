import type { WafRule } from '@/domain/rules';
import { PAYLOAD_FIELDS, anyFieldMatches } from '@/presets/fields';

/** Inline script / handler injection shared by query, body and cookies. */
const XSS_CORE =
  /(<\s*script\b|(?:java|vb)script\s*:|on\w+\s*=|<\s*img\b[^>]*\bonerror\b|<\s*svg\b[^>]*\bonload\b|\bdocument\s*(?:\?\.|\.)\s*(?:cookie|location|write(?:ln)?)\b)/i;

/**
 * Percent- / entity- / unicode-encoded `<script`, i.e. a payload already
 * shaped to slip past a naive string filter (CRS 941100 variants).
 */
const XSS_ENCODED_TAG =
  /(?:%3[cC]|&lt;|&#0{0,3}60;?|&#[xX]0{0,3}3[cC];?|\\u0{0,2}3[cC]|\\x3[cC])\s*(?:%2[fF]|\/)?\s*(?:script|img|svg|iframe|body|object|embed)\b/i;

/**
 * URI schemes that render attacker-controlled markup or code.
 * `data:image/png` and friends are deliberately not matched.
 */
const XSS_DANGEROUS_URI =
  /\bdata\s*:\s*(?:text\/html|image\/svg\+xml|application\/(?:x-)?(?:javascript|ecmascript)|text\/javascript)/i;

/**
 * Attribute-based vectors that carry no event-handler prefix, so the generic
 * `on*=` pattern misses them (CRS 941150 / 941210).
 */
const XSS_ATTRIBUTE_VECTOR =
  /(?:\b(?:srcdoc|formaction|dynsrc|lowsrc)\s*=|\bxlink\s*:\s*href\s*=|\bexpression\s*\(\s*[^)]{0,60}\)|\battributeName\s*=\s*["']?\s*(?:href|xlink:href|values|from|to)\b|<\s*set\b[^>]{0,120}\battributeName\b)/i;

/**
 * JavaScript primitives used to decode, build or exfiltrate a payload.
 * Kept at `high`: CMS and snippet-sharing apps legitimately post JS text.
 */
const XSS_JS_PRIMITIVES =
  /(?:\bString\s*\.\s*fromCharCode\s*\(|\batob\s*\(|\bunescape\s*\(|\bFunction\s*\(\s*["'`]|\b(?:window|top|self|parent)\s*\.\s*(?:location|name|document)\b|\bdocument\s*\.\s*domain\b|\bnavigator\s*\.\s*sendBeacon\s*\(|\bXMLHttpRequest\b|\bimport\s*\(\s*["'`]\s*(?:https?:|\/\/))/i;

const SSI_INJECTION = /<!--#\s*(?:config|echo|exec|flastmod|fsize|include)\b/i;

const GENERIC_HTML_TAG =
  /<\s*(?:iframe|object|embed|link|meta|base|form|svg|math|foreignobject|template|marquee|details|portal|frame(?:set)?)\b/i;

const EVAL_ALERT = /\b(?:eval|alert|prompt|confirm)\s*\(/i;

/**
 * Indirect calls to a sink that evade the plain `alert(` pattern:
 * `alert.call(0,1)`, `alert\`1\``, `alert?.(1)` (optional-chaining call),
 * `(alert)(1)`. Higher signal than a bare `alert(`, so it can sit at `high`
 * rather than `paranoid`.
 */
const XSS_INDIRECT_CALL =
  /\b(?:alert|prompt|confirm|eval)\s*(?:\.\s*(?:call|apply|bind)\s*\(|\?\.\s*[(`]|`)|\(\s*(?:alert|prompt|confirm|eval)\s*\)\s*[`(]/i;

/**
 * A quote / bracket that breaks out of a JS string or attribute context and
 * lands directly on a sink call — `'-alert(1)//`, `");eval(x)`. The breakout
 * character before the sink is what keeps this off ordinary prose that merely
 * mentions `alert`, so it is high signal and sits at `high`.
 */
const XSS_BREAKOUT_CALL =
  /['"`]\s*[-+;,)}\]>]\s*(?:alert|prompt|confirm|eval)\s*(?:\?\.)?\s*[(`]/i;

/** Reflected / stored XSS and SSI-style payloads. */
export const xssRules: readonly WafRule[] = [
  {
    id: 'preset-xss-query',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible XSS in query string',
    when: { field: 'query', matches: XSS_CORE },
  },
  {
    id: 'preset-xss-body',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible XSS in body',
    when: {
      field: 'body',
      matches:
        /(<\s*script\b|(?:java|vb)script\s*:|on\w+\s*=|<\s*img\b[^>]*\bonerror\b|\bdocument\s*(?:\?\.|\.)\s*(?:cookie|write(?:ln)?)\b)/i,
    },
  },
  {
    id: 'preset-xss-headers',
    priority: 55,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible XSS in headers',
    when: {
      field: 'headers',
      matches: /(<\s*script\b|(?:java|vb)script\s*:)/i,
    },
  },
  {
    id: 'preset-xss-cookies',
    priority: 55,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible XSS in cookies',
    when: { field: 'cookies', matches: XSS_CORE },
  },
  {
    id: 'preset-xss-path',
    priority: 55,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible XSS in path',
    when: { field: 'path', matches: XSS_CORE },
  },
  {
    id: 'preset-xss-encoded-tag',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Encoded HTML tag used to evade XSS filtering',
    when: anyFieldMatches([...PAYLOAD_FIELDS, 'path'], XSS_ENCODED_TAG, [
      '%3c',
      '&lt;',
      '&#',
      '\\u',
      '\\x3',
    ]),
  },
  {
    id: 'preset-xss-dangerous-uri',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Renderable data: URI (HTML / SVG / JavaScript)',
    when: anyFieldMatches(
      [...PAYLOAD_FIELDS, 'path'],
      XSS_DANGEROUS_URI,
      ['data'],
    ),
  },
  {
    id: 'preset-xss-attribute-vector',
    priority: 52,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible XSS via HTML attribute vector',
    when: anyFieldMatches(PAYLOAD_FIELDS, XSS_ATTRIBUTE_VECTOR, [
      'srcdoc',
      'formaction',
      'dynsrc',
      'lowsrc',
      'xlink',
      'expression',
      'attributename',
      '<set',
    ]),
  },
  {
    id: 'preset-ssi-injection',
    priority: 50,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible SSI command injection',
    when: anyFieldMatches(
      ['query', 'body', 'path', 'cookies'],
      SSI_INJECTION,
      ['<!--#'],
    ),
  },
  {
    id: 'preset-xss-js-primitives',
    priority: 55,
    action: 'block',
    minLevel: 'high',
    reason: 'JavaScript primitive used to decode or exfiltrate a payload',
    when: anyFieldMatches(PAYLOAD_FIELDS, XSS_JS_PRIMITIVES),
  },
  {
    id: 'preset-xss-generic-tags',
    priority: 55,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Generic HTML tag in request (paranoid XSS)',
    when: anyFieldMatches(['query', 'body'], GENERIC_HTML_TAG, ['<']),
  },
  {
    id: 'preset-xss-indirect-call',
    priority: 55,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible XSS via indirect sink call (call/apply/optional chaining)',
    when: anyFieldMatches(PAYLOAD_FIELDS, XSS_INDIRECT_CALL, [
      'alert',
      'prompt',
      'confirm',
      'eval',
    ]),
  },
  {
    id: 'preset-xss-breakout-call',
    priority: 55,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible XSS breakout from a string/attribute into a sink call',
    when: anyFieldMatches(PAYLOAD_FIELDS, XSS_BREAKOUT_CALL, [
      'alert',
      'prompt',
      'confirm',
      'eval',
    ]),
  },
  {
    id: 'preset-xss-eval-alert',
    priority: 55,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Possible eval/alert XSS probe',
    when: anyFieldMatches(['query', 'body'], EVAL_ALERT),
  },
];
