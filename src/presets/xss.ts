import type { WafRule } from '@/domain/rules';

/** Reflected / stored XSS and SSI-style payloads. */
export const xssRules: readonly WafRule[] = [
  {
    id: 'preset-xss-query',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible XSS in query string',
    when: {
      field: 'query',
      matches:
        /(<\s*script\b|(?:java|vb)script\s*:|on\w+\s*=|<\s*img\b[^>]*\bonerror\b|<\s*svg\b[^>]*\bonload\b|\bdocument\s*\.\s*(?:cookie|location|write(?:ln)?)\b)/i,
    },
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
        /(<\s*script\b|(?:java|vb)script\s*:|on\w+\s*=|<\s*img\b[^>]*\bonerror\b|\bdocument\s*\.\s*(?:cookie|write(?:ln)?)\b)/i,
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
    id: 'preset-ssi-injection',
    priority: 50,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible SSI command injection',
    when: {
      anyOf: [
        {
          field: 'query',
          matches:
            /<!--#\s*(?:config|echo|exec|flastmod|fsize|include)\b/i,
        },
        {
          field: 'body',
          matches:
            /<!--#\s*(?:config|echo|exec|flastmod|fsize|include)\b/i,
        },
      ],
    },
  },
  {
    id: 'preset-xss-generic-tags',
    priority: 55,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Generic HTML tag in request (paranoid XSS)',
    when: {
      anyOf: [
        {
          field: 'query',
          matches: /<\s*(?:iframe|object|embed|link|meta|base|form)\b/i,
        },
        {
          field: 'body',
          matches: /<\s*(?:iframe|object|embed|link|meta|base|form)\b/i,
        },
      ],
    },
  },
  {
    id: 'preset-xss-eval-alert',
    priority: 55,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Possible eval/alert XSS probe',
    when: {
      anyOf: [
        {
          field: 'query',
          matches: /\b(?:eval|alert|prompt|confirm)\s*\(/i,
        },
        {
          field: 'body',
          matches: /\b(?:eval|alert|prompt|confirm)\s*\(/i,
        },
      ],
    },
  },
];
