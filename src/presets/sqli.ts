import type { WafRule } from '@/domain/rules';

/**
 * Classic high-signal SQLi (UNION/boolean equality).
 * Active from `low`.
 */
const SQLI_CLASSIC =
  /(?:\bUNION\b\s+(?:ALL\s+)?\bSELECT\b|\b(?:INTERSECT|EXCEPT)\b\s+\bSELECT\b|\bOR\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+|\uff07)/i;

/**
 * Time-based / stacked / schema probes — higher FP risk on noisy apps.
 * Active from `high`.
 */
const SQLI_ADVANCED =
  /(?:\bAND\b\s+EXTRACTVALUE\b|\b(?:SLEEP|BENCHMARK|WAITFOR|RLIKE)\b\s*[\s(]|\bINFORMATION_SCHEMA\b|;\s*(?:SELECT|DECLARE|WAITFOR|CREATE)\b|(?:^|[\s)])(?:OR|AND)\s+(?:SELECT|UNION|DECLARE|INSERT|UPDATE|DELETE|WAITFOR)\b)/i;

function sqliFieldRules(
  field: 'query' | 'body' | 'path' | 'cookies',
  pattern: RegExp,
  kind: 'classic' | 'advanced',
): WafRule {
  const minLevel = kind === 'classic' ? 'low' : 'high';
  const label = kind === 'classic' ? 'SQL injection' : 'advanced SQL injection';
  return {
    id: `preset-sqli-${kind}-${field}`,
    priority: 50,
    action: 'block',
    minLevel,
    reason: `Possible ${label} in ${field === 'query' ? 'query string' : field}`,
    when: { field, matches: pattern },
  };
}

const FIELDS = ['query', 'body', 'path', 'cookies'] as const;

/** SQL injection patterns across query, path, body and cookies. */
export const sqliRules: readonly WafRule[] = [
  ...FIELDS.map((field) => sqliFieldRules(field, SQLI_CLASSIC, 'classic')),
  ...FIELDS.map((field) => sqliFieldRules(field, SQLI_ADVANCED, 'advanced')),
];
