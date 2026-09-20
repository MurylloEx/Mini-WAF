import type { WafRule } from '@/domain/rules';
import {
  PAYLOAD_PATH_FIELDS,
  URL_FIELDS,
  anyFieldMatches,
} from '@/presets/fields';

/**
 * Classic high-signal SQLi (UNION/boolean equality).
 * Active from `low`.
 */
const SQLI_CLASSIC =
  /(?:\bUNION\b\s+(?:ALL\s+)?\bSELECT\b|\b(?:INTERSECT|EXCEPT)\b\s+\bSELECT\b|\bOR\b\s+['"]?\d+['"]?\s*=\s*['"]?\d+|＇)/i;

/**
 * Time-based / stacked / schema probes — higher FP risk on noisy apps.
 * Active from `high`.
 */
const SQLI_ADVANCED =
  /(?:\bAND\b\s+EXTRACTVALUE\b|\b(?:SLEEP|BENCHMARK|WAITFOR|RLIKE)\b\s*[\s(]|\bINFORMATION_SCHEMA\b|;\s*(?:SELECT|DECLARE|WAITFOR|CREATE)\b|(?:^|[\s)])(?:OR|AND)\s+(?:SELECT|UNION|DECLARE|INSERT|UPDATE|DELETE|WAITFOR)\b)/i;

/**
 * DBMS fingerprinting plus file / command primitives (CRS 942140 / 942190).
 * These tokens have no meaning in ordinary user input, so they stay at `low`.
 */
const SQLI_DBMS_PRIMITIVES =
  /(?:@@(?:version|datadir|hostname|basedir|tmpdir)\b|\bload_file\s*\(|\binto\s+(?:out|dump)file\b|\bxp_cmdshell\b|\bsp_executesql\b|\bpg_sleep\s*\(|\bdbms_pipe\s*\.|\butl_inaddr\b|\bsys_context\s*\(|\bopenrowset\s*\(|\bsysdatabases\b|\bsysusers\b)/i;

/**
 * MySQL versioned comment used to smuggle keywords past naive filters
 * (CRS 942500). Scanned on URL-borne fields only: minified JavaScript keeps
 * `/*!` license banners, so bodies would false-positive.
 */
const SQLI_VERSIONED_COMMENT = /\/\*!(?:\d{5})?/;

/**
 * Quoted tautologies that the numeric `OR 1=1` pattern misses:
 * `' OR 'a'='a`, `") OR (1=1`, `' || '1'='1`.
 */
const SQLI_TAUTOLOGY =
  /['"`]\s*\)?\s*(?:OR|AND|XOR|\|\||&&)\s*\(?\s*['"`]?[\w.]{1,24}['"`]?\s*(?:=|<>|!=|<=>|\bLIKE\b)\s*['"`]?[\w.]{1,24}['"`]?/i;

/**
 * A full `SELECT … FROM <identifier>` projection reaching the server through
 * the URL or a cookie is injection in practice (CRS 942360).
 */
const SQLI_SELECT_FROM = /\bSELECT\b[\s\S]{1,160}?\bFROM\b\s*[\w."`[]/i;

/**
 * MongoDB / NoSQL operator injection — the classic `{"$ne": null}` auth
 * bypass, in JSON body form and in the bracketed query-string form that
 * Express' extended parser produces (CRS 942290).
 */
const NOSQL_OPERATOR =
  /(?:["']\s*\$(?:where|ne|gt|gte|lt|lte|regex|expr|function|nin|in|all|elemMatch|jsonSchema)\s*["']\s*:|\[\s*\$(?:where|ne|gt|gte|lt|lte|regex|expr|function)\s*\]|(?:^|[&[])\$(?:where|ne|gt|gte|lt|lte|regex|expr|function)\s*[=\]])/i;

/**
 * Blind / boolean / enumeration structure probes (CRS 942130 / 942210).
 * Kept at `high`: `ORDER BY 1` and `CASE WHEN` can legitimately appear in
 * reporting or query-builder payloads. The trailing-comment arm requires the
 * `--` to close the value, so Markdown headings and `"#fff"` do not match.
 */
const SQLI_BLIND =
  /(?:\b(?:ORDER|GROUP)\s+BY\s+\d{1,4}\s*(?:--|#|;|\/\*|\)|$)|\bHAVING\b\s*\d{1,4}\s*=\s*\d{1,4}|\bCASE\s+WHEN\b[\s\S]{0,80}?\bTHEN\b|\b(?:AND|OR)\s*\(\s*SELECT\b|\bIF\s*\(\s*(?:\d{1,4}\s*[=<>]|ASCII\s*\(|SUBSTR)|\bCHAR\s*\(\s*\d{1,3}(?:\s*,\s*\d{1,3}){3,}\s*\)|['"`]\s*\)*\s*(?:;\s*)?--(?:\s|$))/i;

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

/** SQL / NoSQL injection patterns across query, path, body and cookies. */
export const sqliRules: readonly WafRule[] = [
  ...FIELDS.map((field) => sqliFieldRules(field, SQLI_CLASSIC, 'classic')),
  ...FIELDS.map((field) => sqliFieldRules(field, SQLI_ADVANCED, 'advanced')),
  {
    id: 'preset-sqli-dbms-primitives',
    priority: 48,
    action: 'block',
    minLevel: 'low',
    reason: 'SQL injection using DBMS file or command primitives',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, SQLI_DBMS_PRIMITIVES, [
      '@@',
      'load_file',
      'outfile',
      'dumpfile',
      'xp_cmdshell',
      'sp_executesql',
      'pg_sleep',
      'dbms_pipe',
      'utl_inaddr',
      'sys_context',
      'openrowset',
      'sysdatabases',
      'sysusers',
    ]),
  },
  {
    id: 'preset-sqli-versioned-comment',
    priority: 48,
    action: 'block',
    minLevel: 'low',
    reason: 'MySQL versioned comment used to obfuscate SQL',
    when: anyFieldMatches(URL_FIELDS, SQLI_VERSIONED_COMMENT, ['/*!']),
  },
  {
    id: 'preset-sqli-tautology',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible SQL injection tautology',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, SQLI_TAUTOLOGY),
  },
  {
    id: 'preset-sqli-select-from',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'SQL SELECT … FROM projection in URL-borne input',
    when: anyFieldMatches(URL_FIELDS, SQLI_SELECT_FROM, ['select']),
  },
  {
    id: 'preset-sqli-nosql-operator',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible NoSQL (MongoDB) operator injection',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, NOSQL_OPERATOR, ['$']),
  },
  {
    id: 'preset-sqli-blind',
    priority: 52,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible blind / enumeration SQL injection',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, SQLI_BLIND),
  },
];
