import type { WafRule } from '@/domain/rules';
import {
  PAYLOAD_FIELDS,
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
const SQLI_VERSIONED_COMMENT = /\/\*!(?:\d{5})?|\/\*%21/i;

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
 * Whitespace-free nested subquery — `(select(0)from(select(sleep(1)))x)`,
 * `union select(1)from(users)`. {@link SQLI_SELECT_FROM} needs a word / quote
 * after `FROM`; the tight `from(` form puts a paren there instead and slips
 * past it. Kept at `high`: a `select(…)from(` shape can appear in posted SQL.
 */
const SQLI_COMPACT_SUBQUERY = /\bselect\s*\([\s\S]{0,80}?\bfrom\s*\(/i;

/**
 * MySQL / MariaDB JSON accessors used to read data during injection
 * (`JSON_EXTRACT(`, `JSON_KEYS(`, `JSON_ARRAYAGG(` …). These need no `FROM`,
 * so {@link SQLI_SELECT_FROM} never sees them. Kept at `high`: `json_*` tokens
 * can surface in ORM logs or SQL-adjacent prose.
 */
const SQLI_JSON_FUNCTION =
  /\bjson_(?:extract|keys|depth|contains(?:_path)?|search|value|query|arrayagg|objectagg|table|valid|unquote|length|overlaps|storage_(?:size|free)|merge(?:_preserve|_patch)?)\s*\(/i;

/**
 * MongoDB driver / shell method calls in request input —
 * `db.users.find({$where…})`, `db.coll.aggregate(`. A JS-object payload that
 * carries no `$operator` string still exposes the driver call. Kept at `high`:
 * code-sharing apps may legitimately post this.
 */
const NOSQL_DRIVER_API =
  /\bdb\.\w{1,40}\.(?:find(?:One)?(?:AndModify|AndUpdate|AndDelete|AndReplace)?|insert(?:One|Many)?|update(?:One|Many)?|delete(?:One|Many)?|replaceOne|remove|save|aggregate|mapReduce|count(?:Documents)?|distinct|bulkWrite)\s*\(/i;

/**
 * MongoDB / NoSQL operator injection — the classic `{"$ne": null}` auth
 * bypass, in JSON body form and in the bracketed query-string form that
 * Express' extended parser produces (CRS 942290).
 */
const NOSQL_OPERATOR =
  /(?:["']\s*\$(?:where|ne|gt|gte|lt|lte|regex|expr|function|nin|in|all|elemMatch|jsonSchema)\s*["']\s*:|\[\s*\$(?:where|ne|gt|gte|lt|lte|regex|expr|function)\s*\]|(?:^|[&[])\$(?:where|ne|gt|gte|lt|lte|regex|expr|function)\s*[=\]])/i;

/**
 * NoSQL operator injection in bare (unquoted) form — `$where: '…'`,
 * `, $or: [`, `{$gt: ''}`. {@link NOSQL_OPERATOR} only matches a *quoted*
 * `"$ne":` key or a bracketed `[$ne]`; MongoDB-shell / JS-object payloads and
 * their query-string variants drop the quotes, so they need their own arm.
 * The leading `[,{[(]` (or start of value for `$where:`) keeps ordinary
 * `${var}` template interpolation — where `$` is followed by `{`, not preceded
 * by a bracket — from matching.
 */
const NOSQL_STRING =
  /\$where\s*:|(?:^|[,{[(])\s*\$(?:or|and|nor|not|gt|gte|lt|lte|ne|nin|in|regex|expr|function|elemMatch|jsonSchema)\s*:/i;

/**
 * Keyword-free numeric boolean test — `AND 1=1`, `OR 6522=6522`,
 * `123) AND 12=12`. {@link SQLI_CLASSIC} only covers `OR <n>=<n>` separated by
 * whitespace; sqlmap's default boolean-blind probe and GoTestWAF's `) AND n=n`
 * payloads use `AND` or a tight closing paren and carry no quote or SQL
 * keyword, so every other arm misses them. Kept at `high`: a bare `n=n` after
 * `and`/`or` can surface in free-form or mathematical text.
 */
const SQLI_BOOLEAN_EQUALITY =
  /\b(?:AND|OR|XOR)\b\s*\(?\s*\d{1,6}\s*(?:=|!=|<=>|>=|<=)\s*\d{1,6}/i;

/**
 * Blind / boolean / enumeration structure probes (CRS 942130 / 942210).
 * Kept at `high`: `ORDER BY 1` and `CASE WHEN` can legitimately appear in
 * reporting or query-builder payloads. The trailing-comment arm requires the
 * `--` to close the value, so Markdown headings and `"#fff"` do not match.
 */
const SQLI_BLIND =
  /(?:\b(?:ORDER|GROUP)\s+BY\s+\d{1,4}\s*(?:--|#|;|\/\*|\)|$)|\bHAVING\b\s*\d{1,4}\s*=\s*\d{1,4}|\bCASE\s+WHEN\b[\s\S]{0,80}?\bTHEN\b|\b(?:AND|OR)\s*\(\s*SELECT\b|\bIF\s*\(\s*(?:\d{1,4}\s*[=<>]|ASCII\s*\(|SUBSTR)|\bCHAR\s*\(\s*\d{1,3}(?:\s*,\s*\d{1,3}){3,}\s*\)|['"`]\s*\)*\s*(?:;\s*)?--(?:\s|$))/i;

/**
 * MongoDB `$where` JavaScript denial of service — an infinite `while(true)` /
 * `for(;;)` busy loop smuggled into a server-side predicate. `paranoid`: a
 * posted code snippet can carry the same loop, and the prefilter (`while` /
 * `for(`) keeps the regex off every clean request.
 */
const NOSQL_TIMEBOMB =
  /\bwhile\s*\(\s*(?:true|1|!0|0x1)\s*\)|\bfor\(\s*;\s*;\s*\)/i;

/**
 * MongoDB `$where` *timing* denial-of-service — a busy-wait that spins until a
 * wall-clock delta elapses: `var d = new Date(); do{ c = new Date(); }while(c-d
 * < 10000)`. {@link NOSQL_TIMEBOMB} only matches the infinite `while(true)` /
 * `for(;;)` forms; this loop carries a *real* condition (`c - d`), so it needs
 * its own arm. The signature is a `new Date()` read feeding a subtraction
 * inside a loop condition. `high` (not `paranoid` like {@link NOSQL_TIMEBOMB}):
 * GoTestWAF exercises it at that level, and the two-`Date()` + `while(a - b)`
 * shape is characteristic enough — a posted benchmark snippet is the only
 * realistic collision, and the `new date` prefilter keeps the regex off every
 * clean request.
 */
const NOSQL_TIME_DOS =
  /\bnew\s+Date\s*\([^)]*\)[\s\S]{0,120}?\bwhile\s*\(\s*[\w.]+\s*-\s*[\w.]+/i;

/**
 * T-SQL (MSSQL) local-variable declaration — `DECLARE @c varchar(255)`,
 * `DECLARE @x int` — the opening move of a stacked-query out-of-band payload
 * (`DECLARE @c …; SELECT @c = 'ping ' + master.sys.fn_varbintohexstr(…)`).
 * `paranoid`: `DECLARE @var <type>` is unambiguously T-SQL, but a code-sharing
 * or DBA-tooling app can legitimately post a stored-procedure body, so the
 * highest-FP tier owns it; the `declare` prefilter keeps it off clean traffic.
 */
const MSSQL_DECLARE =
  /\bDECLARE\s+@\w+\s+(?:var|n)?(?:char|binary)\b|\bDECLARE\s+@\w+\s+(?:big|small|tiny)?int\b|\bDECLARE\s+@\w+\s+(?:table|cursor|xml|money|bit|float|real|uniqueidentifier|date(?:time(?:2|offset)?|)?|time)\b/i;

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
    when: anyFieldMatches(URL_FIELDS, SQLI_VERSIONED_COMMENT, ['/*!', '/*%21']),
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
    id: 'preset-sqli-nosql-string',
    priority: 50,
    action: 'block',
    minLevel: 'balanced',
    reason: 'Possible NoSQL operator injection (unquoted form)',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, NOSQL_STRING, ['$']),
  },
  {
    id: 'preset-sqli-boolean-equality',
    priority: 52,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible boolean-based blind SQL injection (numeric equality)',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, SQLI_BOOLEAN_EQUALITY, ['=']),
  },
  {
    id: 'preset-sqli-compact-subquery',
    priority: 52,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible SQL injection via whitespace-free nested subquery',
    when: anyFieldMatches(URL_FIELDS, SQLI_COMPACT_SUBQUERY, ['select']),
  },
  {
    id: 'preset-sqli-json-functions',
    priority: 52,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible SQL injection using JSON accessor functions',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, SQLI_JSON_FUNCTION, ['json_']),
  },
  {
    id: 'preset-sqli-nosql-driver-api',
    priority: 52,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible NoSQL injection via MongoDB driver API call',
    when: anyFieldMatches(['query', 'body', 'path'], NOSQL_DRIVER_API, ['db.']),
  },
  {
    id: 'preset-sqli-blind',
    priority: 52,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible blind / enumeration SQL injection',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, SQLI_BLIND),
  },
  {
    id: 'preset-sqli-nosql-time-dos',
    priority: 54,
    action: 'block',
    minLevel: 'high',
    reason: 'Possible NoSQL $where timing denial-of-service loop',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, NOSQL_TIME_DOS, ['new date']),
  },
  {
    id: 'preset-sqli-nosql-timebomb',
    priority: 54,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Possible NoSQL $where JavaScript denial-of-service loop',
    when: anyFieldMatches(PAYLOAD_FIELDS, NOSQL_TIMEBOMB, ['while', 'for(']),
  },
  {
    id: 'preset-sqli-mssql-declare',
    priority: 56,
    action: 'block',
    minLevel: 'paranoid',
    reason: 'Possible stacked-query SQL injection via T-SQL DECLARE',
    when: anyFieldMatches(PAYLOAD_PATH_FIELDS, MSSQL_DECLARE, ['declare']),
  },
];
