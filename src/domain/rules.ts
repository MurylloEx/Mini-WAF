/**
 * Declarative WAF rule DSL.
 *
 * Example:
 * ```ts
 * const rules: WafRule[] = [
 *   {
 *     id: 'block-sqli',
 *     when: { field: 'query.id', matches: /('|OR\s+1=1)/i },
 *     action: 'block',
 *     reason: 'Possible SQL injection',
 *     minLevel: 'low',
 *   },
 * ];
 * ```
 */

import type { ProtectionLevel } from '@/domain/levels';
import type { WafLoggingSetting } from '@/logging/port';

export type { ProtectionLevel } from '@/domain/levels';
export {
  PROTECTION_LEVELS,
  DEFAULT_PROTECTION_LEVEL,
  DEFAULT_RULE_MIN_LEVEL,
  protectionLevelRank,
  isLevelActive,
  isProtectionLevel,
} from '@/domain/levels';

/** Pure predicate for field matching (e.g. Host IP literal checks). */
export type MatchPredicate = (value: string) => boolean;

/** Match target: literal, regex, string list, or pure predicate. */
export type MatchPattern =
  | string
  | RegExp
  | readonly string[]
  | MatchPredicate;
/**
 * Supported request fields.
 * Nested accessors use dotted paths (`query.id`, `headers.user-agent`).
 */
export type WafField =
  | 'ip'
  | 'method'
  | 'path'
  | 'url'
  | 'body'
  | 'files'
  | 'query'
  | 'headers'
  | 'cookies'
  | `query.${string}`
  | `headers.${string}`
  | `cookies.${string}`;

export interface RateLimitSpec {
  /** Maximum hits inside the window before the condition matches. */
  readonly max: number;
  /** Sliding window length in milliseconds. */
  readonly windowMs: number;
  /**
   * Optional key override. Defaults to the resolved field value
   * (typically the client IP when `field: 'ip'`).
   */
  readonly keyPrefix?: string;
}

/** Match a single request field. */
export interface FieldCondition {
  readonly field: WafField;
  /** Regex, exact string, or list of strings (OR). */
  readonly matches?: MatchPattern;
  /** Case-sensitive exact equality. */
  readonly equals?: string;
  /** Case-insensitive substring. */
  readonly includes?: string;
  /** When set, condition matches after exceeding the rate limit. */
  readonly rateLimit?: RateLimitSpec;
  /**
   * Cheap literal gate evaluated **before** `matches` / `equals` / `includes`.
   *
   * A candidate value only reaches the pattern when it contains at least one
   * of these substrings (case-insensitive). Use it whenever every payload the
   * pattern can match necessarily contains a fixed literal — `indexOf` over a
   * large body is far cheaper than a regex pass, and the field's lowercased
   * form is computed once per request and shared by every rule.
   *
   * Leave it out when unsure: an incomplete `requires` list silently narrows
   * the rule, because a value missing every literal is never matched.
   */
  readonly requires?: readonly string[];
}

/** Logical AND of nested conditions. */
export interface AllCondition {
  readonly all: readonly WafCondition[];
}

/** Logical OR of nested conditions. */
export interface AnyOfCondition {
  readonly anyOf: readonly WafCondition[];
}

/** Negate a nested condition. */
export interface NotCondition {
  readonly not: WafCondition;
}

export type WafCondition =
  | FieldCondition
  | AllCondition
  | AnyOfCondition
  | NotCondition;

export type WafAction = 'allow' | 'block' | 'log';

export interface WafRule {
  readonly id: string;
  readonly when: WafCondition;
  readonly action: WafAction;
  /** Human-readable reason used in logs / block responses. */
  readonly reason?: string;
  /** Defaults to true. */
  readonly enabled?: boolean;
  /**
   * Lower numbers run first. Defaults to 100.
   * `allow` rules that match short-circuit evaluation.
   */
  readonly priority?: number;
  /**
   * Minimum protection level required for this rule to run.
   * Defaults to `'low'` (active at every configured level).
   * Semântica: regra ativa se `config.level >= minLevel`.
   */
  readonly minLevel?: ProtectionLevel;
}

export type WafPresetName =
  | 'default'
  | 'sqli'
  | 'xss'
  | 'scanners'
  | 'path-traversal'
  | 'rfi'
  | 'rce'
  | 'protocol';

export interface WafConfig {
  /**
   * Protection level. Only rules with `minLevel <= level` are applied.
   * Default: `'balanced'`.
   */
  readonly level?: ProtectionLevel;
  /** Custom rules evaluated after (or instead of) presets. */
  readonly rules?: readonly WafRule[];
  /** Built-in rule packs to include. */
  readonly presets?: readonly WafPresetName[];
  /**
   * Optional allowlist of rule ids.
   * When present and non-empty, only those ids remain after presets + custom
   * merge and level filtering (see `buildRuleList` order in the engine).
   */
  readonly enabledRuleIds?: readonly string[];
  /**
   * Drop rules whose `id` is listed. Applied after presets + custom merge,
   * level filter, and optional `enabledRuleIds` allowlist.
   */
  readonly disabledRuleIds?: readonly string[];
  /** HTTP status used on block. Default: 403. */
  readonly blockStatusCode?: number;
  /** Response body used on block. Default: "Forbidden". */
  readonly blockBody?: string;
  /**
   * Logging is **off by default** (no I/O, no formatting).
   * - `false` / omitted — silent
   * - `true` — plain console at level `info` (blocks + audit)
   * - `{ level?, sink? }` — verbosity + optional injectable {@link import('../logging/port').WafLogger}
   */
  readonly logging?: WafLoggingSetting;
  /**
   * Cap length of each field value scanned by matchers (body, query, headers, …).
   * Longer values are truncated for matching / rate-limit key material only
   * (the HTTP body itself is not rejected).
   * Default: `8192`. Set `0` for unlimited (not recommended in production).
   */
  readonly maxFieldLength?: number;
  /**
   * Yield to the event loop every N rules during evaluation so large rule sets
   * do not starve other work. Default: `32`. Set `0` to disable yielding.
   * Packs smaller than this interval skip yielding (sync scan path).
   * Safe with `rateLimit` rules: counters live in a shared in-place store.
   */
  readonly ruleYieldEvery?: number;
  /**
   * Cap on distinct rate-limit keys (typically per-IP buckets). Cold keys are
   * evicted LRU-style when the cap is exceeded. Default: `10000`.
   */
  readonly maxRateLimitKeys?: number;
  /**
   * Optional short-TTL LRU of allow/block decisions keyed by a request fingerprint
   * (method + path + IP + query + UA + body hash).
   *
   * **Disabled automatically** when any active rule uses `rateLimit` so DoS
   * counters always advance. Default: off.
   */
  readonly decisionCache?: {
    readonly max?: number;
    readonly ttlMs?: number;
  };
}

export type WafDecision = 'allow' | 'block';

export interface WafEvaluationResult {
  readonly decision: WafDecision;
  readonly matchedRule: WafRule | undefined;
  readonly reason: string | undefined;
  /** Rules with action `log` that matched during evaluation. */
  readonly loggedRules: readonly WafRule[];
}

/** Type guard: whether a condition is a single-field match (`field`). */
export function isFieldCondition(
  condition: WafCondition,
): condition is FieldCondition {
  return 'field' in condition;
}

/** Type guard: whether a condition is a logical AND (`all`). */
export function isAllCondition(
  condition: WafCondition,
): condition is AllCondition {
  return 'all' in condition;
}

/** Type guard: whether a condition is a logical OR (`anyOf`). */
export function isAnyOfCondition(
  condition: WafCondition,
): condition is AnyOfCondition {
  return 'anyOf' in condition;
}

/** Type guard: whether a condition is a negation (`not`). */
export function isNotCondition(
  condition: WafCondition,
): condition is NotCondition {
  return 'not' in condition;
}
