import type {
  WafConfig,
  WafDecision,
  WafEvaluationResult,
  WafRule,
} from '@/domain/rules';
import type { ProtectionLevel } from '@/domain/levels';
import {
  DEFAULT_PROTECTION_LEVEL,
  DEFAULT_RULE_MIN_LEVEL,
  isLevelActive,
} from '@/domain/levels';
import type { WafHttpContext } from '@/domain/context';
import {
  evaluateCondition,
  type EvaluateOptions,
  type RateLimitInfo,
} from '@/engine/evaluate';
import {
  emptyRateLimitState,
  RateLimitStore,
  DEFAULT_MAX_RATE_LIMIT_KEYS,
  type RateLimitPort,
} from '@/engine/rate-limit';
import { resolvePresets } from '@/presets';
import type { WafLogger } from '@/logging/port';
import {
  isLogLevelActive,
  pickLoggerSink,
  resolveLogging,
  type ResolvedLogging,
  type WafLogLevel,
} from '@/logging/port';
import { createConsoleLogger, silentLogger } from '@/logging/logger';
import {
  filterRulesByDisabledIds,
  filterRulesByEnabledIds,
} from '@/engine/rule-filter';
import { conditionHasRateLimit, rulesHaveRateLimit } from '@/engine/condition-utils';
import { requestFingerprint } from '@/engine/fingerprint';
import { normalizeRules } from '@/engine/normalize-condition';
import type { WafField } from '@/domain/rules';
import { LruCache } from '@/utils/lru';

export interface WafEngineOptions {
  /** Inject a shared rate-limit store (tests / multi-instance). */
  readonly rateLimitStore?: RateLimitStore;
  /**
   * Override the logging sink when logging is enabled.
   * Ignored while `config.logging` is off (default) — no logger calls.
   */
  readonly logger?: WafLogger;
}

export interface ResolvedDecisionCache {
  readonly max: number;
  readonly ttlMs: number;
}

export interface ResolvedPerformance {
  readonly maxFieldLength: number;
  readonly ruleYieldEvery: number;
  readonly maxRateLimitKeys: number;
  readonly decisionCache: ResolvedDecisionCache | undefined;
}

export interface ResolvedWafConfig {
  readonly level: ProtectionLevel;
  readonly rules: readonly WafRule[];
  readonly presets: readonly NonNullable<WafConfig['presets']>[number][];
  readonly blockStatusCode: number;
  readonly blockBody: string;
  readonly logging: ResolvedLogging;
  readonly performance: ResolvedPerformance;
}

export interface WafEngine {
  readonly rules: readonly WafRule[];
  readonly config: ResolvedWafConfig;
  readonly rateLimitStore: RateLimitStore;
  handle(ctx: WafHttpContext): Promise<WafEvaluationResult>;
}

const DEFAULT_RULE_YIELD_EVERY = 32;
/**
 * Production-safe default: truncate each scanned field before matchers/regex.
 * `0` still means unlimited when set explicitly. Keeps oversized-header
 * presets (≥2048) working while bounding catastrophic regex cost on huge bodies.
 */
export const DEFAULT_MAX_FIELD_LENGTH = 8_192;
const DEFAULT_DECISION_CACHE_MAX = 256;
const DEFAULT_DECISION_CACHE_TTL_MS = 1_000;
/** Body slice length used only for decision-cache fingerprints. */
const FINGERPRINT_BODY_MAX = 4_096;

function sortRules(rules: readonly WafRule[]): readonly WafRule[] {
  return [...rules]
    .filter((rule) => rule.enabled !== false)
    .sort((a, b) => (a.priority ?? 100) - (b.priority ?? 100));
}

/** Keep rules whose `minLevel` is satisfied by the configured protection level. */
export function filterRulesByLevel(
  rules: readonly WafRule[],
  level: ProtectionLevel,
): readonly WafRule[] {
  return rules.filter((rule) =>
    isLevelActive(level, rule.minLevel ?? DEFAULT_RULE_MIN_LEVEL),
  );
}

/**
 * Build the final rule list (immutable). Order:
 * 1. resolve presets + custom rules
 * 2. filter by protection level (`minLevel`)
 * 3. apply `enabledRuleIds` allowlist (if set and non-empty)
 * 4. apply `disabledRuleIds`
 * 5. drop `enabled: false` and sort by priority
 */
export function buildRuleList(config: WafConfig): readonly WafRule[] {
  const level = config.level ?? DEFAULT_PROTECTION_LEVEL;
  const fromPresets = resolvePresets(config.presets ?? []);
  const custom = config.rules ?? [];
  return normalizeRules(
    sortRules(
      filterRulesByDisabledIds(
        filterRulesByEnabledIds(
          filterRulesByLevel([...fromPresets, ...custom], level),
          config.enabledRuleIds,
        ),
        config.disabledRuleIds,
      ),
    ),
  );
}

function resolvePerformance(config: WafConfig): ResolvedPerformance {
  const decision = config.decisionCache;
  return {
    maxFieldLength: config.maxFieldLength ?? DEFAULT_MAX_FIELD_LENGTH,
    ruleYieldEvery: config.ruleYieldEvery ?? DEFAULT_RULE_YIELD_EVERY,
    maxRateLimitKeys: config.maxRateLimitKeys ?? DEFAULT_MAX_RATE_LIMIT_KEYS,
    decisionCache:
      decision === undefined
        ? undefined
        : {
            max: decision.max ?? DEFAULT_DECISION_CACHE_MAX,
            ttlMs: decision.ttlMs ?? DEFAULT_DECISION_CACHE_TTL_MS,
          },
  };
}

function resolveConfig(
  config: WafConfig,
  rules: readonly WafRule[],
): ResolvedWafConfig {
  return {
    level: config.level ?? DEFAULT_PROTECTION_LEVEL,
    rules,
    presets: config.presets ? [...config.presets] : [],
    blockStatusCode: config.blockStatusCode ?? 403,
    blockBody: config.blockBody ?? 'Forbidden',
    logging: resolveLogging(config.logging),
    performance: resolvePerformance(config),
  };
}

function resolveEngineLogger(
  config: WafConfig,
  logging: ResolvedLogging,
  optionsLogger: WafLogger | undefined,
): WafLogger {
  if (!logging.enabled) {
    return silentLogger;
  }
  return pickLoggerSink(
    config.logging,
    optionsLogger,
    createConsoleLogger(),
  );
}

function emitIfLevel(
  logging: ResolvedLogging,
  minimum: WafLogLevel,
  emit: () => void,
): void {
  if (!logging.enabled) {
    return;
  }
  if (!isLogLevelActive(logging.level, minimum)) {
    return;
  }
  emit();
}

export interface ScanState {
  readonly loggedRules: readonly WafRule[];
  readonly blockCandidate: WafRule | undefined;
  readonly allowRule: WafRule | undefined;
  readonly lastRateLimitInfo: RateLimitInfo | undefined;
}

export interface ScanOptions {
  readonly evaluate: EvaluateOptions;
  /** Yield every N rules; `0` disables. */
  readonly ruleYieldEvery: number;
  /** Shared rate-limit store (hits apply immediately / atomically per key). */
  readonly rateLimits: RateLimitPort;
}

function initialScanState(): ScanState {
  return {
    loggedRules: [],
    blockCandidate: undefined,
    allowRule: undefined,
    lastRateLimitInfo: undefined,
  };
}

function shouldSkipRule(rule: WafRule, state: ScanState): boolean {
  // First matching block wins for the decision; later pure blocks are redundant.
  // Still evaluate allow / log / anything with rateLimit side effects.
  return (
    state.blockCandidate !== undefined &&
    rule.action === 'block' &&
    !conditionHasRateLimit(rule.when)
  );
}

function applyMatchedRule(state: ScanState, rule: WafRule): ScanState {
  if (rule.action === 'allow') {
    return { ...state, allowRule: rule };
  }
  if (rule.action === 'log') {
    return {
      ...state,
      loggedRules: [...state.loggedRules, rule],
    };
  }
  if (rule.action === 'block' && state.blockCandidate === undefined) {
    return { ...state, blockCandidate: rule };
  }
  return state;
}

function advanceOneRule(
  ctx: WafHttpContext,
  rule: WafRule,
  state: ScanState,
  options: ScanOptions,
): ScanState {
  if (shouldSkipRule(rule, state)) {
    return state;
  }

  const evaluation = evaluateCondition(
    ctx,
    rule.when,
    options.rateLimits,
    options.evaluate,
  );

  const withRate = {
    ...state,
    lastRateLimitInfo: evaluation.rateLimitInfo ?? state.lastRateLimitInfo,
  };

  if (!evaluation.matched) {
    return withRate;
  }

  return applyMatchedRule(withRate, rule);
}

function yieldToEventLoop(): Promise<void> {
  return new Promise((resolve) => {
    setImmediate(resolve);
  });
}

function scanRulesFrom(
  ctx: WafHttpContext,
  rules: readonly WafRule[],
  index: number,
  state: ScanState,
  options: ScanOptions,
  endExclusive: number = rules.length,
): ScanState {
  if (
    index >= endExclusive ||
    index >= rules.length ||
    state.allowRule !== undefined
  ) {
    return state;
  }

  const rule = rules[index];
  if (rule === undefined) {
    return scanRulesFrom(ctx, rules, index + 1, state, options, endExclusive);
  }

  const next = advanceOneRule(ctx, rule, state, options);
  if (next.allowRule !== undefined) {
    return next;
  }

  return scanRulesFrom(ctx, rules, index + 1, next, options, endExclusive);
}

/**
 * Effective yield interval: skip yielding entirely when the pack is smaller
 * than `ruleYieldEvery` (no fairness benefit, only Promise/setImmediate cost).
 */
function effectiveRuleYieldEvery(
  ruleCount: number,
  ruleYieldEvery: number,
): number {
  if (ruleYieldEvery <= 0 || ruleCount < ruleYieldEvery) {
    return 0;
  }
  return ruleYieldEvery;
}

async function scanRulesChunkedAsync(
  ctx: WafHttpContext,
  rules: readonly WafRule[],
  index: number,
  state: ScanState,
  options: ScanOptions,
  yieldEvery: number,
): Promise<ScanState> {
  if (index >= rules.length || state.allowRule !== undefined) {
    return state;
  }

  const endExclusive = Math.min(index + yieldEvery, rules.length);
  const next = scanRulesFrom(ctx, rules, index, state, options, endExclusive);
  if (next.allowRule !== undefined || endExclusive >= rules.length) {
    return next;
  }

  await yieldToEventLoop();
  return scanRulesChunkedAsync(
    ctx,
    rules,
    endExclusive,
    next,
    options,
    yieldEvery,
  );
}

async function scanRulesFromAsync(
  ctx: WafHttpContext,
  rules: readonly WafRule[],
  state: ScanState,
  options: ScanOptions,
): Promise<ScanState> {
  const yieldEvery = effectiveRuleYieldEvery(
    rules.length,
    options.ruleYieldEvery,
  );

  // Small packs (or yield disabled): one synchronous pass — no Promise chain.
  if (yieldEvery === 0) {
    return scanRulesFrom(ctx, rules, 0, state, options);
  }

  // Large packs: sync chunks of `yieldEvery` rules, then setImmediate.
  return scanRulesChunkedAsync(ctx, rules, 0, state, options, yieldEvery);
}

function defaultScanOptions(
  rateLimits: RateLimitPort,
  maxFieldLength = DEFAULT_MAX_FIELD_LENGTH,
  ruleYieldEvery = 0,
): ScanOptions {
  return {
    ruleYieldEvery,
    rateLimits,
    evaluate: {
      fields: {
        maxFieldLength,
        memo: new Map<WafField, readonly string[]>(),
        memoLower: new Map<WafField, readonly string[]>(),
      },
    },
  };
}

/**
 * Rule scan (synchronous, no event-loop yields).
 * Rate-limit hits go through `options.rateLimits` immediately.
 * Returns a new ScanState — never mutates rules or the previous state object.
 */
export function scanRules(
  ctx: WafHttpContext,
  rules: readonly WafRule[],
  rateLimits: RateLimitPort,
  options: Omit<ScanOptions, 'rateLimits'> = {
    ruleYieldEvery: 0,
    evaluate: { fields: { maxFieldLength: DEFAULT_MAX_FIELD_LENGTH } },
  },
): ScanState {
  return scanRulesFrom(
    ctx,
    rules,
    0,
    initialScanState(),
    { ...options, rateLimits },
  );
}

/**
 * Async rule scan with optional `setImmediate` yields every N rules.
 * Preserves evaluation order, allow short-circuit, and rate-limit side effects.
 * Yields are safe with rate limits: the shared store applies hits in place.
 */
export async function scanRulesAsync(
  ctx: WafHttpContext,
  rules: readonly WafRule[],
  options: ScanOptions,
): Promise<ScanState> {
  return scanRulesFromAsync(ctx, rules, initialScanState(), options);
}

function applyRateLimitHeaders(
  ctx: WafHttpContext,
  info: RateLimitInfo | undefined,
): void {
  if (!info) {
    return;
  }
  ctx.setResponseHeader('X-RateLimit-Limit', info.limit);
  ctx.setResponseHeader('X-RateLimit-Remaining', info.remaining);
  ctx.setResponseHeader('X-RateLimit-Reset', info.resetAt);
}

function resultFromScan(
  scan: ScanState,
  resolved: ResolvedWafConfig,
  ctx: WafHttpContext,
  logger: WafLogger,
): WafEvaluationResult {
  applyRateLimitHeaders(ctx, scan.lastRateLimitInfo);

  if (scan.allowRule) {
    emitIfLevel(resolved.logging, 'debug', () => {
      logger.connection(ctx);
    });
    return {
      decision: 'allow',
      matchedRule: scan.allowRule,
      reason: scan.allowRule.reason,
      loggedRules: scan.loggedRules,
    };
  }

  emitIfLevel(resolved.logging, 'info', () => {
    for (const logged of scan.loggedRules) {
      logger.audit(ctx, logged);
    }
  });

  if (scan.blockCandidate) {
    const blockedRule = scan.blockCandidate;
    const reason =
      blockedRule.reason ?? `Blocked by rule ${blockedRule.id}`;
    ctx.drop(resolved.blockStatusCode, resolved.blockBody);
    emitIfLevel(resolved.logging, 'error', () => {
      logger.blocked(ctx, blockedRule);
    });
    return {
      decision: 'block',
      matchedRule: blockedRule,
      reason,
      loggedRules: scan.loggedRules,
    };
  }

  emitIfLevel(resolved.logging, 'debug', () => {
    logger.connection(ctx);
  });

  return {
    decision: 'allow',
    matchedRule: undefined,
    reason: undefined,
    loggedRules: scan.loggedRules,
  };
}

interface CachedDecision {
  readonly decision: WafDecision;
  readonly matchedRuleId: string | undefined;
  readonly reason: string | undefined;
  readonly loggedRuleIds: readonly string[];
}

function toCachedDecision(result: WafEvaluationResult): CachedDecision {
  return {
    decision: result.decision,
    matchedRuleId: result.matchedRule?.id,
    reason: result.reason,
    loggedRuleIds: result.loggedRules.map((rule) => rule.id),
  };
}

function fromCachedDecision(
  cached: CachedDecision,
  rules: readonly WafRule[],
  resolved: ResolvedWafConfig,
  ctx: WafHttpContext,
  logger: WafLogger,
): WafEvaluationResult {
  const byId = new Map(rules.map((rule) => [rule.id, rule] as const));
  const matchedRule =
    cached.matchedRuleId !== undefined
      ? byId.get(cached.matchedRuleId)
      : undefined;
  const loggedRules = cached.loggedRuleIds.flatMap((id) => {
    const rule = byId.get(id);
    return rule !== undefined ? [rule] : [];
  });

  if (cached.decision === 'block' && matchedRule !== undefined) {
    ctx.drop(resolved.blockStatusCode, resolved.blockBody);
    emitIfLevel(resolved.logging, 'error', () => {
      logger.blocked(ctx, matchedRule);
    });
    return {
      decision: 'block',
      matchedRule,
      reason: cached.reason,
      loggedRules,
    };
  }

  emitIfLevel(resolved.logging, 'debug', () => {
    logger.connection(ctx);
  });

  return {
    decision: 'allow',
    matchedRule,
    reason: cached.reason,
    loggedRules,
  };
}

/**
 * Create the framework-agnostic WAF engine.
 * Rule lists and evaluation results are immutable values.
 */
export function createWafEngine(
  config: WafConfig = {},
  options: WafEngineOptions = {},
): WafEngine {
  const rules = buildRuleList(config);
  const resolved = resolveConfig(config, rules);
  const rateLimitStore =
    options.rateLimitStore ??
    new RateLimitStore(emptyRateLimitState(), {
      maxKeys: resolved.performance.maxRateLimitKeys,
    });
  const logger = resolveEngineLogger(config, resolved.logging, options.logger);
  const rateLimitInRules = rulesHaveRateLimit(rules);
  const decisionCache =
    resolved.performance.decisionCache !== undefined && !rateLimitInRules
      ? new LruCache<CachedDecision>(
          resolved.performance.decisionCache.max,
          resolved.performance.decisionCache.ttlMs,
        )
      : undefined;

  return {
    rules,
    config: resolved,
    rateLimitStore,

    async handle(ctx: WafHttpContext): Promise<WafEvaluationResult> {
      const scanOptions = defaultScanOptions(
        rateLimitStore,
        resolved.performance.maxFieldLength,
        resolved.performance.ruleYieldEvery,
      );

      if (decisionCache !== undefined) {
        const key = requestFingerprint(ctx, FINGERPRINT_BODY_MAX);
        const cached = decisionCache.get(key);
        if (cached !== undefined) {
          return fromCachedDecision(cached, rules, resolved, ctx, logger);
        }

        const scan = await scanRulesAsync(ctx, rules, scanOptions);
        const result = resultFromScan(scan, resolved, ctx, logger);
        decisionCache.set(key, toCachedDecision(result));
        return result;
      }

      const scan = await scanRulesAsync(ctx, rules, scanOptions);
      return resultFromScan(scan, resolved, ctx, logger);
    },
  };
}

export type { WafDecision };
