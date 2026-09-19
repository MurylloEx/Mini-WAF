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
  type RateLimitInfo,
} from '@/engine/evaluate';
import {
  emptyRateLimitState,
  RateLimitStore,
  type RateLimitState,
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

export interface WafEngineOptions {
  /** Inject a shared rate-limit store (tests / multi-instance). */
  readonly rateLimitStore?: RateLimitStore;
  /**
   * Override the logging sink when logging is enabled.
   * Ignored while `config.logging` is off (default) — no logger calls.
   */
  readonly logger?: WafLogger;
}

export interface ResolvedWafConfig {
  readonly level: ProtectionLevel;
  readonly rules: readonly WafRule[];
  readonly presets: readonly NonNullable<WafConfig['presets']>[number][];
  readonly blockStatusCode: number;
  readonly blockBody: string;
  readonly logging: ResolvedLogging;
}

export interface WafEngine {
  readonly rules: readonly WafRule[];
  readonly config: ResolvedWafConfig;
  readonly rateLimitStore: RateLimitStore;
  handle(ctx: WafHttpContext): Promise<WafEvaluationResult>;
}

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
  return sortRules(
    filterRulesByDisabledIds(
      filterRulesByEnabledIds(
        filterRulesByLevel([...fromPresets, ...custom], level),
        config.enabledRuleIds,
      ),
      config.disabledRuleIds,
    ),
  );
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
  readonly rateLimitState: RateLimitState;
  readonly loggedRules: readonly WafRule[];
  readonly blockCandidate: WafRule | undefined;
  readonly allowRule: WafRule | undefined;
  readonly lastRateLimitInfo: RateLimitInfo | undefined;
}

function initialScanState(rateLimitState: RateLimitState): ScanState {
  return {
    rateLimitState,
    loggedRules: [],
    blockCandidate: undefined,
    allowRule: undefined,
    lastRateLimitInfo: undefined,
  };
}

/**
 * Pure rule scan over immutable inputs.
 * Returns a new ScanState — never mutates rules or the previous state object.
 */
export function scanRules(
  ctx: WafHttpContext,
  rules: readonly WafRule[],
  rateLimitState: RateLimitState,
): ScanState {
  let state = initialScanState(rateLimitState);

  for (const rule of rules) {
    const evaluation = evaluateCondition(ctx, rule.when, state.rateLimitState);

    state = {
      ...state,
      rateLimitState: evaluation.rateLimitState,
      lastRateLimitInfo: evaluation.rateLimitInfo ?? state.lastRateLimitInfo,
    };

    if (!evaluation.matched) {
      continue;
    }

    if (rule.action === 'allow') {
      return { ...state, allowRule: rule };
    }

    if (rule.action === 'log') {
      state = {
        ...state,
        loggedRules: [...state.loggedRules, rule],
      };
      continue;
    }

    if (rule.action === 'block' && state.blockCandidate === undefined) {
      state = { ...state, blockCandidate: rule };
    }
  }

  return state;
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
    options.rateLimitStore ?? new RateLimitStore(emptyRateLimitState());
  const logger = resolveEngineLogger(config, resolved.logging, options.logger);

  return {
    rules,
    config: resolved,
    rateLimitStore,

    async handle(ctx: WafHttpContext): Promise<WafEvaluationResult> {
      const scan = scanRules(ctx, rules, rateLimitStore.snapshot());
      rateLimitStore.replace(scan.rateLimitState);
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
    },
  };
}

export type { WafDecision };
