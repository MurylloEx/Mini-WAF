import type { WafAdapter, WafHttpContext } from '@/domain/context';
import type { WafConfig, WafEvaluationResult } from '@/domain/rules';
import {
  createWafEngine,
  type WafEngine,
  type WafEngineOptions,
} from '@/engine/engine';

export interface MiniWafInstance extends WafEngine {
  /**
   * Run the engine against any adapter + native request/response.
   */
  protect<TRequest, TResponse, TNext>(
    adapter: WafAdapter<TRequest, TResponse, TNext>,
    request: TRequest,
    response: TResponse,
    next?: TNext,
  ): Promise<WafEvaluationResult>;
}

export function createMiniWaf(
  config: WafConfig = {},
  options?: WafEngineOptions,
): MiniWafInstance {
  const engine = createWafEngine(config, options);

  return {
    rules: engine.rules,
    config: engine.config,
    rateLimitStore: engine.rateLimitStore,
    handle: (ctx) => engine.handle(ctx),
    async protect(adapter, request, response, next) {
      const ctx = await Promise.resolve(
        adapter.createContext(request, response, next),
      );
      return engine.handle(ctx);
    },
  };
}

/** Shared helper used by framework integrations. */
export async function runWithAdapter<TRequest, TResponse, TNext>(
  waf: WafEngine,
  adapter: WafAdapter<TRequest, TResponse, TNext>,
  request: TRequest,
  response: TResponse,
  next?: TNext,
): Promise<{ readonly result: WafEvaluationResult; readonly ctx: WafHttpContext }> {
  const ctx = await Promise.resolve(
    adapter.createContext(request, response, next),
  );
  const result = await waf.handle(ctx);
  return { result, ctx };
}

export {
  createWafEngine,
  scanRules,
  filterRulesByLevel,
  buildRuleList,
  type WafEngine,
  type WafEngineOptions,
  type ResolvedWafConfig,
  type ScanState,
} from '@/engine/engine';
export {
  filterRulesByEnabledIds,
  filterRulesByDisabledIds,
} from '@/engine/rule-filter';
export {
  loadRules,
  parseRulesFromJson,
  RuleParseError,
} from '@/engine/load-rules';
export {
  matchesPattern,
  includesIgnoreCase,
} from '@/engine/matcher';
export {
  resolveFieldValues,
  resolveFieldJoined,
} from '@/engine/field-resolver';
export {
  evaluateCondition,
  type ConditionEvaluation,
  type RateLimitInfo,
} from '@/engine/evaluate';
export {
  emptyRateLimitState,
  applyRateLimitHit,
  pruneRateLimitState,
  RateLimitStore,
  type RateLimitState,
  type RateLimitHit,
  type RateLimitTransition,
} from '@/engine/rate-limit';
