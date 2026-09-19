import type { WafCondition, FieldCondition } from '@/domain/rules';
import {
  isAllCondition,
  isAnyOfCondition,
  isFieldCondition,
  isNotCondition,
} from '@/domain/rules';
import type { WafHttpContext } from '@/domain/context';
import { includesIgnoreCase, matchesPattern } from '@/engine/matcher';
import { resolveFieldJoined, resolveFieldValues } from '@/engine/field-resolver';
import {
  applyRateLimitHit,
  type RateLimitState,
} from '@/engine/rate-limit';

export interface RateLimitInfo {
  readonly limit: number;
  readonly remaining: number;
  readonly resetAt: number;
}

/** Pure evaluation result: match flag + next rate-limit state. */
export interface ConditionEvaluation {
  readonly matched: boolean;
  readonly rateLimitState: RateLimitState;
  readonly rateLimitInfo: RateLimitInfo | undefined;
}

function patternMatchesField(
  ctx: WafHttpContext,
  condition: FieldCondition,
): boolean {
  const values = resolveFieldValues(ctx, condition.field);
  const hasPattern =
    condition.matches !== undefined ||
    condition.equals !== undefined ||
    condition.includes !== undefined;

  if (!hasPattern) {
    return false;
  }

  return values.some((value) => {
    if (condition.equals !== undefined && value === condition.equals) {
      return true;
    }
    if (
      condition.includes !== undefined &&
      includesIgnoreCase(value, condition.includes)
    ) {
      return true;
    }
    if (
      condition.matches !== undefined &&
      matchesPattern(value, condition.matches)
    ) {
      return true;
    }
    return false;
  });
}

function evaluateField(
  ctx: WafHttpContext,
  condition: FieldCondition,
  rateLimitState: RateLimitState,
): ConditionEvaluation {
  const hasPattern =
    condition.matches !== undefined ||
    condition.equals !== undefined ||
    condition.includes !== undefined;

  const patternOk = hasPattern ? patternMatchesField(ctx, condition) : true;

  if (hasPattern && !patternOk) {
    return {
      matched: false,
      rateLimitState,
      rateLimitInfo: undefined,
    };
  }

  if (!condition.rateLimit) {
    return {
      matched: hasPattern,
      rateLimitState,
      rateLimitInfo: undefined,
    };
  }

  const keyMaterial =
    condition.rateLimit.keyPrefix !== undefined
      ? `${condition.rateLimit.keyPrefix}:${resolveFieldJoined(ctx, condition.field)}`
      : `${condition.field}:${resolveFieldJoined(ctx, condition.field)}`;

  const transition = applyRateLimitHit(
    rateLimitState,
    keyMaterial,
    condition.rateLimit.max,
    condition.rateLimit.windowMs,
  );

  const rateLimitInfo: RateLimitInfo = {
    limit: condition.rateLimit.max,
    remaining: transition.hit.remaining,
    resetAt: transition.hit.resetAt,
  };

  // Rate-limit-only → match when exceeded.
  // Pattern + rate limit → both must hold.
  const matched = hasPattern
    ? transition.hit.exceeded
    : transition.hit.exceeded;

  return {
    matched,
    rateLimitState: transition.state,
    rateLimitInfo,
  };
}

function foldAll(
  ctx: WafHttpContext,
  children: readonly WafCondition[],
  rateLimitState: RateLimitState,
): ConditionEvaluation {
  let state = rateLimitState;
  let lastInfo: RateLimitInfo | undefined;

  for (const child of children) {
    const result = evaluateCondition(ctx, child, state);
    state = result.rateLimitState;
    if (result.rateLimitInfo) {
      lastInfo = result.rateLimitInfo;
    }
    if (!result.matched) {
      return {
        matched: false,
        rateLimitState: state,
        rateLimitInfo: lastInfo,
      };
    }
  }

  return {
    matched: children.length > 0,
    rateLimitState: state,
    rateLimitInfo: lastInfo,
  };
}

function foldAnyOf(
  ctx: WafHttpContext,
  children: readonly WafCondition[],
  rateLimitState: RateLimitState,
): ConditionEvaluation {
  let state = rateLimitState;
  let lastInfo: RateLimitInfo | undefined;

  for (const child of children) {
    const result = evaluateCondition(ctx, child, state);
    state = result.rateLimitState;
    if (result.rateLimitInfo) {
      lastInfo = result.rateLimitInfo;
    }
    if (result.matched) {
      return {
        matched: true,
        rateLimitState: state,
        rateLimitInfo: lastInfo,
      };
    }
  }

  return {
    matched: false,
    rateLimitState: state,
    rateLimitInfo: lastInfo,
  };
}

/**
 * Pure condition evaluator.
 * Side effects (logging, response headers) are left to the engine layer.
 */
export function evaluateCondition(
  ctx: WafHttpContext,
  condition: WafCondition,
  rateLimitState: RateLimitState,
): ConditionEvaluation {
  if (isFieldCondition(condition)) {
    return evaluateField(ctx, condition, rateLimitState);
  }
  if (isAllCondition(condition)) {
    return foldAll(ctx, condition.all, rateLimitState);
  }
  if (isAnyOfCondition(condition)) {
    return foldAnyOf(ctx, condition.anyOf, rateLimitState);
  }
  if (isNotCondition(condition)) {
    const inner = evaluateCondition(ctx, condition.not, rateLimitState);
    return {
      matched: !inner.matched,
      rateLimitState: inner.rateLimitState,
      rateLimitInfo: inner.rateLimitInfo,
    };
  }
  return {
    matched: false,
    rateLimitState,
    rateLimitInfo: undefined,
  };
}
