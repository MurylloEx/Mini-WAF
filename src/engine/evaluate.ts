import type { WafCondition, FieldCondition } from '@/domain/rules';
import {
  isAllCondition,
  isAnyOfCondition,
  isFieldCondition,
  isNotCondition,
} from '@/domain/rules';
import type { WafHttpContext } from '@/domain/context';
import { includesLower, matchesPattern } from '@/engine/matcher';
import {
  resolveFieldJoined,
  resolveFieldValues,
  resolveFieldValuesLower,
  type FieldResolveOptions,
} from '@/engine/field-resolver';
import type { RateLimitPort } from '@/engine/rate-limit';

export interface RateLimitInfo {
  readonly limit: number;
  readonly remaining: number;
  readonly resetAt: number;
}

/** Evaluation result: match flag + optional rate-limit headers payload. */
export interface ConditionEvaluation {
  readonly matched: boolean;
  readonly rateLimitInfo: RateLimitInfo | undefined;
}

export interface EvaluateOptions {
  readonly fields: FieldResolveOptions;
}

const DEFAULT_EVAL_OPTIONS: EvaluateOptions = {
  fields: { maxFieldLength: 0 },
};

function patternMatchesField(
  ctx: WafHttpContext,
  condition: FieldCondition,
  fields: FieldResolveOptions,
): boolean {
  const values = resolveFieldValues(ctx, condition.field, fields);

  // Prefer pre-lowercased needles (normalizeRules); still lower once here for
  // callers that pass raw conditions into evaluateCondition.
  const needleLower =
    condition.includes !== undefined
      ? condition.includes.toLowerCase()
      : undefined;
  const lowerValues =
    needleLower !== undefined
      ? resolveFieldValuesLower(ctx, condition.field, fields)
      : undefined;

  return values.some((value, index) => {
    if (condition.equals !== undefined && value === condition.equals) {
      return true;
    }
    if (needleLower !== undefined && lowerValues !== undefined) {
      const haystackLower = lowerValues[index] ?? value.toLowerCase();
      if (includesLower(haystackLower, needleLower)) {
        return true;
      }
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
  rateLimits: RateLimitPort,
  fields: FieldResolveOptions,
): ConditionEvaluation {
  const hasPattern =
    condition.matches !== undefined ||
    condition.equals !== undefined ||
    condition.includes !== undefined;

  const patternOk = hasPattern
    ? patternMatchesField(ctx, condition, fields)
    : true;

  if (hasPattern && !patternOk) {
    return {
      matched: false,
      rateLimitInfo: undefined,
    };
  }

  if (!condition.rateLimit) {
    return {
      matched: hasPattern,
      rateLimitInfo: undefined,
    };
  }

  const keyMaterial =
    condition.rateLimit.keyPrefix !== undefined
      ? `${condition.rateLimit.keyPrefix}:${resolveFieldJoined(ctx, condition.field, fields)}`
      : `${condition.field}:${resolveFieldJoined(ctx, condition.field, fields)}`;

  const hit = rateLimits.hit(
    keyMaterial,
    condition.rateLimit.max,
    condition.rateLimit.windowMs,
  );

  return {
    matched: hit.exceeded,
    rateLimitInfo: {
      limit: condition.rateLimit.max,
      remaining: hit.remaining,
      resetAt: hit.resetAt,
    },
  };
}

function foldAllSeq(
  ctx: WafHttpContext,
  children: readonly WafCondition[],
  index: number,
  lastInfo: RateLimitInfo | undefined,
  rateLimits: RateLimitPort,
  options: EvaluateOptions,
): ConditionEvaluation {
  if (index >= children.length) {
    return {
      matched: children.length > 0,
      rateLimitInfo: lastInfo,
    };
  }

  const child = children[index];
  if (child === undefined) {
    return foldAllSeq(
      ctx,
      children,
      index + 1,
      lastInfo,
      rateLimits,
      options,
    );
  }

  const result = evaluateCondition(ctx, child, rateLimits, options);
  const nextInfo = result.rateLimitInfo ?? lastInfo;
  if (!result.matched) {
    return {
      matched: false,
      rateLimitInfo: nextInfo,
    };
  }

  return foldAllSeq(
    ctx,
    children,
    index + 1,
    nextInfo,
    rateLimits,
    options,
  );
}

function foldAnyOfSeq(
  ctx: WafHttpContext,
  children: readonly WafCondition[],
  index: number,
  lastInfo: RateLimitInfo | undefined,
  rateLimits: RateLimitPort,
  options: EvaluateOptions,
): ConditionEvaluation {
  if (index >= children.length) {
    return {
      matched: false,
      rateLimitInfo: lastInfo,
    };
  }

  const child = children[index];
  if (child === undefined) {
    return foldAnyOfSeq(
      ctx,
      children,
      index + 1,
      lastInfo,
      rateLimits,
      options,
    );
  }

  const result = evaluateCondition(ctx, child, rateLimits, options);
  const nextInfo = result.rateLimitInfo ?? lastInfo;
  if (result.matched) {
    return {
      matched: true,
      rateLimitInfo: nextInfo,
    };
  }

  return foldAnyOfSeq(
    ctx,
    children,
    index + 1,
    nextInfo,
    rateLimits,
    options,
  );
}

/**
 * Condition evaluator. Rate-limit side effects go through {@link RateLimitPort}
 * (typically the shared {@link import('./rate-limit').RateLimitStore}).
 */
export function evaluateCondition(
  ctx: WafHttpContext,
  condition: WafCondition,
  rateLimits: RateLimitPort,
  options: EvaluateOptions = DEFAULT_EVAL_OPTIONS,
): ConditionEvaluation {
  if (isFieldCondition(condition)) {
    return evaluateField(ctx, condition, rateLimits, options.fields);
  }
  if (isAllCondition(condition)) {
    return foldAllSeq(
      ctx,
      condition.all,
      0,
      undefined,
      rateLimits,
      options,
    );
  }
  if (isAnyOfCondition(condition)) {
    return foldAnyOfSeq(
      ctx,
      condition.anyOf,
      0,
      undefined,
      rateLimits,
      options,
    );
  }
  if (isNotCondition(condition)) {
    const inner = evaluateCondition(
      ctx,
      condition.not,
      rateLimits,
      options,
    );
    return {
      matched: !inner.matched,
      rateLimitInfo: inner.rateLimitInfo,
    };
  }
  return {
    matched: false,
    rateLimitInfo: undefined,
  };
}
