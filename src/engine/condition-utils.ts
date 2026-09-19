import type { WafCondition } from '@/domain/rules';
import {
  isAllCondition,
  isAnyOfCondition,
  isFieldCondition,
  isNotCondition,
} from '@/domain/rules';

function computeConditionHasRateLimit(condition: WafCondition): boolean {
  if (isFieldCondition(condition)) {
    return condition.rateLimit !== undefined;
  }
  if (isAllCondition(condition)) {
    return condition.all.some(conditionHasRateLimit);
  }
  if (isAnyOfCondition(condition)) {
    return condition.anyOf.some(conditionHasRateLimit);
  }
  if (isNotCondition(condition)) {
    return conditionHasRateLimit(condition.not);
  }
  return false;
}

/**
 * Condition trees are immutable once a rule list is built, so the
 * rateLimit-presence check (called per remaining rule on every request once
 * a block candidate exists — see `shouldSkipRule`) is cached per condition
 * object instead of re-walking the tree on every request.
 */
const rateLimitPresenceCache = new WeakMap<WafCondition, boolean>();

/** True when any leaf in the condition tree carries a rateLimit side effect. */
export function conditionHasRateLimit(condition: WafCondition): boolean {
  const cached = rateLimitPresenceCache.get(condition);
  if (cached !== undefined) {
    return cached;
  }
  const result = computeConditionHasRateLimit(condition);
  rateLimitPresenceCache.set(condition, result);
  return result;
}

/** True when the active rule list includes at least one rateLimit condition. */
export function rulesHaveRateLimit(
  rules: readonly { readonly when: WafCondition }[],
): boolean {
  return rules.some((rule) => conditionHasRateLimit(rule.when));
}
