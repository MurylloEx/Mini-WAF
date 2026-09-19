import type { WafCondition } from '@/domain/rules';
import {
  isAllCondition,
  isAnyOfCondition,
  isFieldCondition,
  isNotCondition,
} from '@/domain/rules';

/** True when any leaf in the condition tree carries a rateLimit side effect. */
export function conditionHasRateLimit(condition: WafCondition): boolean {
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

/** True when the active rule list includes at least one rateLimit condition. */
export function rulesHaveRateLimit(
  rules: readonly { readonly when: WafCondition }[],
): boolean {
  return rules.some((rule) => conditionHasRateLimit(rule.when));
}
