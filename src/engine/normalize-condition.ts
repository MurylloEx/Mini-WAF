import type { FieldCondition, WafCondition, WafRule } from '@/domain/rules';
import {
  isAllCondition,
  isAnyOfCondition,
  isFieldCondition,
  isNotCondition,
} from '@/domain/rules';

/**
 * Pre-lowercase static `includes` needles (matching is case-insensitive).
 * Avoids repeated `toLowerCase` on the needle during every field scan.
 */
function normalizeFieldCondition(condition: FieldCondition): FieldCondition {
  if (condition.includes === undefined) {
    return condition;
  }
  const includes = condition.includes.toLowerCase();
  if (includes === condition.includes) {
    return condition;
  }
  return { ...condition, includes };
}

/** Deep-normalize a condition tree (immutable). */
export function normalizeCondition(condition: WafCondition): WafCondition {
  if (isFieldCondition(condition)) {
    return normalizeFieldCondition(condition);
  }
  if (isAllCondition(condition)) {
    return { all: condition.all.map(normalizeCondition) };
  }
  if (isAnyOfCondition(condition)) {
    return { anyOf: condition.anyOf.map(normalizeCondition) };
  }
  if (isNotCondition(condition)) {
    return { not: normalizeCondition(condition.not) };
  }
  return condition;
}

/** Normalize a rule's condition tree (immutable). */
export function normalizeRule(rule: WafRule): WafRule {
  const when = normalizeCondition(rule.when);
  if (when === rule.when) {
    return rule;
  }
  return { ...rule, when };
}

/** Normalize every rule in a list. */
export function normalizeRules(rules: readonly WafRule[]): readonly WafRule[] {
  return rules.map(normalizeRule);
}
