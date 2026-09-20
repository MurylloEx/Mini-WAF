import type { FieldCondition, WafCondition, WafRule } from '@/domain/rules';
import {
  isAllCondition,
  isAnyOfCondition,
  isFieldCondition,
  isNotCondition,
} from '@/domain/rules';

function lowerAll(values: readonly string[]): readonly string[] {
  return values.map((value) => value.toLowerCase());
}

function isAlreadyLower(values: readonly string[]): boolean {
  return values.every((value) => value === value.toLowerCase());
}

/**
 * Pre-lowercase static `includes` and `requires` needles (matching is
 * case-insensitive). Avoids repeated `toLowerCase` on the needles during
 * every field scan.
 */
function normalizeFieldCondition(condition: FieldCondition): FieldCondition {
  const includes =
    condition.includes === undefined
      ? undefined
      : condition.includes.toLowerCase();
  const requires =
    condition.requires === undefined || isAlreadyLower(condition.requires)
      ? condition.requires
      : lowerAll(condition.requires);

  if (includes === condition.includes && requires === condition.requires) {
    return condition;
  }

  return {
    ...condition,
    ...(includes !== undefined ? { includes } : {}),
    ...(requires !== undefined ? { requires } : {}),
  };
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
