import type { WafRule } from '@/domain/rules';

/**
 * Optional allowlist: when `enabledRuleIds` is present and non-empty,
 * keep only rules whose `id` is listed. Empty / undefined → no-op.
 */
export function filterRulesByEnabledIds(
  rules: readonly WafRule[],
  enabledRuleIds: readonly string[] | undefined,
): readonly WafRule[] {
  if (enabledRuleIds === undefined || enabledRuleIds.length === 0) {
    return rules;
  }
  const allowed = new Set(enabledRuleIds);
  return rules.filter((rule) => allowed.has(rule.id));
}

/**
 * Drop rules whose `id` appears in `disabledRuleIds`.
 * Empty / undefined → no-op.
 */
export function filterRulesByDisabledIds(
  rules: readonly WafRule[],
  disabledRuleIds: readonly string[] | undefined,
): readonly WafRule[] {
  if (disabledRuleIds === undefined || disabledRuleIds.length === 0) {
    return rules;
  }
  const blocked = new Set(disabledRuleIds);
  return rules.filter((rule) => !blocked.has(rule.id));
}
