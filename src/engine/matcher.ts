import type { MatchPattern } from '@/domain/rules';

/** Test a candidate string against a match pattern. */
export function matchesPattern(value: string, pattern: MatchPattern): boolean {
  if (typeof pattern === 'string') {
    return value === pattern;
  }
  if (pattern instanceof RegExp) {
    // Reset lastIndex for global / sticky regex reuse safety.
    pattern.lastIndex = 0;
    return pattern.test(value);
  }
  if (typeof pattern === 'function') {
    return pattern(value);
  }
  for (const item of pattern) {
    if (value === item) {
      return true;
    }
  }
  return false;
}

/**
 * Case-insensitive substring check when both sides are already lowercased.
 * Prefer this on hot paths (pre-lower needle at rule load; memoize haystacks).
 */
export function includesLower(
  haystackLower: string,
  needleLower: string,
): boolean {
  if (needleLower.length === 0) {
    return true;
  }
  if (needleLower.length > haystackLower.length) {
    return false;
  }
  return haystackLower.includes(needleLower);
}

/** Case-insensitive substring. Lowers both sides once per call. */
export function includesIgnoreCase(haystack: string, needle: string): boolean {
  return includesLower(haystack.toLowerCase(), needle.toLowerCase());
}
