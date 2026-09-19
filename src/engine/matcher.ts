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

export function includesIgnoreCase(haystack: string, needle: string): boolean {
  if (needle.length === 0) {
    return true;
  }
  if (needle.length > haystack.length) {
    return false;
  }
  return haystack.toLowerCase().includes(needle.toLowerCase());
}
