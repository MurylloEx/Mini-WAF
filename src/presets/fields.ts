import type { WafCondition, WafField } from '@/domain/rules';

/** Fields that usually carry attacker-controlled payloads. */
export const PAYLOAD_FIELDS = ['query', 'body', 'cookies'] as const;

/** Payload fields plus the request path (URL-borne injection). */
export const PAYLOAD_PATH_FIELDS = [
  'query',
  'body',
  'path',
  'cookies',
] as const;

/** URL-borne fields only — used when the body is too noisy to scan safely. */
export const URL_FIELDS = ['query', 'path', 'cookies'] as const;

/**
 * Fan a single pattern out over several fields as a logical OR.
 * The pattern instance is shared, so a rule costs one regex per field value.
 *
 * `requires` is the literal prefilter (see {@link import('@/domain/rules').FieldCondition.requires}).
 * It must list a substring that **every** string the pattern can match
 * contains, otherwise the rule silently stops detecting those payloads.
 */
export function anyFieldMatches(
  fields: readonly WafField[],
  pattern: RegExp,
  requires?: readonly string[],
): WafCondition {
  return {
    anyOf: fields.map((field) => ({
      field,
      matches: pattern,
      ...(requires !== undefined ? { requires } : {}),
    })),
  };
}
