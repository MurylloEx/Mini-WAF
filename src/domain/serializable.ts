/**
 * JSON-serializable WAF rule DSL.
 *
 * Patterns cannot carry live `RegExp` or function predicates.
 * Use string exact matches, string lists, or `{ pattern, flags? }` for regex.
 *
 * Inspired by practical CRS categories / field targeting — not ModSecurity syntax.
 */

import type { ProtectionLevel } from '@/domain/levels';
import type { WafAction, WafField } from '@/domain/rules';

/** Regex expressed as pattern + optional flags (JSON-safe). */
export interface JsonRegexPattern {
  readonly pattern: string;
  readonly flags?: string;
}

/**
 * Serializable `matches` value:
 * - `string` — exact equality (same as live `WafRule`)
 * - `readonly string[]` — OR list of exact strings
 * - `JsonRegexPattern` — compiled to `RegExp`
 */
export type JsonMatchPattern =
  | string
  | readonly string[]
  | JsonRegexPattern;

export interface JsonRateLimitSpec {
  readonly max: number;
  readonly windowMs: number;
  readonly keyPrefix?: string;
}

export interface JsonFieldCondition {
  readonly field: WafField;
  readonly matches?: JsonMatchPattern;
  readonly equals?: string;
  readonly includes?: string;
  readonly rateLimit?: JsonRateLimitSpec;
}

export interface JsonAllCondition {
  readonly all: readonly JsonWafCondition[];
}

export interface JsonAnyOfCondition {
  readonly anyOf: readonly JsonWafCondition[];
}

export interface JsonNotCondition {
  readonly not: JsonWafCondition;
}

export type JsonWafCondition =
  | JsonFieldCondition
  | JsonAllCondition
  | JsonAnyOfCondition
  | JsonNotCondition;

/**
 * One rule as it appears in JSON (or a plain object tree).
 * Alias: {@link SerializableWafRule}.
 */
export interface JsonWafRule {
  readonly id: string;
  readonly when: JsonWafCondition;
  readonly action: WafAction;
  readonly reason?: string;
  readonly enabled?: boolean;
  readonly priority?: number;
  readonly minLevel?: ProtectionLevel;
}

/** @see JsonWafRule */
export type SerializableWafRule = JsonWafRule;
