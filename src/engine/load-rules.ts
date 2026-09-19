/**
 * Load / compile serializable (JSON) rules into live `WafRule` values.
 * Pure validation — no `any` / `unknown`; rejects invalid shapes with path errors.
 */

import type {
  JsonArray,
  JsonObject,
  JsonValue,
} from '@/domain/values';
import {
  isProtectionLevel,
  type MatchPattern,
  type ProtectionLevel,
  type RateLimitSpec,
  type WafAction,
  type WafCondition,
  type WafField,
  type WafRule,
} from '@/domain/rules';
import type {
  JsonMatchPattern,
  JsonWafCondition,
  JsonWafRule,
} from '@/domain/serializable';

const SCALAR_FIELDS = new Set<string>([
  'ip',
  'method',
  'path',
  'url',
  'body',
  'files',
  'query',
  'headers',
  'cookies',
]);

const WAF_ACTIONS = new Set<string>(['allow', 'block', 'log']);

const REGEX_FLAG_CHARS = new Set([
  'd',
  'g',
  'i',
  'm',
  's',
  'u',
  'v',
  'y',
]);

export class RuleParseError extends Error {
  readonly path: string;

  constructor(path: string, message: string) {
    super(`${path}: ${message}`);
    this.name = 'RuleParseError';
    this.path = path;
  }
}

function isJsonObject(value: JsonValue): value is JsonObject {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function isJsonArray(value: JsonValue): value is JsonArray {
  return Array.isArray(value);
}

function expectObject(value: JsonValue, path: string): JsonObject {
  if (!isJsonObject(value)) {
    throw new RuleParseError(path, 'expected a JSON object');
  }
  return value;
}

function expectString(value: JsonValue | undefined, path: string): string {
  if (typeof value !== 'string') {
    throw new RuleParseError(path, 'expected a string');
  }
  return value;
}

function expectBoolean(value: JsonValue | undefined, path: string): boolean {
  if (typeof value !== 'boolean') {
    throw new RuleParseError(path, 'expected a boolean');
  }
  return value;
}

function expectFiniteNumber(value: JsonValue | undefined, path: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value)) {
    throw new RuleParseError(path, 'expected a finite number');
  }
  return value;
}

function expectStringArray(
  value: JsonValue,
  path: string,
): readonly string[] {
  if (!isJsonArray(value)) {
    throw new RuleParseError(path, 'expected a string array');
  }
  return value.map((item, index) =>
    expectString(item, `${path}[${index}]`),
  );
}

function parseJsonDocument(input: string): JsonValue {
  try {
    return JSON.parse(input) as JsonValue;
  } catch (cause) {
    const detail =
      cause instanceof Error ? cause.message : 'invalid JSON';
    throw new RuleParseError('$', `failed to parse JSON (${detail})`);
  }
}

function isWafField(value: string): value is WafField {
  if (SCALAR_FIELDS.has(value)) {
    return true;
  }
  return (
    value.startsWith('query.') ||
    value.startsWith('headers.') ||
    value.startsWith('cookies.')
  );
}

function isWafAction(value: string): value is WafAction {
  return WAF_ACTIONS.has(value);
}

function assertRegexFlags(flags: string, path: string): void {
  const chars = [...flags];
  const invalid = chars.find((ch) => !REGEX_FLAG_CHARS.has(ch));
  if (invalid !== undefined) {
    throw new RuleParseError(path, `invalid regex flag "${invalid}"`);
  }
  const unique = new Set(chars);
  if (unique.size !== chars.length) {
    throw new RuleParseError(path, 'duplicate regex flags');
  }
}

function compileRegex(
  pattern: string,
  flags: string | undefined,
  path: string,
): RegExp {
  const resolvedFlags = flags ?? '';
  assertRegexFlags(resolvedFlags, `${path}.flags`);
  try {
    return new RegExp(pattern, resolvedFlags);
  } catch (cause) {
    const detail =
      cause instanceof Error ? cause.message : 'invalid regular expression';
    throw new RuleParseError(path, detail);
  }
}

function loadMatchPattern(
  value: JsonValue,
  path: string,
): MatchPattern {
  if (typeof value === 'string') {
    return value;
  }
  if (isJsonArray(value)) {
    return expectStringArray(value, path);
  }
  if (isJsonObject(value)) {
    const pattern = expectString(value.pattern, `${path}.pattern`);
    const flags =
      value.flags === undefined
        ? undefined
        : expectString(value.flags, `${path}.flags`);
    return compileRegex(pattern, flags, path);
  }
  throw new RuleParseError(
    path,
    'expected a string, string array, or { pattern, flags? }',
  );
}

function loadRateLimit(
  value: JsonValue,
  path: string,
): RateLimitSpec {
  const obj = expectObject(value, path);
  const max = expectFiniteNumber(obj.max, `${path}.max`);
  const windowMs = expectFiniteNumber(obj.windowMs, `${path}.windowMs`);
  if (max < 1) {
    throw new RuleParseError(`${path}.max`, 'must be >= 1');
  }
  if (windowMs < 1) {
    throw new RuleParseError(`${path}.windowMs`, 'must be >= 1');
  }
  const keyPrefix =
    obj.keyPrefix === undefined
      ? undefined
      : expectString(obj.keyPrefix, `${path}.keyPrefix`);
  return keyPrefix === undefined
    ? { max, windowMs }
    : { max, windowMs, keyPrefix };
}

function loadCondition(value: JsonValue, path: string): WafCondition {
  const obj = expectObject(value, path);
  const keys = Object.keys(obj).filter((key) => obj[key] !== undefined);

  if ('all' in obj && obj.all !== undefined) {
    if (keys.some((key) => key !== 'all')) {
      throw new RuleParseError(path, '`all` cannot be mixed with other keys');
    }
    if (!isJsonArray(obj.all)) {
      throw new RuleParseError(`${path}.all`, 'expected an array');
    }
    return {
      all: obj.all.map((item, index) =>
        loadCondition(item, `${path}.all[${index}]`),
      ),
    };
  }

  if ('anyOf' in obj && obj.anyOf !== undefined) {
    if (keys.some((key) => key !== 'anyOf')) {
      throw new RuleParseError(path, '`anyOf` cannot be mixed with other keys');
    }
    if (!isJsonArray(obj.anyOf)) {
      throw new RuleParseError(`${path}.anyOf`, 'expected an array');
    }
    return {
      anyOf: obj.anyOf.map((item, index) =>
        loadCondition(item, `${path}.anyOf[${index}]`),
      ),
    };
  }

  if ('not' in obj && obj.not !== undefined) {
    if (keys.some((key) => key !== 'not')) {
      throw new RuleParseError(path, '`not` cannot be mixed with other keys');
    }
    return { not: loadCondition(obj.not, `${path}.not`) };
  }

  if (!('field' in obj) || obj.field === undefined) {
    throw new RuleParseError(
      path,
      'expected field condition or all / anyOf / not',
    );
  }

  const fieldRaw = expectString(obj.field, `${path}.field`);
  if (!isWafField(fieldRaw)) {
    throw new RuleParseError(
      `${path}.field`,
      `unsupported field "${fieldRaw}"`,
    );
  }

  const allowedFieldKeys = new Set([
    'field',
    'matches',
    'equals',
    'includes',
    'rateLimit',
  ]);
  const unexpected = keys.find((key) => !allowedFieldKeys.has(key));
  if (unexpected !== undefined) {
    throw new RuleParseError(path, `unexpected key "${unexpected}"`);
  }

  const matches =
    obj.matches === undefined
      ? undefined
      : loadMatchPattern(obj.matches, `${path}.matches`);
  const equals =
    obj.equals === undefined
      ? undefined
      : expectString(obj.equals, `${path}.equals`);
  const includes =
    obj.includes === undefined
      ? undefined
      : expectString(obj.includes, `${path}.includes`);
  const rateLimit =
    obj.rateLimit === undefined
      ? undefined
      : loadRateLimit(obj.rateLimit, `${path}.rateLimit`);

  if (
    matches === undefined &&
    equals === undefined &&
    includes === undefined &&
    rateLimit === undefined
  ) {
    throw new RuleParseError(
      path,
      'field condition needs matches, equals, includes, or rateLimit',
    );
  }

  return {
    field: fieldRaw,
    ...(matches !== undefined ? { matches } : {}),
    ...(equals !== undefined ? { equals } : {}),
    ...(includes !== undefined ? { includes } : {}),
    ...(rateLimit !== undefined ? { rateLimit } : {}),
  };
}

function loadMinLevel(
  value: JsonValue | undefined,
  path: string,
): ProtectionLevel | undefined {
  if (value === undefined) {
    return undefined;
  }
  const raw = expectString(value, path);
  if (!isProtectionLevel(raw)) {
    throw new RuleParseError(path, `invalid protection level "${raw}"`);
  }
  return raw;
}

function loadRule(value: JsonValue, path: string): WafRule {
  const obj = expectObject(value, path);
  const id = expectString(obj.id, `${path}.id`);
  if (id.length === 0) {
    throw new RuleParseError(`${path}.id`, 'must be non-empty');
  }
  if (obj.when === undefined) {
    throw new RuleParseError(`${path}.when`, 'required');
  }
  const when = loadCondition(obj.when, `${path}.when`);
  const actionRaw = expectString(obj.action, `${path}.action`);
  if (!isWafAction(actionRaw)) {
    throw new RuleParseError(
      `${path}.action`,
      `invalid action "${actionRaw}" (expected allow | block | log)`,
    );
  }

  const reason =
    obj.reason === undefined
      ? undefined
      : expectString(obj.reason, `${path}.reason`);
  const enabled =
    obj.enabled === undefined
      ? undefined
      : expectBoolean(obj.enabled, `${path}.enabled`);
  const priority =
    obj.priority === undefined
      ? undefined
      : expectFiniteNumber(obj.priority, `${path}.priority`);
  const minLevel = loadMinLevel(obj.minLevel, `${path}.minLevel`);

  const allowedKeys = new Set([
    'id',
    'when',
    'action',
    'reason',
    'enabled',
    'priority',
    'minLevel',
  ]);
  const unexpected = Object.keys(obj).find(
    (key) => obj[key] !== undefined && !allowedKeys.has(key),
  );
  if (unexpected !== undefined) {
    throw new RuleParseError(path, `unexpected key "${unexpected}"`);
  }

  return {
    id,
    when,
    action: actionRaw,
    ...(reason !== undefined ? { reason } : {}),
    ...(enabled !== undefined ? { enabled } : {}),
    ...(priority !== undefined ? { priority } : {}),
    ...(minLevel !== undefined ? { minLevel } : {}),
  };
}

/**
 * Compile a typed JSON value (array of rules, or `{ rules: [...] }`) into
 * live `WafRule` instances (RegExp compiled from `{ pattern, flags? }`).
 */
export function loadRules(value: JsonValue): readonly WafRule[] {
  if (isJsonArray(value)) {
    return value.map((item, index) => loadRule(item, `rules[${index}]`));
  }
  if (isJsonObject(value) && value.rules !== undefined) {
    if (!isJsonArray(value.rules)) {
      throw new RuleParseError('$.rules', 'expected an array');
    }
    return value.rules.map((item, index) =>
      loadRule(item, `$.rules[${index}]`),
    );
  }
  throw new RuleParseError(
    '$',
    'expected a JSON array of rules or an object with a "rules" array',
  );
}

/**
 * Parse a JSON string and compile rules.
 * Accepts either a top-level array or `{ "rules": [ ... ] }`.
 */
export function parseRulesFromJson(input: string): readonly WafRule[] {
  return loadRules(parseJsonDocument(input));
}

/** Re-export serializable types for consumers. */
export type {
  JsonMatchPattern,
  JsonWafCondition,
  JsonWafRule,
};
