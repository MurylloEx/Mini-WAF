import type { WafField } from '@/domain/rules';
import type { WafHttpContext } from '@/domain/context';
import { fileDisplayName, scalarToString } from '@/domain/values';
import {
  expandBase64Candidates,
  extractJsonStringValues,
  type DecodeSettings,
} from '@/engine/decode';

export interface FieldResolveOptions {
  /** Truncate each candidate string to this length. `0` = unlimited. */
  readonly maxFieldLength: number;
  /**
   * Optional per-request memo (field → values).
   * Mutated only as a cache; entries are immutable arrays.
   */
  readonly memo?: Map<WafField, readonly string[]>;
  /**
   * Optional per-request memo of lowercased field values for `includes`.
   * Populated lazily from {@link resolveFieldValues}.
   */
  readonly memoLower?: Map<WafField, readonly string[]>;
  /**
   * Transport-decode settings. When absent (or `base64: false`), the match
   * resolvers below delegate straight to the raw resolvers, so the match path
   * is byte-for-byte the pre-decode behaviour and costs no extra lookup.
   */
  readonly decode?: DecodeSettings;
  /** Per-request memo of the match bag (raw values + decoded extras). */
  readonly memoMatch?: Map<WafField, readonly string[]>;
  /** Per-request memo of the match bag, lowercased. */
  readonly memoMatchLower?: Map<WafField, readonly string[]>;
}

const DEFAULT_OPTIONS: FieldResolveOptions = {
  maxFieldLength: 0,
};

function truncateValue(value: string, maxFieldLength: number): string {
  if (maxFieldLength <= 0 || value.length <= maxFieldLength) {
    return value;
  }
  return value.slice(0, maxFieldLength);
}

function truncateAll(
  values: readonly string[],
  maxFieldLength: number,
): readonly string[] {
  if (maxFieldLength <= 0) {
    return values;
  }
  return values.map((value) => truncateValue(value, maxFieldLength));
}

function resolveFieldValuesRaw(
  ctx: WafHttpContext,
  field: WafField,
): readonly string[] {
  if (field === 'ip') {
    return [ctx.getIp()];
  }
  if (field === 'method') {
    return [ctx.getMethod()];
  }
  if (field === 'path') {
    return [ctx.getPath()];
  }
  if (field === 'url') {
    return [ctx.getUrl()];
  }
  if (field === 'body') {
    return [ctx.getRawBody()];
  }
  if (field === 'files') {
    return ctx
      .getFiles()
      .map(fileDisplayName)
      .filter((name) => name.length > 0);
  }
  if (field === 'query') {
    const query = ctx.getQuery();
    return Object.keys(query).map((key) => scalarToString(query[key]));
  }
  if (field === 'headers') {
    const headers = ctx.getHeaders();
    return Object.keys(headers).map((key) => scalarToString(headers[key]));
  }
  if (field === 'cookies') {
    const cookies = ctx.getCookies();
    return Object.keys(cookies).map((key) => cookies[key] ?? '');
  }

  if (field.startsWith('query.')) {
    const key = field.slice('query.'.length);
    return [scalarToString(ctx.getQuery()[key])];
  }
  if (field.startsWith('headers.')) {
    const key = field.slice('headers.'.length).toLowerCase();
    const direct = ctx.getHeader(key);
    if (direct !== undefined) {
      return [direct];
    }
    return [scalarToString(ctx.getHeaders()[key])];
  }
  if (field.startsWith('cookies.')) {
    const key = field.slice('cookies.'.length);
    return [ctx.getCookies()[key] ?? ''];
  }

  return [];
}

/**
 * Resolve one or more string candidates for a field path.
 * Multi-value fields (query, headers, cookies, files) return every value
 * so the matcher can OR across them.
 *
 * When `maxFieldLength` is set, each candidate is truncated before matching
 * (rate-limit key material uses the same truncated view).
 */
export function resolveFieldValues(
  ctx: WafHttpContext,
  field: WafField,
  options: FieldResolveOptions = DEFAULT_OPTIONS,
): readonly string[] {
  const cached = options.memo?.get(field);
  if (cached !== undefined) {
    return cached;
  }

  const resolved = truncateAll(
    resolveFieldValuesRaw(ctx, field),
    options.maxFieldLength,
  );

  options.memo?.set(field, resolved);
  return resolved;
}

/**
 * Same candidates as {@link resolveFieldValues}, already lowercased.
 * Used by case-insensitive `includes` so multi-value bags do not re-lower
 * the same strings for every rule.
 */
export function resolveFieldValuesLower(
  ctx: WafHttpContext,
  field: WafField,
  options: FieldResolveOptions = DEFAULT_OPTIONS,
): readonly string[] {
  const cached = options.memoLower?.get(field);
  if (cached !== undefined) {
    return cached;
  }

  const lowered = resolveFieldValues(ctx, field, options).map((value) =>
    value.toLowerCase(),
  );

  options.memoLower?.set(field, lowered);
  return lowered;
}

/**
 * Match-path candidate bag for a field: the raw values plus any decoded extras
 * (Base64 today). This is what `matches`/`includes` scan — never rate-limit key
 * material or `equals` reference identity.
 *
 * When decoding is off it delegates straight to {@link resolveFieldValues}, so
 * the hot path pays exactly one memo lookup, identical to the pre-decode
 * behaviour. When on, the decode funnel runs once per field and the merged bag
 * is memoized, so every subsequent leaf condition is again a single lookup.
 */
export function resolveFieldMatchValues(
  ctx: WafHttpContext,
  field: WafField,
  options: FieldResolveOptions = DEFAULT_OPTIONS,
): readonly string[] {
  const decode = options.decode;
  if (decode === undefined || !decode.base64) {
    return resolveFieldValues(ctx, field, options);
  }
  const cached = options.memoMatch?.get(field);
  if (cached !== undefined) {
    return cached;
  }

  const raw = resolveFieldValues(ctx, field, options);
  // A payload delivered as one JSON body *value* (`{"q":"<base64>"}`) is not a
  // whole-value Base64 string on its own — the raw body is `{...}`. Pull the
  // JSON string leaves so the decoder can reach it. Feeds the decoder only; the
  // raw body is already scanned as a blob, so no plaintext candidate is added.
  const decodeInput =
    field === 'body' && raw.length > 0
      ? [...raw, ...extractJsonStringValues(raw[0] ?? '')]
      : raw;
  const extras = expandBase64Candidates(decodeInput, decode);
  // No decodable candidate: reuse the raw array reference verbatim, so the
  // lowercased resolver below can detect the no-extras case by identity and
  // skip re-lowering a possibly large body.
  const merged = extras.length === 0 ? raw : [...raw, ...extras];

  options.memoMatch?.set(field, merged);
  return merged;
}

/**
 * Lowercased {@link resolveFieldMatchValues}. Reuses the lowercased raw bag when
 * no extras were produced, and otherwise appends only the lowercased extras, so
 * the raw values (e.g. an 8 KB body) are never lowered twice.
 */
export function resolveFieldMatchValuesLower(
  ctx: WafHttpContext,
  field: WafField,
  options: FieldResolveOptions = DEFAULT_OPTIONS,
): readonly string[] {
  const decode = options.decode;
  if (decode === undefined || !decode.base64) {
    return resolveFieldValuesLower(ctx, field, options);
  }
  const cached = options.memoMatchLower?.get(field);
  if (cached !== undefined) {
    return cached;
  }

  const merged = resolveFieldMatchValues(ctx, field, options);
  const rawLower = resolveFieldValuesLower(ctx, field, options);
  // `merged === raw` (same reference) means no extras were appended.
  const lowered =
    merged === resolveFieldValues(ctx, field, options)
      ? rawLower
      : [
          ...rawLower,
          ...merged
            .slice(rawLower.length)
            .map((value) => value.toLowerCase()),
        ];

  options.memoMatchLower?.set(field, lowered);
  return lowered;
}

/** Join all candidates — useful as rate-limit key material. */
export function resolveFieldJoined(
  ctx: WafHttpContext,
  field: WafField,
  options: FieldResolveOptions = DEFAULT_OPTIONS,
): string {
  return resolveFieldValues(ctx, field, options).join('|');
}
