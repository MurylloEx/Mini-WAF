import type { WafField } from '@/domain/rules';
import type { WafHttpContext } from '@/domain/context';
import { fileDisplayName, scalarToString } from '@/domain/values';

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

/** Join all candidates — useful as rate-limit key material. */
export function resolveFieldJoined(
  ctx: WafHttpContext,
  field: WafField,
  options: FieldResolveOptions = DEFAULT_OPTIONS,
): string {
  return resolveFieldValues(ctx, field, options).join('|');
}
