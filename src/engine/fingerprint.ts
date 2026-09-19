import type { WafHttpContext } from '@/domain/context';
import type { HeaderMap, QueryMap } from '@/domain/values';
import { scalarToString } from '@/domain/values';

/** Stable djb2 hash → unsigned hex (no crypto dep). */
export function hashString(input: string): string {
  const hash = Array.from({ length: input.length }).reduce<number>(
    (acc, _, index) => ((acc << 5) + acc + input.charCodeAt(index)) | 0,
    5381,
  );
  return (hash >>> 0).toString(16);
}

function sortedQueryMaterial(query: QueryMap): string {
  return Object.keys(query)
    .sort()
    .map((key) => `${key}=${scalarToString(query[key])}`)
    .join('&');
}

function userAgent(headers: HeaderMap): string {
  const value = headers['user-agent'] ?? headers['User-Agent'];
  return scalarToString(value);
}

/**
 * Compact fingerprint for optional decision caching.
 * Includes method, path, IP, query, UA, and a truncated body hash.
 */
export function requestFingerprint(
  ctx: WafHttpContext,
  bodyHashMax: number,
): string {
  const body = ctx.getRawBody();
  const bodySlice =
    bodyHashMax > 0 && body.length > bodyHashMax
      ? body.slice(0, bodyHashMax)
      : body;
  return [
    ctx.getMethod(),
    ctx.getPath(),
    ctx.getIp(),
    hashString(sortedQueryMaterial(ctx.getQuery())),
    hashString(userAgent(ctx.getHeaders())),
    hashString(bodySlice),
  ].join('|');
}
