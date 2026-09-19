import type { WafHttpContext } from '@/domain/context';
import type { HeaderMap, QueryMap } from '@/domain/values';
import { scalarToString } from '@/domain/values';

/**
 * Stable djb2 hash → unsigned hex (no crypto dep).
 * Walks char codes directly (no intermediate array allocation) since this
 * runs on the decisionCache fingerprint hot path (method/path/ip/query/UA/
 * body-slice, up to `FINGERPRINT_BODY_MAX` chars).
 */
export function hashString(input: string): string {
  let hash = 5381;
  for (let index = 0; index < input.length; index += 1) {
    hash = ((hash << 5) + hash + input.charCodeAt(index)) | 0;
  }
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
