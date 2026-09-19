import type { WafField } from '@/domain/rules';
import type { WafHttpContext } from '@/domain/context';
import { fileDisplayName, scalarToString } from '@/domain/values';

/**
 * Resolve one or more string candidates for a field path.
 * Multi-value fields (query, headers, cookies, files) return every value
 * so the matcher can OR across them.
 */
export function resolveFieldValues(
  ctx: WafHttpContext,
  field: WafField,
): string[] {
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
    return ctx.getFiles().map(fileDisplayName).filter((name) => name.length > 0);
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

/** Join all candidates — useful as rate-limit key material. */
export function resolveFieldJoined(
  ctx: WafHttpContext,
  field: WafField,
): string {
  return resolveFieldValues(ctx, field).join('|');
}
