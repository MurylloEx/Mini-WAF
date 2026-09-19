import type { CookieMap } from '@/domain/values';

/** Decode a single cookie value (default: `decodeURIComponent`). */
export type CookieDecoder = (value: string) => string;

function isNonEmptyHeader(header: string | undefined): header is string {
  return typeof header === 'string' && header.length > 0;
}

function splitCookiePairs(header: string): readonly string[] {
  return header.split(/; */);
}

function unwrapQuotedValue(value: string): string {
  if (value.length >= 2 && value.startsWith('"') && value.endsWith('"')) {
    return value.slice(1, -1);
  }
  return value;
}

function decodeCookieValue(value: string, decode: CookieDecoder): string {
  try {
    return decode(value);
  } catch {
    return value;
  }
}

/**
 * Split one `name=value` segment. Returns undefined when `=` is missing.
 */
function parseCookiePair(
  pair: string,
): readonly [name: string, value: string] | undefined {
  const separatorIndex = pair.indexOf('=');
  if (separatorIndex < 0) {
    return undefined;
  }

  const name = pair.slice(0, separatorIndex).trim();
  const rawValue = pair.slice(separatorIndex + 1).trim();
  return [name, unwrapQuotedValue(rawValue)];
}

function withDecodedCookie(
  cookies: CookieMap,
  name: string,
  value: string,
  decode: CookieDecoder,
): CookieMap {
  if (cookies[name] !== undefined) {
    return cookies;
  }
  return { ...cookies, [name]: decodeCookieValue(value, decode) };
}

/**
 * Parse a Cookie request header into a name→value map.
 * The first occurrence of each name wins (browser / proxy duplicates).
 */
export function parseCookies(
  header: string | undefined,
  decode: CookieDecoder = decodeURIComponent,
): CookieMap {
  if (!isNonEmptyHeader(header)) {
    return {};
  }

  return splitCookiePairs(header).reduce<CookieMap>((cookies, pair) => {
    const parsed = parseCookiePair(pair);
    if (parsed === undefined) {
      return cookies;
    }
    const [name, value] = parsed;
    return withDecodedCookie(cookies, name, value, decode);
  }, {});
}
