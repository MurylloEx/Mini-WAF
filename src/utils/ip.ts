import { isIP, isIPv4, isIPv6 } from 'node:net';
import { LruCache } from '@/utils/lru';

/**
 * Pure client-IP helpers for dual-stack (IPv4 / IPv6 / IPv4-mapped) handling.
 * Prefer these over ad-hoc string compares so rate-limit keys and equals match.
 */

/** Cross-request LRU for normalized IP strings (article-style geo/IP memo). */
const IP_NORMALIZE_CACHE = new LruCache<string>(2048);

/** Strip surrounding whitespace and optional URI brackets (`[addr]`). */
function stripBrackets(raw: string): string {
  const trimmed = raw.trim();
  if (trimmed.startsWith('[') && trimmed.endsWith(']') && trimmed.length >= 2) {
    return trimmed.slice(1, -1);
  }
  return trimmed;
}

/** Drop IPv6 zone / scope id (`fe80::1%eth0`, `fe80::1%25eth0`). */
function stripZoneId(address: string): string {
  const pct = address.indexOf('%');
  return pct >= 0 ? address.slice(0, pct) : address;
}

function parseHextet(part: string): number | undefined {
  if (!/^[0-9a-fA-F]{1,4}$/.test(part)) {
    return undefined;
  }
  return Number.parseInt(part, 16);
}

function ipv4ToHextets(dotted: string): readonly [number, number] | undefined {
  if (!isIPv4(dotted)) {
    return undefined;
  }
  const octets = dotted.split('.').map((octet) => Number.parseInt(octet, 10));
  if (octets.length !== 4) {
    return undefined;
  }
  const [a, b, c, d] = octets;
  if (
    a === undefined ||
    b === undefined ||
    c === undefined ||
    d === undefined
  ) {
    return undefined;
  }
  return [((a & 0xff) << 8) | (b & 0xff), ((c & 0xff) << 8) | (d & 0xff)];
}

function parseIpv6Side(side: string): readonly number[] | undefined {
  if (side.length === 0) {
    return [];
  }

  return side.split(':').reduce<readonly number[] | undefined>((acc, part) => {
    if (acc === undefined) {
      return undefined;
    }
    if (part.includes('.')) {
      const mapped = ipv4ToHextets(part);
      if (mapped === undefined) {
        return undefined;
      }
      return [...acc, mapped[0], mapped[1]];
    }
    const hextet = parseHextet(part);
    if (hextet === undefined) {
      return undefined;
    }
    return [...acc, hextet];
  }, []);
}

/**
 * Expand an IPv6 textual form into eight 16-bit hextets.
 * Returns undefined when the address is not a well-formed IPv6 literal.
 */
function parseIpv6ToHextets(address: string): readonly number[] | undefined {
  const halves = address.split('::');
  if (halves.length > 2) {
    return undefined;
  }

  if (halves.length === 1) {
    const hextets = parseIpv6Side(halves[0] ?? '');
    if (hextets === undefined || hextets.length !== 8) {
      return undefined;
    }
    return hextets;
  }

  const left = parseIpv6Side(halves[0] ?? '');
  const right = parseIpv6Side(halves[1] ?? '');
  if (left === undefined || right === undefined) {
    return undefined;
  }

  const missing = 8 - left.length - right.length;
  if (missing < 0) {
    return undefined;
  }

  return [...left, ...Array.from({ length: missing }, () => 0), ...right];
}

function ipv4MappedFromHextets(
  hextets: readonly number[],
): string | undefined {
  if (hextets.length !== 8) {
    return undefined;
  }
  const prefixZero = hextets.slice(0, 5).every((value) => value === 0);
  if (!prefixZero || hextets[5] !== 0xffff) {
    return undefined;
  }
  const hi = hextets[6];
  const lo = hextets[7];
  if (hi === undefined || lo === undefined) {
    return undefined;
  }
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

function longestZeroRun(
  hextets: readonly number[],
): { readonly start: number; readonly length: number } {
  const runs = hextets.reduce<
    readonly { readonly start: number; readonly length: number }[]
  >((acc, value, index) => {
    if (value !== 0) {
      return acc;
    }
    const last = acc[acc.length - 1];
    if (last !== undefined && last.start + last.length === index) {
      return [
        ...acc.slice(0, -1),
        { start: last.start, length: last.length + 1 },
      ];
    }
    return [...acc, { start: index, length: 1 }];
  }, []);

  const best = runs.reduce(
    (current, run) => (run.length > current.length ? run : current),
    { start: -1, length: 0 },
  );

  return best.length >= 2 ? best : { start: -1, length: 0 };
}

/** RFC 5952-ish compressed lowercase IPv6 from eight hextets. */
function formatIpv6(hextets: readonly number[]): string {
  const run = longestZeroRun(hextets);
  if (run.length === 0) {
    return hextets.map((value) => value.toString(16)).join(':');
  }
  const head = hextets
    .slice(0, run.start)
    .map((value) => value.toString(16))
    .join(':');
  const tail = hextets
    .slice(run.start + run.length)
    .map((value) => value.toString(16))
    .join(':');
  return `${head}::${tail}`;
}

/**
 * Normalize a client IP for equality checks and rate-limit keys.
 *
 * - trims whitespace and strips `[brackets]`
 * - strips IPv6 zone ids
 * - collapses IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to dotted IPv4
 * - compresses equivalent IPv6 forms to a canonical lowercase representation
 * - leaves non-IP opaque strings intact after trim/bracket strip
 *
 * Results are memoized in a small process-local LRU (max 2048) to avoid
 * repeating expansion work for hot client IPs.
 */
export function normalizeClientIp(raw: string): string {
  const hit = IP_NORMALIZE_CACHE.get(raw);
  if (hit !== undefined) {
    return hit;
  }

  const prepared = stripZoneId(stripBrackets(raw));
  if (prepared.length === 0) {
    IP_NORMALIZE_CACHE.set(raw, '');
    return '';
  }

  if (isIPv4(prepared)) {
    IP_NORMALIZE_CACHE.set(raw, prepared);
    return prepared;
  }

  if (isIPv6(prepared) || prepared.includes(':')) {
    const hextets = parseIpv6ToHextets(prepared);
    if (hextets !== undefined) {
      const mapped = ipv4MappedFromHextets(hextets);
      if (mapped !== undefined) {
        IP_NORMALIZE_CACHE.set(raw, mapped);
        return mapped;
      }
      const compressed = formatIpv6(hextets);
      IP_NORMALIZE_CACHE.set(raw, compressed);
      return compressed;
    }
  }

  IP_NORMALIZE_CACHE.set(raw, prepared);
  return prepared;
}

/** Test / ops helper: clear the IP normalization LRU. */
export function clearIpNormalizeCache(): void {
  IP_NORMALIZE_CACHE.clear();
}

/** Test helper: current IP cache size. */
export function ipNormalizeCacheSize(): number {
  return IP_NORMALIZE_CACHE.size;
}

/**
 * First hop from `X-Forwarded-For` (comma-separated or multi-value header),
 * trimmed and passed through {@link normalizeClientIp}.
 */
export function pickClientIpFromXff(
  forwardedFor: string | readonly string[] | undefined,
): string {
  if (forwardedFor === undefined) {
    return '';
  }

  const firstHop =
    typeof forwardedFor === 'string'
      ? (forwardedFor.split(',')[0] ?? '')
      : (forwardedFor[0] ?? '');

  return normalizeClientIp(firstHop);
}

/**
 * True when a Host header value is a raw IP literal (IPv4 or bracketed IPv6),
 * optionally with a port. Used by the protocol Host-IP preset.
 */
export function isHostIpLiteral(hostHeader: string): boolean {
  const host = hostHeader.trim();
  if (host.length === 0) {
    return false;
  }

  if (host.startsWith('[')) {
    const close = host.indexOf(']');
    if (close < 0) {
      return false;
    }
    const literal = host.slice(1, close);
    const rest = host.slice(close + 1);
    if (rest.length > 0 && !/^:\d{1,5}$/.test(rest)) {
      return false;
    }
    return isIP(stripZoneId(literal)) !== 0;
  }

  const lastColon = host.lastIndexOf(':');
  if (lastColon > 0 && /^\d{1,5}$/.test(host.slice(lastColon + 1))) {
    const withoutPort = host.slice(0, lastColon);
    return isIPv4(withoutPort);
  }

  return isIP(host) !== 0;
}
