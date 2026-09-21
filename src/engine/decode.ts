import { Buffer } from 'node:buffer';
import type { JsonValue } from '@/domain/values';

/**
 * Transport-decode settings. Resolved once per engine (see `resolveDecode` in
 * `src/engine/engine.ts`) and threaded through field resolution.
 *
 * Decoding is a *matching-only* concern: decoded variants are appended to the
 * candidate bag scanned by `matches`/`includes`, never to rate-limit key
 * material or `equals` semantics. Existing preset rules therefore scan the
 * decoded form with zero rule changes.
 */
export interface DecodeSettings {
  /**
   * Decode whole-value Base64 payloads and rescan the decoded text.
   * Targets encoders (e.g. GoTestWAF `Base64Flat`) that wrap an entire
   * attack string in one Base64 blob, which no plaintext regex can reach.
   */
  readonly base64: boolean;
}

/** Shared empty result so `values === rawValues` when nothing decodes. */
const NO_EXTRAS: readonly string[] = [];

/**
 * Minimum length before a value is even considered Base64. Short tokens carry
 * no useful attack payload once decoded and are the noisiest false-positive
 * source for the shape test.
 */
const MIN_BASE64_LENGTH = 16;

/**
 * Hard cap on decoded candidates produced per field per request. A request
 * with hundreds of Base64-looking parameters cannot fan the rescan out
 * unboundedly; real payloads sit far under this.
 */
const MAX_DECODED_CANDIDATES = 16;

/**
 * Maximum fraction of non-printable bytes tolerated in the decoded output.
 * This is the load-bearing gate: high-entropy identifiers that survive the
 * shape test (dashless UUIDs, hex hashes, encrypted cookies, image/data blobs,
 * JWT signature segments) decode to binary noise and are rejected here, *before*
 * the expensive regex battery ever runs on them.
 */
const MAX_NONPRINTABLE_RATIO = 0.1;

/**
 * Whole-value standard Base64 shape (padded, so length is always a multiple of
 * four). Anchored: any value carrying a space, `@`, `{`, `:`, `.`, `-`, `_`
 * (i.e. essentially all real query/body/cookie text, and Base64url/JWT with
 * their separators) fails within the first few characters — cheaper than a
 * single detection regex.
 */
const BASE64_SHAPE = /^[A-Za-z0-9+/]+={0,2}$/;

function looksLikeBase64(value: string): boolean {
  const length = value.length;
  if (length < MIN_BASE64_LENGTH || length % 4 !== 0) {
    return false;
  }
  return BASE64_SHAPE.test(value);
}

function isMostlyPrintable(buffer: Buffer): boolean {
  const length = buffer.length;
  if (length === 0) {
    return false;
  }
  // Largest non-printable count that still satisfies the ratio. Once we exceed
  // it the result can only be `false`, so we bail without scanning the rest —
  // binary blobs (the common rejection) fail in the first few percent instead
  // of being walked to the end.
  const maxNonPrintable = Math.floor(length * MAX_NONPRINTABLE_RATIO);
  // Hot byte loop: a single mutable counter is the sanctioned accumulator here
  // (see CLAUDE.md "avoid let"). Allow tab / LF / CR plus printable ASCII.
  let nonPrintable = 0;
  for (const byte of buffer) {
    const printable =
      byte === 9 ||
      byte === 10 ||
      byte === 13 ||
      (byte >= 0x20 && byte <= 0x7e);
    if (!printable) {
      nonPrintable += 1;
      if (nonPrintable > maxNonPrintable) {
        return false;
      }
    }
  }
  return true;
}

function decodeBase64(value: string): string | undefined {
  const buffer = Buffer.from(value, 'base64');
  if (buffer.length === 0 || !isMostlyPrintable(buffer)) {
    return undefined;
  }
  return buffer.toString('utf8');
}

/**
 * Expand a field's raw candidate values with their Base64-decoded forms.
 *
 * The pipeline is a cost funnel — each stage rejects the bulk of traffic before
 * the next, more expensive one:
 * 1. shape test (anchored char-class + length) — kills nearly all benign text;
 * 2. length cap — bounds fan-out;
 * 3. decode + printable-ratio gate — rejects high-entropy non-text blobs so the
 *    regex battery only ever sees plausible decoded payloads.
 *
 * Returns a shared empty array when decoding is off or nothing qualifies, so
 * the caller can keep `values === rawValues` and avoid any allocation.
 */
export function expandBase64Candidates(
  values: readonly string[],
  settings: DecodeSettings,
): readonly string[] {
  if (!settings.base64) {
    return NO_EXTRAS;
  }
  const shaped = values.filter(looksLikeBase64);
  if (shaped.length === 0) {
    return NO_EXTRAS;
  }
  const decoded = shaped
    .slice(0, MAX_DECODED_CANDIDATES)
    .map(decodeBase64)
    .filter((value): value is string => value !== undefined);
  return decoded.length === 0 ? NO_EXTRAS : decoded;
}

/** Bound the JSON walk so a hostile nested body cannot blow up the scan. */
const MAX_JSON_VALUES = 64;
const MAX_JSON_DEPTH = 6;

function safeParseJson(raw: string): JsonValue | undefined {
  try {
    // JSON.parse is typed `any`; land it straight into a typed binding so no
    // `any` escapes into the module.
    const parsed: JsonValue = JSON.parse(raw);
    return parsed;
  } catch {
    return undefined;
  }
}

function collectJsonStrings(
  node: JsonValue | undefined,
  depth: number,
  out: string[],
): void {
  if (out.length >= MAX_JSON_VALUES) {
    return;
  }
  if (typeof node === 'string') {
    // Only strings long enough to be a Base64 payload are worth carrying —
    // the decoder floor rejects the rest anyway.
    if (node.length >= MIN_BASE64_LENGTH) {
      out.push(node);
    }
    return;
  }
  if (depth >= MAX_JSON_DEPTH || node === null || typeof node !== 'object') {
    return;
  }
  // Object.values covers arrays and objects alike (Array.isArray does not
  // narrow a readonly element type), so both containers recurse the same way.
  for (const item of Object.values(node)) {
    if (out.length >= MAX_JSON_VALUES) {
      break;
    }
    collectJsonStrings(item, depth + 1, out);
  }
}

/**
 * Pull the string leaf values out of a JSON body so an encoded payload carried
 * as one JSON *value* — `{"q":"<base64>"}` — becomes a whole-value candidate the
 * Base64 decoder can reach. The raw body is scanned as one blob elsewhere, so
 * this feeds the decoder only; it does not add plaintext match candidates.
 *
 * Bounded in depth and count, and gated by a one-char JSON sniff so non-JSON
 * bodies pay nothing beyond that check.
 */
export function extractJsonStringValues(raw: string): readonly string[] {
  const trimmed = raw.trimStart();
  const first = trimmed.charCodeAt(0);
  // '{' (0x7b), '[' (0x5b), '"' (0x22) — anything else is not a JSON container
  // or string worth parsing.
  if (first !== 0x7b && first !== 0x5b && first !== 0x22) {
    return NO_EXTRAS;
  }
  const parsed = safeParseJson(raw);
  if (parsed === undefined) {
    return NO_EXTRAS;
  }
  const out: string[] = [];
  collectJsonStrings(parsed, 0, out);
  return out.length === 0 ? NO_EXTRAS : out;
}
