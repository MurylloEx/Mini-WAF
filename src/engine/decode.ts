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
  /**
   * Percent-decode candidate values and rescan the decoded text. Targets
   * payloads delivered percent-encoded on surfaces the framework does not
   * decode itself — URL path segments, multipart parts, raw bodies — where an
   * attack like `%3Cimg%20src…` never reaches a plaintext regex.
   */
  readonly url: boolean;
  /**
   * Strip inline SQL comments (`SELECT/**\/value/**\/FROM`) and rescan the
   * de-obfuscated text. Targets the `space2comment` family of SQLi tampers,
   * which slice `/**\/` between tokens so keyword-adjacency patterns
   * (`preset-sqli-select-from`, union, boolean) never see them as adjacent.
   */
  readonly comments: boolean;
}

/** What a raw body hides a payload in, beyond its own text. */
export interface BodyValues {
  /**
   * Long JSON string leaves, form values or multipart field contents: decoder
   * input, since a payload in one of them is not a whole-value blob inside the
   * body.
   */
  readonly values: readonly string[];
  /**
   * The JSON strings (keys and values) written with `\u` or `\/` escapes,
   * decoded: the text the application receives, which the raw body only shows
   * escaped.
   */
  readonly escaped: readonly string[];
}

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/**
 * Minimum length before a value is even considered Base64. Short tokens carry
 * no useful attack payload once decoded and are the noisiest false-positive
 * source for the shape test. Also the floor for the pieces split out of a path
 * or body: shorter ones could never pass it.
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

/** Bound the path split so a pathological path cannot fan the rescan out. */
const MAX_PATH_SEGMENTS = 24;

/**
 * Bound the values pulled out of one body (JSON leaves, form values, multipart
 * fields), and the JSON walk, so a hostile body cannot blow up the scan.
 */
const MAX_BODY_VALUES = 64;
const MAX_JSON_DEPTH = 6;

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/** Shared empty result so `values === rawValues` when nothing decodes. */
const NO_EXTRAS: readonly string[] = [];

/**
 * `pick` applied to each item, keeping the defined results up to `limit`. The
 * shared empty array stands for "nothing", so callers can test by identity and
 * clean traffic allocates nothing.
 */
function collect<T>(
  items: readonly T[],
  limit: number,
  pick: (item: T) => string | undefined,
): readonly string[] {
  // Allocated on the first pick: most fields yield nothing, and this runs for
  // every field of every request. A sanctioned mutable accumulator (see
  // CLAUDE.md "avoid let"), capped so a hostile input cannot fan out.
  let out: string[] | undefined;
  for (const item of items) {
    const picked = pick(item);
    if (picked !== undefined) {
      if (out === undefined) {
        out = [picked];
      } else {
        out.push(picked);
      }
      if (out.length >= limit) {
        break;
      }
    }
  }
  return out ?? NO_EXTRAS;
}

/** `value` when it is long enough to carry a Base64 payload. */
function longEnough(value: string): string | undefined {
  return value.length >= MIN_BASE64_LENGTH ? value : undefined;
}

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

// ---------------------------------------------------------------------------
// Base64
// ---------------------------------------------------------------------------

/**
 * Whole-value standard Base64 shape. Anchored: any value carrying a space, `@`,
 * `{`, `:`, `.`, `-`, `_` (i.e. essentially all real query/body/cookie text, and
 * Base64url/JWT with their separators) fails within the first few characters —
 * cheaper than a single detection regex. Trailing `=` padding is optional: many
 * encoders (e.g. GoTestWAF `Base64Flat`) emit unpadded output.
 */
const BASE64_SHAPE = /^[A-Za-z0-9+/]+={0,2}$/;

function looksLikeBase64(value: string): boolean {
  const length = value.length;
  // A valid Base64 body has length % 4 in {0, 2, 3}; only a remainder of 1 is
  // impossible, so it is the single length we can reject outright. Requiring a
  // multiple of four would drop every unpadded blob — the bulk of real
  // Base64-wrapped attack traffic. `Buffer.from(_, 'base64')` decodes the
  // unpadded forms natively, so no synthetic padding is needed here.
  if (length < MIN_BASE64_LENGTH || length % 4 === 1) {
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
  // (see CLAUDE.md "avoid let"). Counting with a regex over a latin1 copy
  // loses the early exit and measured ~10x slower on binary blobs. Allow
  // tab / LF / CR plus printable ASCII.
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
  // One pass, allocating only for a decoded value: this runs for every field
  // of every request and almost never finds one. The cap counts shaped values,
  // before decoding, so it bounds the decode work itself. Sanctioned mutable
  // accumulators (see CLAUDE.md "avoid let").
  let out: string[] | undefined;
  let shaped = 0;
  for (const value of values) {
    if (looksLikeBase64(value)) {
      const decoded = decodeBase64(value);
      if (decoded !== undefined) {
        if (out === undefined) {
          out = [decoded];
        } else {
          out.push(decoded);
        }
      }
      shaped += 1;
      if (shaped >= MAX_DECODED_CANDIDATES) {
        break;
      }
    }
  }
  return out ?? NO_EXTRAS;
}

// ---------------------------------------------------------------------------
// Percent-encoding
// ---------------------------------------------------------------------------

/**
 * Percent-decode a single value once, but only when it is worth it: a value
 * with no `%` cannot change, and a malformed escape (`%`, `%ZZ`) makes
 * `decodeURIComponent` throw — both cases return `undefined` so the caller adds
 * no candidate. A decode that leaves the value unchanged is also dropped, so
 * already-decoded traffic (e.g. Express-decoded query params) costs nothing
 * beyond the `includes` check.
 */
function decodeUrlOnce(value: string): string | undefined {
  if (!value.includes('%')) {
    return undefined;
  }
  try {
    const decoded = decodeURIComponent(value);
    return decoded === value ? undefined : decoded;
  } catch {
    return undefined;
  }
}

/**
 * Expand a field's raw candidate values with their percent-decoded forms. Only
 * values that actually contain a valid `%XX` escape produce an extra candidate,
 * so clean traffic pays a single `String.includes('%')` per value and allocates
 * nothing. Bounded by the same fan-out cap as the Base64 funnel.
 */
export function expandUrlCandidates(
  values: readonly string[],
  settings: DecodeSettings,
): readonly string[] {
  return settings.url
    ? collect(values, MAX_DECODED_CANDIDATES, decodeUrlOnce)
    : NO_EXTRAS;
}

// ---------------------------------------------------------------------------
// Inline SQL comments
// ---------------------------------------------------------------------------

/**
 * A single inline SQL comment used as a token separator. Three deliberate
 * guards keep this to the evasion form and off legitimate commented code:
 * - `(?!!)` preserves *versioned* comments (`/*!50000SELECT*\/`): the database
 *   executes their body, so stripping them would delete the payload — and they
 *   are already caught by `preset-sqli-versioned-comment`;
 * - `[^*]{0,32}?` matches only *short* comments (the separator form `/**\/`,
 *   `/*a*\/`), never a long prose comment, so `/* explanation … *\/` in a posted
 *   code snippet is left intact and not re-interpreted;
 * - the global flag removes every occurrence in one linear pass.
 */
const INLINE_SQL_COMMENT = /\/\*(?!!)[^*]{0,32}?\*\//g;

/**
 * Delete inline SQL comments from a value so `SELECT/**\/value/**\/FROM`
 * collapses to `SELECT value FROM` for the rescan. Each comment becomes a
 * single space, so tokens split by a comment do not fuse (`a/**\/b` → `a b`).
 * Returns `undefined` when the value carries no `/*` (cheap one-`indexOf` gate)
 * or when nothing changed, so the caller adds no candidate.
 */
function stripInlineSqlComments(value: string): string | undefined {
  if (value.indexOf('/*') === -1) {
    return undefined;
  }
  const stripped = value.replace(INLINE_SQL_COMMENT, ' ');
  return stripped === value ? undefined : stripped;
}

/**
 * Expand a field's raw candidate values with their comment-stripped forms, so
 * the existing SQLi keyword patterns see `space2comment`-tampered payloads as
 * plain adjacent keywords. Clean traffic pays a single `String.indexOf('/*')`
 * per value and allocates nothing; bounded by the shared fan-out cap.
 */
export function expandCommentCandidates(
  values: readonly string[],
  settings: DecodeSettings,
): readonly string[] {
  return settings.comments
    ? collect(values, MAX_DECODED_CANDIDATES, stripInlineSqlComments)
    : NO_EXTRAS;
}

// ---------------------------------------------------------------------------
// URL path segments
// ---------------------------------------------------------------------------

/**
 * Split a URL path into its `/`-separated segments so a payload delivered as one
 * path segment — `/download/<base64>` — becomes a whole-value candidate the
 * decoders can reach. The whole path string is not itself a Base64 blob (its
 * separators fail the anchored shape), so without this the segment is never
 * decoded. Feeds the decoders only; the raw path is already scanned as one
 * string, so no plaintext candidate is added. Only segments long enough to
 * carry a Base64 payload are kept, and the split is count-bounded.
 */
export function extractPathSegments(raw: string): readonly string[] {
  // A path shorter than one segment's floor cannot hold a long segment.
  if (raw.length < MIN_BASE64_LENGTH || raw.indexOf('/') === -1) {
    return NO_EXTRAS;
  }
  return collect(raw.split('/'), MAX_PATH_SEGMENTS, longEnough);
}

// ---------------------------------------------------------------------------
// Body values: JSON, multipart and urlencoded form
// ---------------------------------------------------------------------------

/**
 * Split a raw body the way a framework's body parsers would: JSON, then
 * multipart, then urlencoded form. A body the framework already parsed arrives
 * as JSON and takes the first branch. Bounded in depth and count.
 */
export function extractBodyValues(raw: string): BodyValues {
  if (startsLikeJson(raw)) {
    if (!worthParsingAsJson(raw)) {
      return NO_BODY_VALUES;
    }
    const parsed = safeParseJson(raw);
    if (parsed !== undefined) {
      return { values: jsonValues(parsed), escaped: escapedJsonStrings(raw) };
    }
  }
  const delimiter = multipartDelimiter(raw);
  if (delimiter !== undefined) {
    return { values: multipartValues(raw, delimiter), escaped: NO_EXTRAS };
  }
  return {
    values: looksLikeForm(raw) ? formValues(raw) : NO_EXTRAS,
    escaped: NO_EXTRAS,
  };
}

// --- JSON -------------------------------------------------------------------

const NO_BODY_VALUES: BodyValues = { values: NO_EXTRAS, escaped: NO_EXTRAS };

/**
 * A string literal with at least {@link MIN_BASE64_LENGTH} units of content,
 * an escape counting once.
 */
const LONG_JSON_LITERAL = new RegExp(
  `"(?:[^"\\\\]|\\\\[\\s\\S]){${MIN_BASE64_LENGTH}}`,
);

/**
 * Whether the body opens like JSON: '{' (0x7b), '[' (0x5b) or '"' (0x22).
 * Anything else is not a JSON container or string worth parsing, so non-JSON
 * bodies pay nothing beyond this check.
 */
function startsLikeJson(raw: string): boolean {
  const first = raw.trimStart().charCodeAt(0);
  return first === 0x7b || first === 0x5b || first === 0x22;
}

/**
 * Whether parsing a JSON-looking body can find anything, checked in one cheap
 * pass instead of a parse:
 * - a decoded string is never longer than its literal, so without a literal of
 *   {@link MIN_BASE64_LENGTH} units no string leaf is long enough;
 * - without a `\u` or `\/` escape there is no escaped string to decode;
 * - without a `=` an invalid body could not be read as a form either.
 */
function worthParsingAsJson(raw: string): boolean {
  return (
    LONG_JSON_LITERAL.test(raw) ||
    nextHidingEscape(raw, 0) !== -1 ||
    raw.includes('=')
  );
}

/** The long string leaves of a parsed JSON body, depth- and count-bounded. */
function jsonValues(parsed: JsonValue): readonly string[] {
  const out: string[] = [];
  collectJsonStrings(parsed, 0, out);
  return out.length === 0 ? NO_EXTRAS : out;
}

function collectJsonStrings(
  node: JsonValue | undefined,
  depth: number,
  out: string[],
): void {
  if (out.length >= MAX_BODY_VALUES) {
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
    if (out.length >= MAX_BODY_VALUES) {
      break;
    }
    collectJsonStrings(item, depth + 1, out);
  }
}

/**
 * The JSON strings (keys and values) written with `\u` or `\/` escapes,
 * decoded by the JSON parser. Only valid JSON reaches here, so each escape is
 * found directly and nothing else in the body is walked. Capped like every
 * decoder's output.
 *
 * The cursors here and in the helpers below are the sanctioned `let`s (see
 * CLAUDE.md "avoid let"): `indexOf` jumps from one backslash or quote to the
 * next, while matching every string literal with `matchAll` measured 30-40x
 * slower on a body holding an escape, and recursion would overflow the stack
 * on a long run of backslashes.
 */
function escapedJsonStrings(raw: string): readonly string[] {
  const out: string[] = [];
  let escape = nextHidingEscape(raw, 0);
  while (escape !== -1 && out.length < MAX_DECODED_CANDIDATES) {
    const literal = enclosingLiteral(raw, escape);
    if (literal === undefined) {
      break;
    }
    const decoded = safeParseJson(raw.slice(literal.start, literal.end + 1));
    if (typeof decoded === 'string') {
      out.push(decoded);
    }
    escape = nextHidingEscape(raw, literal.end + 1);
  }
  return out.length === 0 ? NO_EXTRAS : out;
}

/**
 * The next `\u` or `\/` escape at or after `from`, or -1. Walks escape by
 * escape, so the second backslash of `\\` never starts one.
 */
function nextHidingEscape(raw: string, from: number): number {
  let at = raw.indexOf('\\', from);
  while (at !== -1) {
    const kind = raw.charAt(at + 1);
    if (kind === 'u' || kind === '/') {
      return at;
    }
    at = raw.indexOf('\\', at + 2);
  }
  return -1;
}

/**
 * The string literal (quotes included) holding the character at `inside`. In
 * valid JSON a backslash only occurs inside a string, and every `"` inside one
 * is escaped, so the nearest unescaped quotes around it delimit it.
 */
function enclosingLiteral(
  raw: string,
  inside: number,
): { readonly start: number; readonly end: number } | undefined {
  let start = raw.lastIndexOf('"', inside);
  while (start !== -1 && !isUnescapedQuote(raw, start)) {
    start = raw.lastIndexOf('"', start - 1);
  }
  let end = raw.indexOf('"', inside);
  while (end !== -1 && !isUnescapedQuote(raw, end)) {
    end = raw.indexOf('"', end + 1);
  }
  return start === -1 || end === -1 ? undefined : { start, end };
}

/**
 * Whether the `"` at `quote` is unescaped: an odd run of backslashes before it
 * escapes it.
 */
function isUnescapedQuote(raw: string, quote: number): boolean {
  let backslashes = 0;
  while (raw.charAt(quote - 1 - backslashes) === '\\') {
    backslashes += 1;
  }
  return backslashes % 2 === 0;
}

// --- multipart/form-data ----------------------------------------------------

/**
 * The delimiter line of a `multipart/form-data` body (`--<boundary>`), when the
 * body starts with one.
 */
function multipartDelimiter(raw: string): string | undefined {
  if (!raw.startsWith('--')) {
    return undefined;
  }
  const line = raw.split(/[\r\n]/, 1)[0] ?? '';
  return line.length > 2 && !/\s/.test(line) ? line : undefined;
}

/**
 * The contents of a multipart body's form fields, up to the closing delimiter
 * (`--<boundary>--`). File parts are skipped: frameworks hand them over as
 * uploads, not as body values.
 */
function multipartValues(raw: string, delimiter: string): readonly string[] {
  const parts = raw.split(delimiter).slice(1);
  const closing = parts.findIndex((part) => part.startsWith('--'));
  const fields = closing === -1 ? parts : parts.slice(0, closing);
  return collect(fields, MAX_BODY_VALUES, multipartFieldContent);
}

/** The content of a multipart form field, or undefined for a file part. */
function multipartFieldContent(segment: string): string | undefined {
  const part = segment.replace(/^[\r\n]+/, '');
  const separator = part.includes('\r\n\r\n') ? '\r\n\r\n' : '\n\n';
  const headersEnd = part.indexOf(separator);
  if (headersEnd === -1 || /filename=/i.test(part.slice(0, headersEnd))) {
    return undefined;
  }
  return longEnough(
    part.slice(headersEnd + separator.length).replace(/[\r\n]+$/, ''),
  );
}

// --- application/x-www-form-urlencoded --------------------------------------

/**
 * A body shaped like `application/x-www-form-urlencoded`: it holds a `=` and
 * is not markup (XML attributes hold `=` too).
 */
function looksLikeForm(raw: string): boolean {
  return raw.includes('=') && !raw.trimStart().startsWith('<');
}

/** The form-decoded values of a urlencoded body. */
function formValues(raw: string): readonly string[] {
  return collect(raw.split('&'), MAX_BODY_VALUES, formValue);
}

/**
 * The decoded value of a `name=value` pair, when long enough. Form-decoding
 * never lengthens a value, so a short one is dropped before decoding.
 */
function formValue(pair: string): string | undefined {
  const eq = pair.indexOf('=');
  if (eq === -1 || pair.length - eq - 1 < MIN_BASE64_LENGTH) {
    return undefined;
  }
  return longEnough(decodeFormComponent(pair.slice(eq + 1)));
}

/**
 * Percent-decode a form component (`+` is a space); malformed stays as is.
 * A value without `+` or `%` comes back untouched, with no work.
 */
function decodeFormComponent(value: string): string {
  // A global regex beats `replaceAll('+', ' ')` here (measured on V8).
  const spaced = value.includes('+') ? value.replace(/\+/g, ' ') : value;
  if (!spaced.includes('%')) {
    return spaced;
  }
  try {
    return decodeURIComponent(spaced);
  } catch {
    return spaced;
  }
}
