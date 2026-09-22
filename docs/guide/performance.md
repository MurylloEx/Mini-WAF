# Performance & caching

Mini-WAF includes optional knobs to bound CPU and memory without external cache libraries. Full tables, methodology, and caveats live in the repository's [`BENCHMARKS.md`](https://github.com/MurylloEx/Mini-WAF/blob/main/BENCHMARKS.md).

## How much does it cost?

At `balanced` with the `default` pack, a clean request costs roughly **12 µs**
of engine time; at `low`, about **7 µs**. End to end on a real Express server
that is around **20% fewer req/s** on tiny GETs.

Numbers, methodology and how to measure your own set-up live in
[Benchmarking](/guide/benchmarking).

## Configuration knobs

| Option | Default | Purpose |
|--------|---------|---------|
| `maxFieldLength` | `8192` | Truncate each scanned field value (body, query, headers, …) **before** matching / regex. Limits regex cost on huge payloads without rejecting the HTTP body itself. Set `0` for unlimited (not recommended in production). |
| `ruleYieldEvery` | `32` | After every N rules, `handle` may await `setImmediate` so large rule packs do not starve the event loop. Yielding is also gated by a ~1ms sync budget (`DEFAULT_YIELD_BUDGET_MS`). Packs with fewer than N rules skip yielding (fully synchronous scan, still returns a `Promise`). Set `0` to always disable yielding. Safe with `rateLimit` rules: counters live in a shared in-place store. |
| `maxRateLimitKeys` | `10000` | Cap on distinct rate-limit keys (usually per-IP buckets). Cold keys are evicted LRU-style; idle keys are pruned opportunistically. |
| `decisionCache` | omitted (off) | Tiny LRU of allow/block decisions keyed by method + path + IP + query + UA + body hash. **Automatically disabled** when any active rule uses `rateLimit` so DoS counters still advance. Defaults when enabled: `max` 256 / `ttlMs` 1000. |

Normalized client IPs are memoized in a process-local LRU (max 2048) — no external `lru-cache` dependency.

### Tuning `decisionCache`

```ts
import { expressWaf } from 'mini-waf/express';

app.use(
  expressWaf({
    presets: ['default'],
    level: 'balanced',
    // No custom rateLimit condition anywhere in this config, so the cache
    // stays eligible — the built-in `default` preset does NOT include the
    // `scanners` DoS rate-limit rule by itself being the deciding factor;
    // any active rule with `rateLimit` (custom or preset) disables the
    // cache automatically regardless of this setting (rulesHaveRateLimit).
    decisionCache: {
      // Distinct fingerprints retained. Each entry is tiny (decision +
      // matched rule id + reason + logged rule ids), so raising this mostly
      // trades memory for a higher hit rate under bursty repeated traffic
      // (e.g. the same health-check or polling client hammering one route).
      max: 512,
      // How long a cached decision stays valid. Too high risks serving a
      // stale 'allow' after you push a config change that would now block
      // that exact request; too low limits the hit rate on legitimately
      // repeated requests. 1-5s is a reasonable band for most APIs.
      ttlMs: 2_000,
    },
  }),
);
```

The fingerprint (`requestFingerprint`, `src/engine/fingerprint.ts`) hashes method, path, IP, sorted query string, `User-Agent`, and up to 4096 bytes of the body with a fast non-cryptographic djb2 hash — good enough to key a short-TTL cache, not meant as a security boundary.

### Tuning `maxFieldLength`

```ts
createMiniWaf({
  presets: ['default'],
  level: 'balanced',
  // Trade-off: lower bounds regex/matcher cost per field (fewer characters
  // to scan) but risks missing an attack payload that only appears past the
  // truncation point in a very large field. 8192 (the default) already
  // covers the vast majority of legitimate query/header/cookie sizes while
  // keeping catastrophic-regex risk bounded; raise it only for routes that
  // legitimately accept large text bodies you still want fully scanned.
  maxFieldLength: 4_096,
});
```

Setting `0` disables truncation entirely — every byte of every scanned field is matched. This is the highest-fidelity option but also the highest worst-case cost per request on adversarial input; prefer it only behind additional protections (a reverse-proxy body-size cap, a dedicated ReDoS-safe engine, or a request size limit at the framework level).

### Tuning `maxRateLimitKeys` and rate-limit rule bounds

```ts
import { RateLimitStore } from 'mini-waf';
import { createMiniWaf } from 'mini-waf';

// Cap distinct buckets (typically one per client IP) — protects a single
// Node process's memory from an attacker rotating through many source IPs
// purely to grow the counter Map. Cold keys (oldest insertion order) are
// evicted first once the cap is hit.
const waf = createMiniWaf(
  {
    presets: ['default'],
    level: 'balanced',
    maxRateLimitKeys: 5_000,
    rules: [
      {
        id: 'rate-limit-search',
        action: 'block',
        reason: 'Too many search requests',
        when: { all: [
          { field: 'path', equals: '/search' },
          { field: 'ip', rateLimit: { max: 30, windowMs: 10_000, keyPrefix: 'search' } },
        ] },
      },
    ],
  },
  {
    // Inject a shared store across multiple `createMiniWaf` instances (e.g.
    // one engine per Express Router mounted at different prefixes) so a
    // single client IP is bounded across the whole process, not per engine.
    rateLimitStore: new RateLimitStore(undefined, { maxKeys: 5_000, idleMs: 120_000 }),
  },
);
```

## Evaluation shortcuts

- After the first matching `block`, later pure `block` rules (no `rateLimit` in their condition tree) are skipped. `allow`, `log`, and rate-limit side-effect rules still run.
- Prefer specific fields (`query.id`, `headers.user-agent`) over bags (`query`, `headers`, `cookies`). Bags OR across every value and amplify matcher cost.
- Static `includes` needles are lowercased once at rule load (`normalizeRules`); haystacks are memoized per request via `FieldResolveOptions.memoLower` so a field used by multiple `includes` rules is only lowercased once per request.
- **`requires` is the biggest lever on large payloads.** A condition that declares it is gated by an `indexOf` scan before its regex runs, over the same memoized lowercased view. On an 8 KB body this is what separates a handful of substring scans from dozens of full regex passes; most preset rules ship one. See [Custom rules](/guide/custom-rules) for how to write a correct list — an incomplete one is a silent detection gap, not a slowdown.

### Cost scales with rules × field values

A rule costs one matcher run **per candidate value of each field it targets**.
`{ anyOf: [{ field: 'query' }, { field: 'body' }] }` over a query with 5
parameters is 6 runs, not 2. Two consequences:

- Raising `level` raises cost roughly linearly. With `presets: ['default']` the
  active rule count is 19 / 51 / 81 / 94 for `low` / `balanced` / `high` /
  `paranoid` — pick the lowest level that meets your threat model.
- `decisionCache` sidesteps the whole scan on a fingerprint hit, and is by far
  the cheapest win for traffic with repeated shapes (it is disabled
  automatically while a `rateLimit` rule is active).
- `high`/`paranoid` auto-enable Base64, percent (URL) **and** inline-SQL-comment
  decoding. On clean traffic the three add a memoized per-field shape check (a
  Base64 char-class/length test, a `String.includes('%')` test and a
  `String.indexOf('/*')` test) — measured at **≈ +10 %** of the high/paranoid
  scan — and normalize only values that actually look like a Base64 blob, carry a
  `%XX` escape that changes on decode, or contain a `/*` comment; all three are
  **off**, and free, at `low`/`balanced`. A JSON body is parsed once (memoized)
  to expose its string values to the same decoders, bounded in depth and count.
  Set `decode: { base64: false, url: false, comments: false }` to opt out.

## Regex caveats

Node has no sync RegExp timeout and no built-in RE2. Catastrophic backtracking on long strings is mitigated by `maxFieldLength` truncation before `matches`. Avoid nested quantifiers on attacker-controlled input. For hard guarantees, run matching in a worker with a wall-clock budget or use a linear-time engine outside this library.

## Practical tips

- Production defaults (`maxFieldLength: 8192`, `ruleYieldEvery: 32`) are a good starting point.
- Add `requires` to every custom regex rule whose pattern has a fixed literal.
- Disable `preset-dos-rate-limit` only if you rate-limit elsewhere **and** you want `decisionCache` to be eligible.
- Narrow `presets` and pick the lowest `level` that meets your threat model — see [Security notes](/guide/security).
- Measure before and after any of the above: [Benchmarking](/guide/benchmarking).
