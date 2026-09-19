# Performance & caching

Mini-WAF includes optional knobs to bound CPU and memory without external cache libraries. Full tables, methodology, and caveats live in the repository's [`BENCHMARKS.md`](https://github.com/MurylloEx/Mini-WAF/blob/main/BENCHMARKS.md).

## Snapshot (latest documented run)

Same machine as `BENCHMARKS.md` (Ryzen 7 5700X3D, Node 24). Always re-run locally.

| Case | Result |
|------|--------|
| Engine baseline (`A0`, 0 rules) | ~422k ops/s, p50 ~1.1 µs |
| Balanced clean allow (`A1`, 25 rules) | ~113k ops/s, p50 ~6.8 µs |
| + `decisionCache` hits (`A2`) | ~411k ops/s, p50 ~2.0 µs |
| ~8KB body (`A3`) | ~12k ops/s, p50 ~76 µs |
| Express tiny GET, WAF on vs off (`B0`→`B1`) | ~−16% req/s, ~+23% p50 |

Artifacts: `benchmarks/last-run.json`, `benchmarks/last-http-run.json`.

```bash
npm run bench
npm run bench:http
npm run bench:compare
```

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

## Regex caveats

Node has no sync RegExp timeout and no built-in RE2. Catastrophic backtracking on long strings is mitigated by `maxFieldLength` truncation before `matches`. Avoid nested quantifiers on attacker-controlled input. For hard guarantees, run matching in a worker with a wall-clock budget or use a linear-time engine outside this library.

## A minimal benchmark harness (inspired by `benchmarks/run.mjs`)

The real benchmark suite (`benchmarks/run.mjs`) builds against `dist/` (run `npm run build` first) and uses a `createMockContext` helper (`benchmarks/lib/mock-context.mjs`) that implements the full `WafHttpContext` surface without any HTTP server — useful when you want to A/B a config change against your own rule set before deploying it.

```js
import { createMockContext } from './benchmarks/lib/mock-context.mjs';
import { createWafEngine } from './dist/index.js';

const engine = createWafEngine({
  presets: ['default'],
  level: 'balanced',
  ruleYieldEvery: 0, // disable yielding for a clean, single-threaded timing loop
});

function benchAllowPath(iterations = 20_000) {
  const { ctx } = createMockContext({
    method: 'GET',
    url: '/search?q=hello',
    headers: { 'user-agent': 'Mozilla/5.0 (compatible; BenchBot/1.0)' },
  });

  // Warm up the JIT / megamorphic call sites before timing.
  for (let i = 0; i < 1_000; i += 1) {
    void engine.handle(ctx);
  }

  const start = performance.now();
  for (let i = 0; i < iterations; i += 1) {
    void engine.handle(ctx);
  }
  const elapsedMs = performance.now() - start;

  console.log(`${iterations} clean allows in ${elapsedMs.toFixed(2)}ms`);
  console.log(`~${Math.round((iterations / elapsedMs) * 1_000)} ops/s`);
}

benchAllowPath();
```

For the authoritative numbers (throughput, p50/p95/p99 latency, methodology, and machine specs), run the real suite:

```bash
npm run bench          # benchmarks/run.mjs → benchmarks/last-run.json
npm run bench:http     # benchmarks/http.mjs → benchmarks/last-http-run.json
npm run bench:compare  # both, side by side
```

## Practical tips

- Production defaults (`maxFieldLength: 8192`, `ruleYieldEvery: 32`) are a good starting point.
- Disable `preset-dos-rate-limit` only if you rate-limit elsewhere **and** you want `decisionCache` to be eligible.
- Narrow `presets` and pick the lowest `level` that meets your threat model — see [Security notes](/guide/security).
