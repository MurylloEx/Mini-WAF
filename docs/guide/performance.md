# Performance & caching

Mini-WAF includes optional knobs to bound CPU and memory without external cache libraries. Full tables, methodology, and caveats live in the repository’s [`BENCHMARKS.md`](https://github.com/MurylloEx/Mini-WAF/blob/main/BENCHMARKS.md).

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

## Evaluation shortcuts

- After the first matching `block`, later pure `block` rules (no `rateLimit` in their condition tree) are skipped. `allow`, `log`, and rate-limit side-effect rules still run.
- Prefer specific fields (`query.id`, `headers.user-agent`) over bags (`query`, `headers`, `cookies`). Bags OR across every value and amplify matcher cost.
- Static `includes` needles are lowercased once at rule load; haystacks are memoized per request.

## Regex caveats

Node has no sync RegExp timeout and no built-in RE2. Catastrophic backtracking on long strings is mitigated by `maxFieldLength` truncation before `matches`. Avoid nested quantifiers on attacker-controlled input. For hard guarantees, run matching in a worker with a wall-clock budget or use a linear-time engine outside this library.

## Practical tips

- Production defaults (`maxFieldLength: 8192`, `ruleYieldEvery: 32`) are a good starting point.
- Disable `preset-dos-rate-limit` only if you rate-limit elsewhere **and** you want `decisionCache` to be eligible.
- Narrow `presets` and pick the lowest `level` that meets your threat model — see [Security notes](/guide/security).
