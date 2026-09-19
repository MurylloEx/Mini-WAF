# Benchmarks

What Mini-WAF costs in practice on the current engine. Numbers below come from
`benchmarks/last-run.json` and `benchmarks/last-http-run.json` (regenerate with
`npm run bench` / `npm run bench:http`). Harness details live in
[`benchmarks/README.md`](./benchmarks/README.md).

**Machine:** 16× AMD Ryzen 7 5700X3D, Node v24.15.0. Relative only — re-run
locally before drawing conclusions about your hardware.

## Engine results (`A0`–`A7`)

`N = 20000`, warmup `1000`. `preset-dos-rate-limit` disabled on `A1`–`A7`.
Latencies in microseconds.

| ID | What it measures | Rules | ops/s | p50 | p95 | p99 |
|----|-------------------|------:|------:|----:|----:|----:|
| **A0** | Baseline `handle()` with zero rules | 0 | 422.18k/s | 1.12 µs | 3.51 µs | 6.95 µs |
| **A1** | `default` + `balanced`, clean allow | 25 | 113.34k/s | 6.84 µs | 16.23 µs | 19.99 µs |
| **A2** | A1 + `decisionCache` (hits after warmup) | 25 | 410.79k/s | 1.98 µs | 3.01 µs | 4.99 µs |
| **A3** | A1 + ~8KB JSON body | 25 | 12.37k/s | 75.53 µs | 97.86 µs | 129.89 µs |
| **A4** | A1 + small (~24B) body | 25 | 140.49k/s | 6.35 µs | 9.65 µs | 13.42 µs |
| **A5** | A1 SQLi — block path (early-exit) | 25 | 198.13k/s | 4.55 µs | 5.57 µs | 10.54 µs |
| **A6-low** | `level: 'low'` clean allow | 12 | 220.60k/s | 4.04 µs | 5.20 µs | 8.77 µs |
| **A6-balanced** | `level: 'balanced'` clean allow | 25 | 132.27k/s | 6.66 µs | 10.38 µs | 14.48 µs |
| **A6-high** | `level: 'high'` clean allow | 39 | 91.36k/s | 10.02 µs | 13.90 µs | 20.70 µs |
| **A6-paranoid** | `level: 'paranoid'` clean allow | 45 | 75.39k/s | 12.58 µs | 15.85 µs | 21.97 µs |
| **A7-y0** | Paranoid, `ruleYieldEvery: 0` | 45 | 75.05k/s | 12.57 µs | 14.05 µs | 22.81 µs |
| **A7-y32** | Paranoid, `ruleYieldEvery: 32` | 45 | 75.69k/s | 12.51 µs | 13.89 µs | 23.18 µs |

**Highlights**

- **A0 → A1**: 25 rules → ~27% of baseline ops/s (+5.7 µs p50).
- **A1 → A2**: `decisionCache` on a repeated fingerprint is ~3.6× faster
  (113k → 411k ops/s).
- **A4 → A3**: ~8KB body is the costly path (~9% of small-body ops/s) — see
  [Known inherent costs](#known-inherent-costs).
- **A1 → A5**: block can be *faster* than a full clean allow (early-exit).
- **A6-low → A6-paranoid**: cost scales roughly with rule count
  (12 → 45 rules).
- **A7-y0 ↔ A7-y32**: within noise on a 45-rule pack; the ~1ms yield budget
  does not trip on a clean paranoid scan.

## HTTP results (`B0`/`B1`, `C0`–`C3`)

Express, keep-alive, `N = 50000` requests, warmup `2000`, concurrency `32`.
WAF: `presets: ['default']`, `level: 'balanced'`,
`disabledRuleIds: ['preset-dos-rate-limit']`, `ruleYieldEvery: 0`.
Latencies in milliseconds.

| ID | Route / scenario | WAF | req/s | p50 | p95 | p99 | WAF overhead vs no-WAF |
|----|-------------------|:---:|------:|----:|----:|----:|------------------------|
| **B0** | `GET /health`, clean | no | 6.84k/s | 4.42 ms | 5.72 ms | 6.45 ms | — (baseline) |
| **B1** | `GET /health`, clean | yes | 5.76k/s | 5.43 ms | 6.09 ms | 7.01 ms | −15.8% req/s, +22.9% p50 |
| **C0** | `GET /search?q=shoes`, clean | no | 6.61k/s | 4.81 ms | 4.99 ms | 5.54 ms | — (baseline) |
| **C1** | `GET /search?q=shoes`, clean | yes | 5.53k/s | 5.59 ms | 6.68 ms | 6.84 ms | −16.3% req/s, +16.2% p50 |
| **C2** | `GET /search?q=` SQLi (app returns 200) | no | 6.57k/s | 4.83 ms | 5.15 ms | 5.58 ms | — (baseline) |
| **C3** | Same SQLi, WAF **403** | yes | 7.07k/s | 4.46 ms | 4.82 ms | 5.42 ms | **+7.7% req/s**, −7.7% p50 |

Steady-state allow-path overhead (`B0↔B1`, `C0↔C1`) lands around
**15–20% req/s / 15–25% p50** for a 25-rule `balanced` pack on tiny GETs.
Absolute req/s is dominated by Node’s HTTP stack and Express — use the
WAF-on vs WAF-off delta, not raw throughput, as the signal.

`C3` can beat `C2` because a block short-circuits before the route handler;
compare allow pairs only when judging overhead.

## Known inherent costs

### Large body regex (`A3`)

An ~8KB body at the default `maxFieldLength` cap (~75 µs p50 vs ~6 µs for a
tiny body) is the worst engine case. Cost is the sum of many
`RegExp.test()` calls against the payload — not redundant truncation or
lowercasing (fields are memoized once per request). Merging regexes would
break per-rule ids, levels, and enable/disable controls. Mitigate with a
lower `maxFieldLength`, narrower `presets`, or a smaller `level`.

### Protection level (`A6-*`)

Higher levels activate more rules; ops/s and p50 track rule count roughly
linearly. No super-linear cliff in this suite.

### `ruleYieldEvery` (`A7-*`)

Yielding only pays `setImmediate` after ~1ms of accumulated sync work. Typical
packs (including paranoid clean allow) stay under that budget, so `y0` and
`y32` look the same here. The knob matters for heavy custom packs / huge
bodies.

## Reproducing

```bash
npm run bench          # engine A0–A7 → benchmarks/last-run.json
npm run bench:http     # HTTP B*/C* → benchmarks/last-http-run.json
npm run bench:compare  # both
```

```bash
npm run bench -- --iterations 30000 --warmup 1000
npm run bench:http -- --requests 50000 --concurrency 32 --warmup 2000
```

**Notes:** same fixed `N` across engine cases; HTTP uses fixed request count
(not duration) with keep-alive. DoS rate-limit is disabled so synthetic
traffic is not rate-limited and `decisionCache` stays eligible. Prefer
p95/p99 when judging tail impact; always re-run before/after engine changes
and diff the JSON artifacts.
