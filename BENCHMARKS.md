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
| **A0** | Baseline `handle()` with zero rules | 0 | 397.47k/s | 1.11 µs | 3.60 µs | 6.94 µs |
| **A1** | `default` + `balanced`, clean allow | 44 | 68.32k/s | 12.28 µs | 27.77 µs | 32.60 µs |
| **A2** | A1 + `decisionCache` (hits after warmup) | 44 | 406.60k/s | 2.00 µs | 3.60 µs | 5.47 µs |
| **A3** | A1 + ~8KB JSON body | 44 | 7.44k/s | 128.84 µs | 153.63 µs | 177.68 µs |
| **A4** | A1 + small (~24B) body | 44 | 71.78k/s | 13.01 µs | 14.66 µs | 27.04 µs |
| **A5** | A1 SQLi — block path (early-exit) | 44 | 114.77k/s | 7.97 µs | 9.46 µs | 17.89 µs |
| **A6-low** | `level: 'low'` clean allow | 19 | 132.03k/s | 6.88 µs | 8.35 µs | 14.82 µs |
| **A6-balanced** | `level: 'balanced'` clean allow | 44 | 76.28k/s | 12.06 µs | 16.01 µs | 24.51 µs |
| **A6-high** | `level: 'high'` clean allow | 60 | 52.48k/s | 17.49 µs | 24.60 µs | 39.86 µs |
| **A6-paranoid** | `level: 'paranoid'` clean allow | 66 | 47.97k/s | 19.68 µs | 22.82 µs | 36.46 µs |
| **A7-y0** | Paranoid, `ruleYieldEvery: 0` | 66 | 50.21k/s | 19.23 µs | 20.71 µs | 27.26 µs |
| **A7-y32** | Paranoid, `ruleYieldEvery: 32` | 66 | 48.05k/s | 20.05 µs | 21.61 µs | 28.14 µs |

> `A1`–`A5` run the `balanced` pack minus `preset-dos-rate-limit`, hence 44
> rules where `A6-balanced` reports 45.

**Highlights**

- **A0 → A1**: 44 rules → ~17% of baseline ops/s (+11.2 µs p50).
- **A1 → A2**: `decisionCache` on a repeated fingerprint is ~6× faster
  (68k → 407k ops/s) and is unaffected by rule count — the cheapest win
  available for traffic with repeated shapes.
- **A4 → A3**: ~8KB body is still the costly path (~10% of small-body ops/s) —
  see [Known inherent costs](#known-inherent-costs).
- **A1 → A5**: block can be *faster* than a full clean allow (early-exit).
- **A6-low → A6-paranoid**: cost scales roughly with rule count
  (19 → 66 rules); `low` remains ~7 µs p50.
- **A7-y0 ↔ A7-y32**: within noise on a 66-rule pack; the ~1ms yield budget
  does not trip on a clean paranoid scan.
- **Base64 decode (`high`/`paranoid`)**: these levels auto-enable whole-value
  Base64 decoding. On clean traffic (nothing decodes) it adds a per-field
  memoized shape check — measured at roughly **+10–15 % of `A6-high` /
  `A6-paranoid` cost**, and **zero** at `low`/`balanced` (the match path is
  byte-for-byte identical when decoding is off). Decode work only runs when a
  field value is actually a Base64 blob that survives the shape + printable
  gates; a JSON body is additionally parsed once (memoized, depth/count
  bounded) so its string values reach the same decoder. Set
  `decode: { base64: false }` to opt out at high+.

## HTTP results (`B0`/`B1`, `C0`–`C3`)

Express, keep-alive, `N = 50000` requests, warmup `2000`, concurrency `32`.
WAF: `presets: ['default']`, `level: 'balanced'`,
`disabledRuleIds: ['preset-dos-rate-limit']`, `ruleYieldEvery: 0`.
Latencies in milliseconds.

| ID | Route / scenario | WAF | req/s | p50 | p95 | p99 | WAF overhead vs no-WAF |
|----|-------------------|:---:|------:|----:|----:|----:|------------------------|
| **B0** | `GET /health`, clean | no | 6.98k/s | 4.40 ms | 5.36 ms | 5.87 ms | — (baseline) |
| **B1** | `GET /health`, clean | yes | 5.55k/s | 5.58 ms | 6.54 ms | 7.44 ms | −20.5% req/s, +26.8% p50 |
| **C0** | `GET /search?q=shoes`, clean | no | 6.75k/s | 4.71 ms | 4.94 ms | 5.42 ms | — (baseline) |
| **C1** | `GET /search?q=shoes`, clean | yes | 5.47k/s | 5.79 ms | 6.23 ms | 6.39 ms | −18.9% req/s, +22.9% p50 |
| **C2** | `GET /search?q=` SQLi (app returns 200) | no | 6.64k/s | 4.73 ms | 5.38 ms | 5.97 ms | — (baseline) |
| **C3** | Same SQLi, WAF **403** | yes | 6.83k/s | 4.56 ms | 5.22 ms | 6.11 ms | **+2.8% req/s**, −3.7% p50 |

Steady-state allow-path overhead (`B0↔B1`, `C0↔C1`) lands around
**19–21% req/s / 23–27% p50** for a 45-rule `balanced` pack on tiny GETs.
This is the number to reason about: in a real HTTP server the WAF scan is a
small slice of the request, so a ~40% engine-level delta shows up as ~20%
end-to-end.
Absolute req/s is dominated by Node’s HTTP stack and Express — use the
WAF-on vs WAF-off delta, not raw throughput, as the signal.

`C3` can beat `C2` because a block short-circuits before the route handler;
compare allow pairs only when judging overhead.

## Known inherent costs

### Large body regex (`A3`)

An ~8KB body at the default `maxFieldLength` cap (~129 µs p50 vs ~13 µs for a
tiny body) is the worst engine case. Cost is the sum of many
`RegExp.test()` calls against the payload — not redundant truncation or
lowercasing (fields are memoized once per request).

Two things were measured and rejected here:

- **Merging rules into one regex per family made it ~3× slower** — V8 drops its
  literal prefix optimization once alternations with different heads are
  combined. It would also break per-rule ids, levels and enable/disable.
- **Allocation-free condition results** moved the needle by ~1% (noise), so the
  straightforward code was kept.

What did work is the `requires` literal prefilter: gating each pattern behind an
`indexOf` over the memoized lowercased field roughly **doubled** 8KB-body
throughput (3.0k → 7.4k ops/s) at the same rule count. Beyond that, mitigate
with a lower `maxFieldLength`, narrower `presets`, a smaller `level`, or
`decisionCache`.

### Protection level (`A6-*`)

Higher levels activate more rules; ops/s and p50 track rule count roughly
linearly. No super-linear cliff in this suite. With `presets: ['default']` the
active count is 19 / 45 / 61 / 67 for `low` / `balanced` / `high` / `paranoid`.

Cost is really *rules × candidate values per field*: a rule targeting `query`
runs once per query parameter, so a request with ten parameters costs ten
matcher runs for that rule.

### `ruleYieldEvery` (`A7-*`)

Yielding only pays `setImmediate` after ~1ms of accumulated sync work. Typical
packs (including paranoid clean allow) stay under that budget, so `y0` and
`y32` look the same here. The knob matters for heavy custom packs / huge
bodies.

### Prefilter coverage

A rule without `requires` pays a full regex pass on every candidate value.
Preset rules declare one wherever the pattern allows it; custom regex rules
should too — see [custom rules](https://murylloex.github.io/Mini-WAF/guide/custom-rules).

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
