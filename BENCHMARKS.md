# Benchmarks

What Mini-WAF costs in practice on the current engine. Numbers below come from
`benchmarks/last-run.json` and `benchmarks/last-http-run.json` (regenerate with
`npm run bench` / `npm run bench:http`). Harness details live in
[`benchmarks/README.md`](./benchmarks/README.md).

**Machine:** 16× AMD Ryzen 7 5700X3D, Node v24.14.1. Relative only — re-run
locally before drawing conclusions about your hardware.

## Engine results (`A0`–`A7`)

`N = 20000`, warmup `1000`. `preset-dos-rate-limit` disabled on `A1`–`A7`.
Latencies in microseconds.

| ID | What it measures | Rules | ops/s | p50 | p95 | p99 |
|----|-------------------|------:|------:|----:|----:|----:|
| **A0** | Baseline `handle()` with zero rules | 0 | 369.19k/s | 1.18 µs | 3.88 µs | 7.07 µs |
| **A1** | `default` + `balanced`, clean allow | 50 | 63.36k/s | 13.44 µs | 29.18 µs | 35.10 µs |
| **A2** | A1 + `decisionCache` (hits after warmup) | 50 | 394.65k/s | 2.09 µs | 3.22 µs | 5.21 µs |
| **A3** | A1 + ~8KB JSON body | 50 | 7.26k/s | 133.86 µs | 156.50 µs | 163.52 µs |
| **A4** | A1 + small (~24B) body | 50 | 66.51k/s | 14.37 µs | 15.71 µs | 22.12 µs |
| **A5** | A1 SQLi — block path (early-exit) | 50 | 110.17k/s | 8.56 µs | 9.73 µs | 15.01 µs |
| **A6-low** | `level: 'low'` clean allow | 19 | 136.90k/s | 6.82 µs | 8.00 µs | 11.46 µs |
| **A6-balanced** | `level: 'balanced'` clean allow | 50 | 71.03k/s | 13.22 µs | 16.72 µs | 21.11 µs |
| **A6-high** | `level: 'high'` clean allow | 80 | 37.11k/s | 25.88 µs | 31.11 µs | 36.81 µs |
| **A6-paranoid** | `level: 'paranoid'` clean allow | 93 | 33.37k/s | 29.04 µs | 33.14 µs | 39.92 µs |
| **A7-y0** | Paranoid, `ruleYieldEvery: 0` | 93 | 33.81k/s | 28.86 µs | 31.20 µs | 38.42 µs |
| **A7-y32** | Paranoid, `ruleYieldEvery: 32` | 93 | 33.28k/s | 29.29 µs | 31.75 µs | 39.22 µs |

> `A1`–`A5` run the `balanced` pack minus `preset-dos-rate-limit`, hence 50
> rules where `A6-balanced` reports 51.
> `A6-high` / `A6-paranoid` auto-enable transport decoding, so their cost
> already includes it (see the Base64/URL note below).

**Highlights**

- **A0 → A1**: 50 rules → ~17% of baseline ops/s (+12.3 µs p50).
- **A1 → A2**: `decisionCache` on a repeated fingerprint is ~6× faster
  (63k → 395k ops/s) and is unaffected by rule count — the cheapest win
  available for traffic with repeated shapes.
- **A4 → A3**: ~8KB body is still the costly path (~11% of small-body ops/s) —
  see [Known inherent costs](#known-inherent-costs).
- **A1 → A5**: block can be *faster* than a full clean allow (early-exit).
- **A6-low → A6-paranoid**: cost scales roughly with rule count
  (19 → 93 rules); `low` remains ~7 µs p50.
- **A7-y0 ↔ A7-y32**: within noise on a 93-rule pack; the ~1ms yield budget
  does not trip on a clean paranoid scan.
- **Transport decode (`high`/`paranoid`)**: these levels auto-enable whole-value
  **Base64** decoding, **percent (URL)** decoding and **inline-SQL-comment**
  stripping. On clean traffic (nothing decodes) the three normalizers add a
  per-field memoized shape check (a Base64 char-class/length test, a
  `String.includes('%')` test and a `String.indexOf('/*')` test) — an isolated
  decode-on vs decode-off measurement at `high` puts this at **≈ +10–15 %** of
  the `A6-high` scan, and **zero** at `low`/`balanced` (the match path is
  byte-for-byte identical when decoding is off). Work only runs when a value is
  actually a Base64 blob surviving the shape + printable gates, actually carries
  a `%XX` escape that changes on decode, or actually contains a `/*` comment,
  and each decoder adds at most 16 candidates per field. A body is
  additionally split once (memoized, depth/count bounded) into its JSON string
  values, form values or multipart fields so they reach the same decoders.
  Measured decode-on vs decode-off at `high` on POST bodies:

  | Body | Added cost |
  |------|-----------:|
  | ~8 KB JSON, one long value | ≈ +6 % |
  | ~6 KB JSON, ~270 short string values | ≈ +17 % |
  | ~3.4 KB form, nothing encoded | ≈ +20 % |
  | ~6.5 KB JSON, many literals with `\uXXXX` / `\/` escapes | ≈ +40 % |
  | ~3.7 KB form carrying `%XX` escapes | ≈ ×2 |

  The last two are the decoders doing their job: a JSON string literal written
  with `\uXXXX` / `\/` escapes is added, decoded, as an extra candidate (the
  raw body is still scanned as sent, duplicate keys included), and a form body
  with a `%XX` escape is rescanned once percent-decoded. A JSON body with no
  string literal of 16+ characters, no such escape and no `=` cannot yield a
  candidate, so it skips `JSON.parse` entirely. Set `decode: { base64: false, url: false, comments: false }` to opt
  out at high+.

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
**19–21% req/s / 23–27% p50** for a 50-rule `balanced` pack on tiny GETs.
This is the number to reason about: in a real HTTP server the WAF scan is a
small slice of the request, so a ~40% engine-level delta shows up as ~20%
end-to-end.
Absolute req/s is dominated by Node’s HTTP stack and Express — use the
WAF-on vs WAF-off delta, not raw throughput, as the signal.

`C3` can beat `C2` because a block short-circuits before the route handler;
compare allow pairs only when judging overhead.

## Known inherent costs

### Large body regex (`A3`)

An ~8KB body at the default `maxFieldLength` cap (~134 µs p50 vs ~14 µs for a
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
active count is 19 / 51 / 81 / 94 for `low` / `balanced` / `high` / `paranoid`.

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
should too — see [custom rules](https://mini-waf.vercel.app/guide/custom-rules).

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
