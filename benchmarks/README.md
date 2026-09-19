# Benchmarks

Reproducible **A/B** performance suite for **mini-waf**.

## Requirements

- Node.js ≥ 18
- `npm install` at repo root (uses `express` as a devDependency)
- Built package: `npm run build` (also run by the npm scripts below)

No extra load-generator dependency — HTTP benches use Node `http.Agent` keep-alive with a fixed request count.

## Run

```bash
# Engine-only (A0–A7), default N=20000 warmup=1000
npm run bench

# HTTP Express before/after WAF (B0/B1, C0–C3), default N=50000
npm run bench:http

# Both, sequentially
npm run bench:compare
```

Overrides:

```bash
npm run bench -- --iterations 30000 --warmup 1000
npm run bench:http -- --requests 50000 --concurrency 32 --warmup 2000
npm run bench:compare -- --iterations 20000 --requests 50000
```

Artifacts:

- `benchmarks/last-run.json` — engine
- `benchmarks/last-http-run.json` — HTTP

## Engine cases (mock context)

| ID | Setup |
|----|--------|
| **A0** | 0 rules — baseline `handle` overhead |
| **A1** | `default` + `balanced`, **without** `preset-dos-rate-limit` — clean allow |
| **A2** | A1 + `decisionCache` — same fingerprint (cache hits after warmup) |
| **A3** | A1 + ~8KB body |
| **A4** | A1 + small body (~24B) |
| **A5** | A1 SQLi query — block path |
| **A6-*** | `low` / `balanced` / `high` / `paranoid` — clean, same N |
| **A7-y0 / A7-y32** | paranoid `ruleYieldEvery` 0 vs 32 — same N |

Every engine case uses the **same N** and warmup. Report columns: N, wall time, ops/s, p50/p95/p99 (µs), decision.

`preset-dos-rate-limit` is disabled on A1–A7 so thousands of iterations from one IP stay on the allow path (and so `decisionCache` is not forced off by a rate-limit rule).

## HTTP cases (Express, localhost)

Fixed **request count** (not duration). Keep-alive. Warmup discarded.

| ID | Route | WAF |
|----|-------|-----|
| **B0** | `GET /health` clean | no |
| **B1** | `GET /health` clean | yes (balanced, dos disabled) |
| **C0** | `GET /search?q=shoes` | no |
| **C1** | `GET /search?q=shoes` | yes |
| **C2** | `GET /search?q=` SQLi | no (expect **200**) |
| **C3** | `GET /search?q=` SQLi | yes (expect **403**) |

Report: total completed, duration, concurrency, req/s, p50/p95/p99, error rate, status-code distribution.

WAF choice for fair allow path: `disabledRuleIds: ['preset-dos-rate-limit']`, `ruleYieldEvery: 0`.

## Interpreting

- Prefer **p95/p99** under load; use pair deltas printed by the scripts.
- Rank bottlenecks from **that run’s** numbers only.
- HTTP throughput is dominated by Node/Express; use relative WAF cost, not absolute capacity planning.
