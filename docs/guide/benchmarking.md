# Benchmarking

Mini-WAF ships two benchmark suites and commits their JSON artifacts, so a
config or rule change can be measured rather than guessed at.

## Snapshot (latest committed run)

Ryzen 7 5700X3D, Node 24. **Relative only** — re-run locally before drawing
conclusions about your hardware.

| Case | Rules | Result |
|------|------:|--------|
| Engine baseline (`A0`, no rules) | 0 | ~397k ops/s, p50 ~1.1 µs |
| Balanced clean allow (`A1`) | 44 | ~68k ops/s, p50 ~12.3 µs |
| + `decisionCache` hits (`A2`) | 44 | ~407k ops/s, p50 ~2.0 µs |
| Low clean allow (`A6-low`) | 19 | ~132k ops/s, p50 ~6.9 µs |
| ~8KB body (`A3`) | 44 | ~7.4k ops/s, p50 ~129 µs |
| Express tiny GET, WAF on vs off (`B0`→`B1`) | 44 | ~−21% req/s, ~+27% p50 |

The HTTP delta is the number to reason about for capacity planning: in a real
server the rule scan is a small slice of the request, so a ~40% engine-level
difference shows up as ~20% end-to-end.

Full tables, methodology and caveats live in
[`BENCHMARKS.md`](https://github.com/MurylloEx/Mini-WAF/blob/main/BENCHMARKS.md).

## Running the suites

```bash
npm run bench          # engine A0–A7  → benchmarks/last-run.json
npm run bench:http     # HTTP B*/C*    → benchmarks/last-http-run.json
npm run bench:compare  # both, side by side
```

Both build the library first (the harness imports from `dist/`). Override the
workload:

```bash
npm run bench -- --iterations 30000 --warmup 2000
npm run bench:http -- --requests 50000 --concurrency 32 --warmup 2000
```

## What each suite measures

| Suite | Isolates | Use it for |
|-------|----------|------------|
| `bench` (engine) | Rule evaluation only — no sockets, no framework | A/B-ing rules, levels, `maxFieldLength`, `decisionCache` |
| `bench:http` (Express) | End-to-end request cost with the WAF on vs off | Capacity planning, "what does this actually cost me" |

Engine deltas are large and noisy-free; HTTP deltas are smaller and closer to
what you will observe in production. Quote HTTP numbers to stakeholders, engine
numbers when optimizing.

## A/B-ing your own rule set

The harness's `createMockContext` (`benchmarks/lib/mock-context.mjs`) implements
the full `WafHttpContext` surface with no HTTP server, which is enough to time a
config change against your own rules before deploying it:

```js
import { createMockContext } from './benchmarks/lib/mock-context.mjs';
import { createWafEngine } from './dist/index.js';

const engine = createWafEngine({
  presets: ['default'],
  level: 'balanced',
  ruleYieldEvery: 0, // disable yielding for a clean, single-threaded timing loop
});

async function benchAllowPath(iterations = 20_000) {
  const { ctx } = createMockContext({
    method: 'GET',
    url: '/search?q=hello',
    headers: { 'user-agent': 'Mozilla/5.0 (compatible; BenchBot/1.0)' },
  });

  // Warm up the JIT / megamorphic call sites before timing.
  for (let i = 0; i < 1_000; i += 1) {
    await engine.handle(ctx);
  }

  const start = performance.now();
  for (let i = 0; i < iterations; i += 1) {
    await engine.handle(ctx);
  }
  const elapsedMs = performance.now() - start;

  console.log(`${iterations} clean allows in ${elapsedMs.toFixed(2)}ms`);
  console.log(`~${Math.round((iterations / elapsedMs) * 1_000)} ops/s`);
}

await benchAllowPath();
```

`handle` always returns a Promise even when the scan runs synchronously
(`ruleYieldEvery: 0`), so `await` it — discarding the promise would time only
part of the work.

## Reading the results honestly

- **Interleave runs.** Machine state drifts; run before/after/before/after and
  compare best-of rather than a single pair.
- **Watch an unchanged case.** `A0` (zero rules) and `A2` (cache hits) should
  barely move. If they shift 5%+, your measurement is noise, not signal.
- **Prefer p95/p99** when judging tail impact; means hide the cases that page
  someone at 3am.
- **Diff the JSON artifacts** (`benchmarks/last-run.json`) in review — they are
  committed precisely so a regression is visible in the diff.

## Things that were measured and rejected

Recorded here so they are not re-attempted:

| Idea | Result |
|------|--------|
| Merging each rule family into one big regex | **~3× slower** — V8 drops its literal-prefix optimization when alternations with different heads are combined |
| Allocation-free condition results (frozen singletons) | ~1%, within noise — not worth the readability cost |
| Scanning query parameter *names* as extra candidates | −12% to −17% throughput; left out, and documented as a [coverage limit](/guide/security) |

What did work was the [`requires` prefilter](/guide/conditions#the-requires-prefilter):
roughly doubled 8KB-body throughput at an unchanged rule count.
