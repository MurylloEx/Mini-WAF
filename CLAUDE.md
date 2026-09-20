# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
npm run lint          # typecheck src + tests (there is no ESLint; tsc IS the linter)
npm test              # vitest run
npm run test:watch
npm run build         # clean, emit CJS + ESM, write dist/*/package.json type markers
npm run integration   # build, install integration/, run the live-server scenarios
npm run bench         # engine micro-benchmarks -> benchmarks/last-run.json
npm run bench:http    # Express HTTP benchmarks -> benchmarks/last-http-run.json
npm run docs:dev      # VitePress on :5173
npm run docs:build
```

Single test file / single test:

```bash
npx vitest run tests/presets.test.ts
npx vitest run -t "blocks union select"
```

`npm run lint` runs `tsc` twice (`tsconfig.json` for `src`, `tsconfig.tests.json` for `tests`). Both must pass — CI runs lint, test and build on Node 22/24/26.

`npm run integration` boots real Express, Fastify, NestJS and Koa apps on ports 3101-3104 and fires HTTP requests at them. It reinstalls `integration/` every run, which rewrites the `mini-waf` version inside the five `integration/**/package-lock.json` files — that churn is expected after a version bump.

## Architecture

The engine never touches a framework request object. Everything flows through two interfaces in `src/domain/context.ts`:

- **`WafHttpContext`** — the framework-agnostic view of one request (`getIp()`, `getQuery()`, `getRawBody()`, `drop()`, …). `src/engine/field-resolver.ts` resolves *every* `WafField` exclusively through these getters, so an adapter returning the wrong value for `getIp()` silently breaks every `field: 'ip'` rule and rate-limit bucket with no compile-time signal.
- **`WafAdapter`** — maps a native request/response pair into a context, once per request.

The built-in Express/Fastify/NestJS entrypoints are thin wrappers over this same path; `createAdapter(handlers)` is the supported way to add a framework.

### Request lifecycle

`createMiniWaf(config)` (`src/engine/index.ts`) → `createWafEngine` (`src/engine/engine.ts`) resolves config **once at construction**, not per request:

1. `buildRuleList` — resolve presets, concat custom rules, filter by `minLevel` vs `config.level`, apply `enabledRuleIds` allowlist, apply `disabledRuleIds`, drop `enabled: false`, sort by `priority` (lower first).
2. `normalizeRules` pre-lowercases `includes` needles and `requires` literals so the hot path never lowercases a constant.

Per request, `handle(ctx)` walks the sorted rules. A matching `allow` rule short-circuits; a matching `block` rule calls `ctx.drop()`. `log` rules accumulate into `loggedRules` without stopping evaluation.

### Rule DSL

`src/domain/rules.ts` is the contract. A `WafCondition` is one of `FieldCondition` (`field` + `matches`/`equals`/`includes`/`rateLimit`), `AllCondition`, `AnyOfCondition`, `NotCondition`, each with a type guard.

`requires` on a `FieldCondition` is a cheap `indexOf` gate that runs **before** the regex — the value must contain one of the literals or the pattern is never tried. It roughly doubled throughput on 8 KB bodies. It is also a footgun: an incomplete list silently narrows the rule into a detection gap, so only add literals that *every* payload the pattern can match must contain.

### Performance invariants

These exist because they were measured; do not undo them casually:

- Field values are memoized per request (`memo`), and their lowercased forms lazily in a second memo (`memoLower`) — an unconditional `toLowerCase()` in the hot path is a measurable regression.
- Merging preset regexes into larger alternations made evaluation **3× slower** (V8 loses the literal-prefix optimization). Keep patterns separate.
- `maxFieldLength` (default 8192) truncates each scanned value before any matcher runs.
- `ruleYieldEvery` (default 32) yields to the event loop on large rule sets; smaller packs take a fully synchronous path.

When a change to `src/engine/*` or `src/domain/*` affects cost, re-run the benches and update `BENCHMARKS.md`.

### Presets

`src/presets/` mirrors OWASP CRS categories (sqli, xss, rce, rfi, path-traversal, scanners, protocol, default). `src/presets/fields.ts` holds the shared field tuples and `anyFieldMatches()` — use it rather than hand-rolling `anyOf` lists.

Rule ids are public API: users disable rules by id, and `tests/preset-coverage.test.ts` asserts *which* rule id fires for each attack. That file also carries a benign corpus asserted to produce `allow` — a new rule that blocks any of it is a false positive, which is the main risk when touching presets.

## Code constraints

- **No `any`, no `unknown`** anywhere in `src/`. `src/domain/values.ts` exists to model HTTP values (`JsonValue`, `QueryValue`, `HeaderValue`) without them. When a framework type does not fit, widen the library's interface to match reality rather than casting.
- **Avoid `let`** — the handful of occurrences are local mutable accumulators (hash loops, `blocked` flags, lazy caches). Prefer immutable transforms.
- `exactOptionalPropertyTypes` is on: an optional property that can hold `undefined` must say `| undefined` explicitly.
- Imports use the `@/` alias, rewritten at build time by `tsc-alias`.
- All code, comments, docs and commit messages are in **English**, regardless of the conversation language.
- Commits follow Conventional Commits (`feat(engine):`, `fix(adapters):`, `docs(integrations):`, `chore(release):`).

## Packaging

The package ships dual CJS + ESM. `exports` carries **per-condition `types`** (inside `import` and `require`, not one top-level `types`) — a single top-level `types` breaks CJS consumers under `moduleResolution: node16` with `TS1479`. `typesVersions` covers `node10`. `sideEffects: false` keeps it tree-shakeable. `scripts/mark-dist-types.mjs` writes the `{"type": ...}` marker into `dist/cjs` and `dist/esm`; without it the `import` condition gets re-interpreted as CJS.

The library is Node-only (`node:net`, `node:buffer`, `node:perf_hooks`, `setImmediate`), so it cannot run on edge runtimes. Next.js route handlers need `export const runtime = 'nodejs'`.

## Docs

VitePress in `docs/`, published to GitHub Pages by `.github/workflows/docs.yml` on every push to `master` — there is no `gh-pages` branch. Images live in `.github/assets/`, which VitePress serves as its public dir so the README and the site share one copy.

Two recurring traps:
- A dead link fails the docs build. Run `npm run docs:build` before pushing.
- Markdown tables split cells on `|` **even inside inline code**; escape it as `\|` (e.g. `ctx.get(name) \|\| undefined`).

Document only APIs that actually exist in `src/**` and `package.json` `exports`. Test helpers such as `createMockContext` are *not* exported from the package — examples that use them are wrong.

## Publishing

`npm publish` requires an OTP (2FA). npm's supply-chain scanner rejects some README content with a bare `E403` and no explanation — a literal `${IFS}` cost three burned OTPs once. To bisect without spending OTPs: run `npm publish --ignore-scripts` *without* `--otp`; `EOTP` means the payload passed policy, `E403` means the content was blocked.
