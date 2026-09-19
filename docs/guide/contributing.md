# Contributing

## Setup

```bash
npm install
npm run build
npm test
```

## Scripts

| Script | Purpose |
|--------|---------|
| `npm run build` | Compile TypeScript to `dist/` (+ `tsc-alias`) |
| `npm run lint` | Typecheck library and tests |
| `npm test` | Vitest unit/integration tests |
| `npm run test:watch` | Vitest watch mode |
| `npm run bench` | Engine micro-benchmarks → `benchmarks/last-run.json` |
| `npm run bench:http` | Express HTTP benchmarks → `benchmarks/last-http-run.json` |
| `npm run bench:compare` | Both suites |
| `npm run integration` | Build + run `integration/` scenario apps |
| `npm run docs:dev` | VitePress docs (this site) |
| `npm run docs:build` | Build static docs |
| `npm run docs:preview` | Preview the docs build |

## Layout

- `src/domain` — types, levels, serializable DSL
- `src/engine` — evaluation, matching, rate-limit, fingerprints
- `src/adapters` — Express / Fastify / Nest / `createAdapter`
- `src/presets` — built-in rule packs
- `src/logging` — optional logger port
- `integration/` — Express, Fastify, NestJS, Koa samples
- `docs/` — VitePress documentation
- `BENCHMARKS.md` — performance report (update when engine costs change)

## Guidelines

- Do not invent public APIs in docs or examples — mirror `src/**` and `package.json` `exports`.
- Prefer immutability for preset arrays; dedupe by `id` when composing.
- Keep logging off by default; avoid new mandatory dependencies for the hot path.
- When changing `src/engine/*` or `src/domain/*` in ways that affect cost, re-run benches and refresh `BENCHMARKS.md`.

## License

MIT — see `LICENSE` in the repository root.
