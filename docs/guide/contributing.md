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
| `npm run build` | Compile TypeScript twice — CJS to `dist/cjs`, ESM to `dist/esm` — then write the `type` markers |
| `npm run lint` | Typecheck library and tests |
| `npm test` | Vitest unit/integration tests |
| `npm run test:watch` | Vitest watch mode |
| `npm run bench` | Engine micro-benchmarks → `benchmarks/last-run.json` |
| `npm run bench:http` | Express HTTP benchmarks → `benchmarks/last-http-run.json` |
| `npm run bench:compare` | Both suites |
| `npm run integration` | Build + run `integration/` scenario apps |
| `npm run docs:dev` | Serve the docs locally on :5173 |

## Docs

The documentation lives in `docs/` as plain Markdown, rendered in the browser
with no build step. `docs/_sidebar.md` sets the navigation order, which also
drives the previous/next links and the search index.

```bash
npm run docs:dev    # http://localhost:5173
```

To add a page, create `docs/guide/<name>.md` and add one line to
`docs/_sidebar.md`. Link between pages with site paths such as
`[Presets](/guide/presets)`; `tests/docs-links.test.ts` fails on any link or
anchor that does not resolve.

The site is deployed to Vercel as static files from `docs/`. See
`docs/README.md` for the details.

## Layout

- `src/domain` — types, levels, serializable DSL
- `src/engine` — evaluation, matching, rate-limit, fingerprints
- `src/adapters` — Express / Fastify / Nest / `createAdapter`
- `src/presets` — built-in rule packs
- `src/logging` — optional logger port
- `integration/` — Express, Fastify, NestJS, Koa samples
- `docs/` — this documentation site (plain Markdown)
- `BENCHMARKS.md` — performance report (update when engine costs change)

## Guidelines

- Do not invent public APIs in docs or examples — mirror `src/**` and `package.json` `exports`.
- Prefer immutability for preset arrays; dedupe by `id` when composing.
- Keep logging off by default; avoid new mandatory dependencies for the hot path.
- When changing `src/engine/*` or `src/domain/*` in ways that affect cost, re-run benches and refresh `BENCHMARKS.md`.

## Funding

Mini-WAF is maintained in the open, unpaid. Donations on
[Ko-fi](https://ko-fi.com/murylloex) fund rule-set curation, the documentation site and the
maintenance time behind both.

## License

MIT — see `LICENSE` in the repository root.
