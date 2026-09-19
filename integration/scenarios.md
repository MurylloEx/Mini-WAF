# Integration scenarios

Automated by `scenarios/run.mjs`. Each core scenario runs against **express** (`:3101`), **fastify** (`:3102`), **nestjs-express** (`:3103`), and **koa** (`:3104`) unless noted.

Shared baseline config: `{ presets: ['default'], level: 'balanced' }`.

| # | Scenario | Request | Expected |
|---|----------|---------|----------|
| 1 | Clean request | `GET /` | `200` |
| 2 | SQLi in query | `GET /search?q=1'+OR+1=1` | `403` |
| 3 | XSS in query | `GET /search?q=<script>alert(1)</script>` | `403` |
| 4 | Path traversal | `GET /search?q=../../etc/passwd` | `403` |
| 5 | RFI / remote URL | `GET /search?q=http://evil.example/shell.txt` | `403` |
| 6 | Scanner UA | `GET /` with `User-Agent: sqlmap/1.7` | `403` |
| 7 | Health path | `GET /health` | `200` (default preset does **not** whitelist `/health`; clean traffic is allowed) |
| 8 | POST body SQLi | `POST /echo` JSON `{ "msg": "1 OR 1=1" }` | `403` |
| 8b | POST body XSS | `POST /echo` JSON `{ "msg": "<script>x</script>" }` | `403` |
| 9 | Rate-limit | Many requests from same IP | Optional / flaky — default rule is `120` req / `60s` (`preset-dos-rate-limit`). Not asserted in CI-style runner; see notes below. |
| 10 | `disabledRuleIds` smoke | Ephemeral Express + Nest (`nestMiddleware`) with SQLi query rules disabled | SQLi query → `200` |
| 10b | Custom rule smoke | Ephemeral Express + Nest with rule blocking path `/blocked` | `GET /blocked` → `403` |

## How to run

```bash
# full suite (build not included — run `npm run build` at repo root first)
cd integration && npm run integration

# against already-running servers
node scenarios/run.mjs --no-start
```

Environment overrides:

- `INTEGRATION_HOST` (default `127.0.0.1`)
- `EXPRESS_PORT` / `FASTIFY_PORT` / `NEST_PORT` / `KOA_PORT` (defaults `3101` / `3102` / `3103` / `3104`)
- `SKIP_RATE_LIMIT=1` (default) — skip scenario 9
- `RUN_RATE_LIMIT=1` — attempt rate-limit (expects `403` within ~150 rapid requests; may flake)

## Framework differences

| Topic | Express | Fastify | NestJS (Express) | Koa (custom adapter) |
|-------|---------|---------|------------------|----------------------|
| WAF entry | `expressWaf` middleware | `fastifyWaf` plugin (`preHandler`) | `MiniWafModule` + `MiniWafMiddleware` | `createAdapter` + `createMiniWaf` / `protect` |
| Body before WAF | `express.json()` then WAF | Built-in JSON parser → `preHandler` | Nest body parser → middleware | `koa-bodyparser` then WAF |
| Block response | Adapter `drop()` → `403` + `Forbidden` | Plugin also sends `403` if not already sent | Same as Express adapter | Adapter `drop()` sets `ctx.status` / `ctx.body` |
| Path matching | `originalUrl` / `url` | `routerPath` or URL path | Express-shaped on this platform | `ctx.path` via adapter `getPath` |

## Notes / known caveats

1. **`/health` is not special** under `presets: ['default']`. A whitelist would need a custom `allow` rule or omitting the path from middleware.
2. **Rate-limit** shares an in-process counter per engine instance. Hitting four servers does not share counters. Triggering 120+ requests is slow and can interfere with other scenarios if run mid-suite — keep it optional.
3. **RFI on path** does not match bare `http://` (query does). Prefer query payloads for scenario 5.
4. **SQLi classic** matches patterns like `OR 1=1` / `UNION SELECT`; advanced time-based patterns need `level: 'high'` or above.
5. Nest `MiniWafModule` is a plain class (no `@Module()` decorator) so `@nestjs/common` stays an optional peer. `forRoot` binds options onto `MiniWafMiddleware` because Nest instantiates middleware via `new` without `@Inject`.
6. **Koa** has no built-in Mini-WAF package entry; the integration app is the reference for the README custom-adapter path.

## Bugs found while building this harness

| Issue | Fix |
|-------|-----|
| `MiniWafModule` was a plain object → Nest `metatype is not a constructor` | Changed to a real `class MiniWafModule` with static `forRoot` |
| Nest `apply(MiniWafMiddleware)` constructed the class with `undefined` options | `MiniWafModule.forRoot` calls `MiniWafMiddleware.bindOptions(options)` so Nest’s `new` works without `@Inject` |
