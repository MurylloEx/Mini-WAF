# Framework integrations

Built-in integrations share one engine (`createWafEngine` under `createMiniWaf`). Install only the peer for your stack. The repo also ships runnable apps under `integration/` (`integration/express`, `integration/fastify`, `integration/nestjs-express`, `integration/koa`).

## Express

**Import:** `mini-waf/express`
**Peer:** `express` `>= 4`

```ts
import express from 'express';
import { expressWaf, expressSecurityPolicy } from 'mini-waf/express';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(expressSecurityPolicy()); // optional
app.use(
  expressWaf({
    presets: ['default'],
    level: 'balanced',
  }),
);
```

`expressWaf(config, options?)` returns standard `(req, res, next)` middleware. Internally it calls `runWithAdapter(waf, createExpressAdapter(), req, res, next)`, which builds a `WafHttpContext` and runs `engine.handle(ctx)`. On `allow` **and** `!ctx.isBlocked()` it calls `next()`; on `block`, `WafHttpContext.drop(statusCode, body)` has already ended the response through the Express adapter (`res.status(code).end(body)` when available, otherwise `res.statusCode = code; res.end(body)`), so `next()` is skipped.

```ts
// src/adapters/express.adapter.ts (excerpt) — how the adapter derives fields
const ip = resolveIp(req); // req.ip → X-Forwarded-For first hop → socket.remoteAddress
const url = req.originalUrl || req.url || '/';
const path = url.match(/^[^?]*/)?.[0] || '/';
const getRawBody = lazyBodyToString(() => req.rawBody ?? req.body);
```

Two details worth internalizing when wiring Express:

- `getRawBody` is **lazy** (`lazyBodyToString`): `JSON.stringify`-ing an already-parsed body only happens the first time a rule actually resolves `field: 'body'`, and the result is memoized for the rest of the request. Clean requests that never trigger a body-scoped rule pay nothing extra.
- Real client IP resolution order: `req.ip` (if the Express app trusts a proxy and Express itself resolved it) → first hop of `X-Forwarded-For` → `req.connection.remoteAddress` / `req.socket.remoteAddress`. All three go through `normalizeClientIp`, which canonicalizes `::ffff:a.b.c.d` to `a.b.c.d` and compresses IPv6 — so `rateLimit` buckets and `equals: 'ip'` rules see one canonical form regardless of transport quirks.

Optional secure headers: `expressSecurityPolicy()` sets `X-Frame-Options: sameorigin`, `X-XSS-Protection: 1`, `X-Content-Type-Options: nosniff`, removes `X-Powered-By`/`Server`, and mirrors `Origin` into `Access-Control-Allow-Origin` (plus full preflight headers on `OPTIONS`). It does not touch the WAF decision — apply it independently.

See `integration/express/server.mjs` for a full runnable sample.

## Fastify

**Import:** `mini-waf/fastify`
**Peer:** `fastify` `>= 4`

```ts
import Fastify from 'fastify';
import { fastifyWaf, fastifySecurityPolicy } from 'mini-waf/fastify';

const app = Fastify();
app.addHook('onRequest', fastifySecurityPolicy()); // optional

await app.register(fastifyWaf, {
  config: {
    presets: ['default'],
    level: 'balanced',
  },
});
```

Plugin options accept `config` or `settings` (same `WafConfig` — `opts.config ?? opts.settings ?? { presets: ['default'] }`), plus anything from `WafEngineOptions` (e.g. `logger`, `rateLimitStore`) because `FastifyPluginOptions extends WafEngineOptions`. The plugin registers a `preHandler` hook:

```ts
// src/fastify.ts (excerpt)
instance.addHook('preHandler', async (request, reply) => {
  const { result } = await runWithAdapter(waf, adapter, request, reply);
  if (result.decision === 'block' && !reply.sent) {
    reply.code(403).send('Forbidden');
  }
});
```

Note the `!reply.sent` guard: the Fastify adapter's `drop()` already calls `reply.code(statusCode).send(body)` with the rule's configured `blockStatusCode`/`blockBody` (default `403`/`'Forbidden'`) — this second check only exists as a defensive fallback and does not usually fire with custom `blockStatusCode`, since `drop()` runs first inside `engine.handle`.

The export is marked with Fastify's `skip-override` symbol (`Object.assign(fastifyWaf, { [Symbol.for('skip-override')]: true })`) so the `preHandler` hook still applies to routes declared on **parent-scoped** instances even though `fastifyWaf` is registered as an encapsulated plugin — you do not need `fastify-plugin` yourself.

Without the plugin wrapper, register a manual `preHandler` on a subset of routes:

```ts
import { fastifyPreHandler } from 'mini-waf/fastify';

app.register(async (instance) => {
  instance.addHook('preHandler', fastifyPreHandler({ presets: ['default'], level: 'high' }));
  instance.get('/admin/stats', async () => ({ ok: true }));
}, { prefix: '/admin' });
```

See `integration/fastify/server.mjs`.

## NestJS

**Import:** `mini-waf/nestjs`
**Peers:** `@nestjs/common`, `@nestjs/core` `>= 9`

```ts
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { MiniWafModule, MiniWafMiddleware } from 'mini-waf/nestjs';

@Module({
  imports: [
    MiniWafModule.forRoot({
      config: {
        presets: ['default'],
        level: 'balanced',
      },
      platform: 'auto', // 'express' | 'fastify' | 'auto'
    }),
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(MiniWafMiddleware).forRoutes('*');
  }
}
```

### How `platform: 'auto'` decides

`createNestAdapter('auto')` (`src/adapters/nestjs.adapter.ts`) picks Express or Fastify structurally, with no `@nestjs/platform-*` import:

```ts
function isFastifyReply(res: NestResponse): res is FastifyLikeReply {
  return (
    'code' in res && typeof res.code === 'function' &&
    'send' in res && typeof res.send === 'function' &&
    'header' in res && typeof res.header === 'function'
  );
}

function looksLikeFastifyRequest(req: NestRequest): boolean {
  return 'server' in req || ('ips' in req && Array.isArray(req.ips));
}
```

When the reply looks like a Fastify `FastifyReply` (has `code`/`send`/`header`), or the request carries Fastify-only fields (`server`, `ips`), the adapter maps the Nest request/response through `toFastifyRequest` and delegates to `createFastifyAdapter()`. Otherwise it maps through `toExpressRequest` and delegates to `createExpressAdapter()`. Pin `platform: 'express'` or `platform: 'fastify'` explicitly if you use a custom Nest HTTP adapter that could confuse the heuristic.

### Why `MiniWafModule.forRoot` exists

```ts
// src/nestjs.ts (excerpt)
export class MiniWafMiddleware {
  private static boundOptions: NestMiniWafOptions | undefined;

  static bindOptions(options: NestMiniWafOptions): void {
    MiniWafMiddleware.boundOptions = options;
  }

  constructor(options?: NestMiniWafOptions) {
    const resolved = options ?? MiniWafMiddleware.boundOptions;
    if (resolved === undefined) {
      throw new Error(/* ... */);
    }
    this.waf = createMiniWaf(resolveConfig(resolved), resolved);
    this.adapter = createNestAdapter(resolved.platform ?? 'auto');
  }
  // ...
}
```

Nest instantiates middleware **classes** passed to `consumer.apply(...)` with `new MiniWafMiddleware()` — it does not run them through the DI container the way it does controllers/providers, so `@Inject()` constructor parameters are not an option here. `MiniWafModule.forRoot(options)` works around this by statically binding the options onto the class (`MiniWafMiddleware.bindOptions(options)`) before returning the `DynamicModule`, so by the time Nest calls `new MiniWafMiddleware()` the constructor can fall back to `MiniWafMiddleware.boundOptions`. The token `MINI_WAF_OPTIONS` is also provided/exported for advanced wiring (e.g. re-reading the resolved config from another provider via `@Inject(MINI_WAF_OPTIONS)`).

Functional alternative when you would rather not use a module at all:

```ts
import { nestMiddleware } from 'mini-waf/nestjs';

const waf = nestMiddleware({ presets: ['default'], level: 'balanced' }, { platform: 'auto' });

// Anywhere Nest (or a raw Express/Fastify app underneath) accepts an
// (req, res, next) middleware:
app.use(waf);
```

See `integration/nestjs-express/` for a TypeScript Nest + Express sample.

## Integration test apps

From the repo root:

```bash
npm run integration
```

That builds the library (`npm run build` first — the apps import from `dist/`) and runs the scenarios under `integration/` (Express, Fastify, NestJS, and the custom Koa adapter). Each app under `integration/*/server.mjs` boots a tiny real server (see `integration/koa/server.mjs` for the adapter pattern reused in [Custom adapters](/guide/custom-adapters)), and `integration/scenarios/run.mjs` drives HTTP requests against all of them to assert consistent allow/block behavior across frameworks.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Body rules never fire | WAF before body parser | Put parser first (Express); register plugin after Fastify's parser is available; Nest after platform defaults |
| Nest never blocks | Middleware not applied | `consumer.apply(MiniWafMiddleware).forRoutes('*')` |
| Nest throws `MiniWafMiddleware requires options` | `MiniWafMiddleware` used without `MiniWafModule.forRoot` and no constructor options | Use the module, or `new MiniWafMiddleware({ config, platform })` explicitly |
| Fastify hook does not run on a nested plugin's routes | Registered the WAF with a plugin that is itself encapsulated below yours | `fastifyWaf` already sets `skip-override`; register it high in the plugin tree (e.g. on the root instance) rather than deep inside an unrelated encapsulated sub-plugin |
| Unexpected FPs | Level too high | Drop to `balanced` / `low`, narrow presets, or use `disabledRuleIds` / early `allow` |

More in [Security notes](/guide/security).
