# Quick start

Minimal examples for the three built-in integrations, followed by fuller, closer-to-production versions. All three integrations pass the same `WafConfig` shape (`presets`, `level`, optional `rules`, and the performance/logging knobs documented in [Configuration](/guide/configuration)) into `createMiniWaf` under the hood — only the adapter that maps the framework's request/response onto `WafHttpContext` changes.

## Express

```ts
import express from 'express';
import { expressWaf } from 'mini-waf/express';

const app = express();

// 1) parser
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 2) WAF
app.use(
  expressWaf({
    presets: ['default'],
    level: 'balanced',
  }),
);

// 3) routes
app.get('/health', (_req, res) => res.send('ok'));
app.listen(3000);
```

Optional secure headers: `app.use(expressSecurityPolicy())` from `mini-waf/express`.

### Realistic Express app

The middleware order rule (`parser → WAF → routes`) matters because `WafField` values like `'body'` are read from `req.body` / `req.rawBody` — if nothing parsed the request yet, the field resolver in `src/engine/field-resolver.ts` sees an empty string and body-based rules never fire. The example below adds error handling, several routes with different exposure profiles, and a couple of custom rules layered on top of the `default` preset pack.

```ts
import express, { type Request, type Response, type NextFunction } from 'express';
import { expressWaf, expressSecurityPolicy } from 'mini-waf/express';
import type { WafConfig } from 'mini-waf';

const app = express();

// --- 1) Body parsers first --------------------------------------------
// Without this, `body`-scoped rules (SQLi/XSS presets, custom rules using
// `field: 'body'`) always see an empty string — not a bug, just missing input.
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// --- 2) Optional hardened response headers -----------------------------
// Sets X-Frame-Options, X-XSS-Protection, X-Content-Type-Options, strips
// X-Powered-By/Server, and mirrors CORS Origin/Access-Control-* on OPTIONS.
app.use(expressSecurityPolicy());

// --- 3) WAF config -------------------------------------------------------
const wafConfig: WafConfig = {
  // 'default' = scanners + protocol + sqli + xss + path-traversal + rfi + rce
  presets: ['default'],
  // Only rules whose `minLevel` is <= 'balanced' are active (low < balanced < high < paranoid)
  level: 'balanced',
  rules: [
    {
      // Whitelist health checks *before* any preset can match. `priority: 1`
      // makes this rule run first; `action: 'allow'` short-circuits the scan
      // so a load balancer's HEAD/GET /health never risks a false positive.
      id: 'allow-health',
      priority: 1,
      action: 'allow',
      when: { field: 'path', equals: '/health' },
    },
    {
      // Compound AND: block only when the path looks like an admin surface
      // AND the request carries no session cookie — i.e. an unauthenticated
      // probe against /admin*, not a logged-in operator.
      id: 'block-unauthenticated-admin-probe',
      action: 'block',
      reason: 'Unauthenticated request to an admin surface',
      when: {
        all: [
          { field: 'path', matches: /^\/admin(\/|$)/ },
          { not: { field: 'cookies.session', matches: /^.+$/ } },
        ],
      },
    },
  ],
  // Logging is off unless you opt in — see the Logging guide.
  logging: { level: 'info' },
  // Truncate scanned field values before matching (regex-cost bound); 8192 is the engine default.
  maxFieldLength: 8_192,
};

app.use(expressWaf(wafConfig));

// --- 4) Routes ------------------------------------------------------------
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok' });
});

app.get('/search', (req: Request, res: Response) => {
  // Legitimate query strings still pass through untouched when they don't
  // match any active rule — the WAF never rewrites or sanitizes input.
  res.json({ query: req.query.q ?? null });
});

app.post('/orders', express.json(), (req: Request, res: Response) => {
  // If this payload contained something like {"q":"' OR 1=1 --"} it would
  // have been blocked upstream by `preset-sqli-classic-body` before reaching
  // this handler — no need to re-validate for that class of injection here.
  res.status(201).json({ id: 'order_123', ...req.body });
});

// --- 5) Error handling -----------------------------------------------------
// The WAF middleware forwards adapter/body errors via `next(err)`; keep a
// generic error handler last so those don't crash the process.
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('unhandled error', err);
  res.status(500).json({ error: 'internal_error' });
});

app.listen(3000, () => {
  console.log('listening on http://localhost:3000');
});
```

## Fastify

```ts
import Fastify from 'fastify';
import { fastifyWaf } from 'mini-waf/fastify';

const app = Fastify();

// Fastify has a built-in JSON parser; register WAF before routes
await app.register(fastifyWaf, {
  config: {
    presets: ['default'],
    level: 'balanced',
  },
});

app.get('/health', async () => ({ ok: true }));
await app.listen({ port: 3000 });
```

Without the plugin: `fastifyPreHandler(config)` as a manual `preHandler` hook.

Optional headers: `app.addHook('onRequest', fastifySecurityPolicy())`.

### Realistic Fastify app

`fastifyWaf` is registered with `app.register(...)` and internally calls `instance.addHook('preHandler', ...)`; it is exported with Fastify's `skip-override` symbol set (`Object.assign(fastifyWaf, { [Symbol.for('skip-override')]: true })`) so the hook still applies to routes declared on parent-scoped instances, not just the plugin's own encapsulated context.

```ts
import Fastify, { type FastifyInstance } from 'fastify';
import { fastifyWaf, fastifySecurityPolicy } from 'mini-waf/fastify';
import type { WafConfig } from 'mini-waf';

const app: FastifyInstance = Fastify({ logger: true });

// Optional hardened headers as an onRequest hook (runs before parsing).
app.addHook('onRequest', fastifySecurityPolicy());

const wafConfig: WafConfig = {
  presets: ['default'],
  level: 'balanced',
  // Cap concurrent distinct rate-limit buckets (per-IP by default) — bounds
  // memory under a distributed flood instead of growing the Map unbounded.
  maxRateLimitKeys: 10_000,
  // Short-lived decision cache: repeated identical requests (same method +
  // path + IP + query + UA + body hash) skip re-scanning rules entirely.
  // Disabled automatically if any active rule carries `rateLimit` (see
  // preset-dos-rate-limit inside the `default` pack) so counters keep advancing.
  decisionCache: { max: 512, ttlMs: 2_000 },
};

// `fastifyWaf` accepts { config } or { settings } — both are the same WafConfig.
await app.register(fastifyWaf, { config: wafConfig });

app.get('/health', async () => ({ status: 'ok' }));

app.get('/search', async (request) => {
  const { q } = request.query as { q?: string };
  return { query: q ?? null };
});

app.post('/orders', async (request, reply) => {
  // Fastify parses JSON before preHandler hooks run, so `request.body` is
  // already populated when the WAF's `preHandler` inspects `field: 'body'`.
  const body = request.body as Record<string, unknown>;
  reply.code(201);
  return { id: 'order_123', ...body };
});

// Fastify's default error handler already responds with 500 on uncaught
// errors; override only if you need a custom envelope.
app.setErrorHandler((err, _req, reply) => {
  app.log.error(err);
  reply.status(500).send({ error: 'internal_error' });
});

await app.listen({ port: 3000, host: '0.0.0.0' });
```

Manual hook (no plugin wrapper), useful when you only want the WAF on a subset of routes:

```ts
import { fastifyPreHandler } from 'mini-waf/fastify';

const protectAdminRoutes = fastifyPreHandler({
  presets: ['default'],
  level: 'high', // stricter on the admin surface than the public API
});

app.register(
  async (instance) => {
    instance.addHook('preHandler', protectAdminRoutes);
    instance.get('/admin/stats', async () => ({ ok: true }));
  },
  { prefix: '/admin' },
);
```

## NestJS

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
    // Apply early (all routes). Nest/Express body parser already runs before this.
    consumer.apply(MiniWafMiddleware).forRoutes('*');
  }
}
```

Functional factory (no module): `nestMiddleware({ presets: ['default'], level: 'balanced' })`.

### Realistic NestJS app

`MiniWafModule.forRoot(options)` calls `MiniWafMiddleware.bindOptions(options)` before returning the dynamic module — this is required because Nest constructs middleware *classes* with `new MiniWafMiddleware()` and cannot inject constructor arguments the way it injects providers into controllers/services. `MiniWafMiddleware`'s constructor falls back to the statically bound options, then builds a `createNestAdapter(platform)` that structurally detects Express vs Fastify request/response shapes (looking for Fastify's `code`/`send`/`header` methods on the reply) when `platform: 'auto'`.

```ts
import {
  Module,
  NestModule,
  MiddlewareConsumer,
  Controller,
  Get,
  Post,
  Body,
  Query,
} from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import { MiniWafModule, MiniWafMiddleware } from 'mini-waf/nestjs';
import type { WafConfig } from 'mini-waf';

const wafConfig: WafConfig = {
  presets: ['default'],
  level: 'balanced',
  disabledRuleIds: [
    // Drop the broad scanner UA list (paranoid-only, higher FP) even though
    // we run at 'balanced' where it would not be active anyway — explicit
    // beats implicit when the config is meant to be read by ops later.
    'preset-scanners-ua-broad',
  ],
  rules: [
    {
      id: 'allow-health',
      priority: 1,
      action: 'allow',
      when: { field: 'path', equals: '/health' },
    },
  ],
};

@Controller()
class AppController {
  @Get('health')
  health() {
    return { status: 'ok' };
  }

  @Get('search')
  search(@Query('q') q?: string) {
    return { query: q ?? null };
  }

  @Post('orders')
  createOrder(@Body() body: Record<string, unknown>) {
    // Already scanned by the WAF middleware before the Nest router dispatched
    // here (SQLi/XSS presets on `field: 'body'` run in the middleware layer).
    return { id: 'order_123', ...body };
  }
}

@Module({
  imports: [MiniWafModule.forRoot({ config: wafConfig, platform: 'auto' })],
  controllers: [AppController],
})
class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(MiniWafMiddleware).forRoutes('*');
  }
}

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  await app.listen(3000);
}
void bootstrap();
```

Functional alternative when you do not want a dynamic module (e.g. a hand-rolled Express bootstrap around Nest):

```ts
import { nestMiddleware } from 'mini-waf/nestjs';

const waf = nestMiddleware({ presets: ['default'], level: 'balanced' }, { platform: 'express' });
app.use(waf); // plain Express-compatible (req, res, next) signature
```

## Custom adapter (any framework)

See [Custom adapters](/guide/custom-adapters) for a complete Koa adapter walkthrough using `createAdapter` + `createMiniWaf`, including field-by-field explanations of `WafHttpContext`.

## Next

- [Core concepts](/guide/concepts) — rules, levels, enable/disable
- [Framework integrations](/guide/integrations) — more detail and integration apps
