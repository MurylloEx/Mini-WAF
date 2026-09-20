# Fastify

**Import:** `mini-waf/fastify` · **Peer:** `fastify >= 4`

```bash
npm install mini-waf fastify
```

## Minimal setup

```ts
import Fastify from 'fastify';
import { fastifyWaf } from 'mini-waf/fastify';

const app = Fastify();

// Fastify parses JSON itself; just register the WAF before your routes.
await app.register(fastifyWaf, {
  config: { presets: ['default'], level: 'balanced' },
});

app.get('/health', async () => ({ ok: true }));
await app.listen({ port: 3000 });
```

## Plugin options

The plugin accepts `config` **or** `settings` — both are the same `WafConfig`
(`opts.config ?? opts.settings ?? { presets: ['default'] }`) — plus anything
from `WafEngineOptions` (`logger`, `rateLimitStore`), because
`FastifyPluginOptions extends WafEngineOptions`.

```ts
await app.register(fastifyWaf, {
  config: { presets: ['default'], level: 'balanced' },
  logger: myLogger,          // honored only when logging is enabled
  rateLimitStore: sharedStore, // share per-IP budgets across engines
});
```

## Where it hooks in

The plugin registers a `preHandler` hook, which runs **after** Fastify's body
parsing — so `field: 'body'` is already populated when rules run:

```ts
// src/fastify.ts (excerpt)
instance.addHook('preHandler', async (request, reply) => {
  const { result } = await runWithAdapter(waf, adapter, request, reply);
  if (result.decision === 'block' && !reply.sent) {
    reply.code(403).send('Forbidden');
  }
});
```

The `!reply.sent` guard is a defensive fallback. The adapter's `drop()` already
called `reply.code(statusCode).send(body)` with your configured
`blockStatusCode` / `blockBody` inside `engine.handle`, so this branch does not
usually fire — and does not override a custom status.

## Encapsulation and `skip-override`

Fastify encapsulates plugins by default, which would scope the hook to the
plugin's own context. `fastifyWaf` is exported with Fastify's `skip-override`
symbol set:

```ts
Object.assign(fastifyWaf, { [Symbol.for('skip-override')]: true });
```

so the `preHandler` applies to routes declared on **parent-scoped** instances
too. You do not need `fastify-plugin` yourself. Register it high in the plugin
tree (ideally on the root instance) rather than deep inside an unrelated
encapsulated sub-plugin.

## Protecting only some routes

When you want the WAF on a subset of routes, skip the plugin wrapper and add the
hook manually:

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

## Optional security headers

```ts
import { fastifySecurityPolicy } from 'mini-waf/fastify';

// onRequest runs before parsing, so headers are set as early as possible.
app.addHook('onRequest', fastifySecurityPolicy());
```

## Production-shaped example

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
  // Cap distinct rate-limit buckets (per-IP by default) — bounds memory
  // under a distributed flood instead of growing the Map unbounded.
  maxRateLimitKeys: 10_000,
  // Short-lived decision cache: repeated identical requests (same method +
  // path + IP + query + UA + body hash) skip re-scanning rules entirely.
  // Disabled automatically while any active rule carries `rateLimit` — which
  // the `default` pack does via preset-dos-rate-limit — so counters advance.
  decisionCache: { max: 512, ttlMs: 2_000 },
};

await app.register(fastifyWaf, { config: wafConfig });

app.get('/health', async () => ({ status: 'ok' }));

app.get('/search', async (request) => {
  const { q } = request.query as { q?: string };
  return { query: q ?? null };
});

app.post('/orders', async (request, reply) => {
  // Fastify parses JSON before preHandler hooks, so `request.body` is
  // already populated when the WAF inspects `field: 'body'`.
  const body = request.body as Record<string, unknown>;
  reply.code(201);
  return { id: 'order_123', ...body };
});

// Fastify's default error handler already answers 500 on uncaught errors;
// override only if you need a custom envelope.
app.setErrorHandler((err, _req, reply) => {
  app.log.error(err);
  reply.status(500).send({ error: 'internal_error' });
});

await app.listen({ port: 3000, host: '0.0.0.0' });
```

::: tip decisionCache and the default pack
The example above sets `decisionCache`, but the `default` preset includes
`preset-dos-rate-limit` at `balanced`, so the cache stays **disabled** to keep
DoS counters advancing. To actually use it, add
`disabledRuleIds: ['preset-dos-rate-limit']` and rate-limit at your edge
instead. See [Performance](/guide/performance).
:::

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Hook does not run on a nested plugin's routes | The WAF was registered inside an encapsulated sub-plugin | Register `fastifyWaf` on the root instance; `skip-override` handles the rest |
| Body rules never fire | A custom content-type parser runs after `preHandler` | Keep default parsing, or move the WAF to a later hook that sees the parsed body |
| Blocks return 403 despite a custom `blockStatusCode` | Something replied before the adapter's `drop()` | Check for an earlier `onRequest` hook that sends a response |

## Runnable sample

`integration/fastify/server.mjs` in the repository boots a real server used by
the [integration scenarios](/guide/integrations/testing).
