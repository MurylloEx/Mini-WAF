# Framework integrations

Built-in integrations share one engine. Install only the peer for your stack. The repo also ships runnable apps under `integration/`.

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

`expressWaf(config, options?)` returns standard `(req, res, next)` middleware. On `allow`, it calls `next()`; on `block`, the adapter drops the response.

See `integration/express/server.mjs` for a full sample.

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

Plugin options accept `config` or `settings` (same `WafConfig`). The plugin is marked with Fastify’s `skip-override` so hooks apply to parent routes.

Manual hook: `fastifyPreHandler(config)`.

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

Notes:

- `MiniWafModule.forRoot` binds options onto `MiniWafMiddleware` before Nest instantiates it (Nest middleware classes are constructed without DI for constructor options unless you use the module).
- Token `MINI_WAF_OPTIONS` is also provided/exported for advanced wiring.
- Functional alternative: `nestMiddleware({ presets: ['default'], level: 'balanced' })`.

See `integration/nestjs-express/` for a TypeScript Nest + Express sample.

## Integration test apps

From the repo root:

```bash
npm run integration
```

That builds the library and runs the scenarios under `integration/` (Express, Fastify, NestJS, and the custom Koa adapter).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Body rules never fire | WAF before body parser | Put parser first (Express); register plugin after Fastify’s parser is available; Nest after platform defaults |
| Nest never blocks | Middleware not applied | `consumer.apply(MiniWafMiddleware).forRoutes('*')` |
| Unexpected FPs | Level too high | Drop to `balanced` / `low`, narrow presets, or use `disabledRuleIds` / early `allow` |

More in [Security notes](/guide/security).
