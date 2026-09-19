# Quick start

Minimal examples for the three built-in integrations. All use the same `WafConfig` shape: `presets`, `level`, optional `rules`, and performance / logging knobs.

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

## Custom adapter (any framework)

See [Custom adapters](/guide/custom-adapters) for the Koa pattern using `createAdapter` + `createMiniWaf`.

## Next

- [Core concepts](/guide/concepts) — rules, levels, enable/disable
- [Framework integrations](/guide/integrations) — more detail and integration apps
