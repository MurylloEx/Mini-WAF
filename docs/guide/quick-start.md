# Quick start

Three steps, whatever your framework: install, put the WAF **after** your body
parser, pick a level.

```bash
npm install mini-waf
```

## Express

```ts
import express from 'express';
import { expressWaf } from 'mini-waf/express';

const app = express();

app.use(express.json());                                   // 1) parser
app.use(expressWaf({ presets: ['default'], level: 'balanced' })); // 2) WAF
app.get('/health', (_req, res) => res.send('ok'));         // 3) routes

app.listen(3000);
```

→ [Full Express guide](/guide/integrations/express)

## Fastify

```ts
import Fastify from 'fastify';
import { fastifyWaf } from 'mini-waf/fastify';

const app = Fastify();

// Fastify parses JSON itself — just register before your routes.
await app.register(fastifyWaf, {
  config: { presets: ['default'], level: 'balanced' },
});

app.get('/health', async () => ({ ok: true }));
await app.listen({ port: 3000 });
```

→ [Full Fastify guide](/guide/integrations/fastify)

## NestJS

```ts
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { MiniWafModule, MiniWafMiddleware } from 'mini-waf/nestjs';

@Module({
  imports: [
    MiniWafModule.forRoot({
      config: { presets: ['default'], level: 'balanced' },
    }),
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(MiniWafMiddleware).forRoutes('*');
  }
}
```

Both steps are required — `forRoot` supplies the options, `configure` mounts the
middleware.

→ [Full NestJS guide](/guide/integrations/nestjs)

## Any other framework

`createAdapter` + `createMiniWaf` map any runtime onto the engine.
→ [Custom adapters](/guide/integrations/custom-adapters)

## Check that it works

```bash
curl -i 'http://localhost:3000/health'                  # 200
curl -i 'http://localhost:3000/health?q=1%27+OR+1%3D1'  # 403 Forbidden
```

If the first returns 403, your traffic is tripping a rule — drop to
`level: 'low'` and read [Security notes](/guide/security). If the second
returns 200, the WAF is not mounted where you think it is.

## Then what

| Next step | Page |
|-----------|------|
| Understand what a rule is | [Core concepts](/guide/concepts) |
| See what the `default` pack blocks | [Presets](/guide/presets) |
| Tune false positives | [Protection levels](/guide/protection-levels) |
| Write app-specific rules | [Custom rules](/guide/custom-rules) |
| Turn on logging | [Logging](/guide/logging) |
