# NestJS

**Import:** `mini-waf/nestjs` · **Peers:** `@nestjs/common`, `@nestjs/core` `>= 9`

```bash
npm install mini-waf @nestjs/common @nestjs/core
```

Mini-WAF plugs into Nest as **middleware**, so it runs before guards,
interceptors and the router — and after the platform's body parsing.

## Minimal setup

```ts
import { Module, NestModule, MiddlewareConsumer } from '@nestjs/common';
import { MiniWafModule, MiniWafMiddleware } from 'mini-waf/nestjs';

@Module({
  imports: [
    MiniWafModule.forRoot({
      config: { presets: ['default'], level: 'balanced' },
      platform: 'auto', // 'express' | 'fastify' | 'auto'
    }),
  ],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // Apply early, to all routes. Nest's body parser already ran by now.
    consumer.apply(MiniWafMiddleware).forRoutes('*');
  }
}
```

Both steps are required: `forRoot` supplies the options, `configure` actually
mounts the middleware. Importing the module alone does nothing.

## Why `MiniWafModule.forRoot` exists

Nest instantiates middleware **classes** passed to `consumer.apply(...)` with a
plain `new MiniWafMiddleware()`. It does not run them through the DI container
the way it does controllers and providers, so `@Inject()` constructor parameters
are not available.

`forRoot(options)` works around that by statically binding the options onto the
class before returning the `DynamicModule`:

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

By the time Nest calls `new MiniWafMiddleware()`, the constructor falls back to
`MiniWafMiddleware.boundOptions`. The `MINI_WAF_OPTIONS` token is also provided
and exported, so another provider can read the resolved config via
`@Inject(MINI_WAF_OPTIONS)`.

::: warning One engine per process
Because options are bound statically on the class, a second
`MiniWafModule.forRoot(...)` overwrites the first. For two different policies,
use `nestMiddleware(...)` (below) to build independent instances.
:::

## How `platform: 'auto'` decides

`createNestAdapter('auto')` picks Express or Fastify **structurally**, without
importing `@nestjs/platform-*`:

```ts
// src/adapters/nestjs.adapter.ts (excerpt)
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

When the reply looks like a `FastifyReply` (`code`/`send`/`header`), or the
request carries Fastify-only fields (`server`, `ips`), the adapter maps through
`toFastifyRequest` and delegates to `createFastifyAdapter()`. Otherwise it maps
through `toExpressRequest` and uses `createExpressAdapter()`.

Pin `platform: 'express'` or `platform: 'fastify'` explicitly if you run a
custom Nest HTTP adapter that could confuse the heuristic.

## Functional alternative

When you would rather not use a dynamic module — for example a hand-rolled
Express bootstrap around Nest, or two different policies in one process:

```ts
import { nestMiddleware } from 'mini-waf/nestjs';

const waf = nestMiddleware(
  { presets: ['default'], level: 'balanced' },
  { platform: 'express' },
);

app.use(waf); // plain Express-compatible (req, res, next)
```

## Production-shaped example

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
    // Broad scanner UA list is paranoid-only, so it would not run at
    // 'balanced' anyway — listing it explicitly documents the intent for
    // whoever reads this config during an incident.
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
    // Already scanned in the middleware layer, before the router dispatched
    // here — SQLi/XSS body rules ran against the parsed payload.
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

## Scoping to some routes

`MiddlewareConsumer` already supports this — no Mini-WAF-specific API needed:

```ts
configure(consumer: MiddlewareConsumer) {
  consumer
    .apply(MiniWafMiddleware)
    .exclude('metrics', 'health')
    .forRoutes('*');
}
```

Prefer an `allow` rule over `exclude` when you want the path *logged* as
allowed rather than skipped entirely.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Nothing is ever blocked | Module imported but middleware never mounted | Add `consumer.apply(MiniWafMiddleware).forRoutes('*')` |
| `MiniWafMiddleware requires options` | Used without `MiniWafModule.forRoot` and without constructor options | Use the module, or `new MiniWafMiddleware({ config, platform })` |
| Wrong adapter picked | Custom Nest HTTP adapter confuses the `auto` heuristic | Pin `platform: 'express'` or `'fastify'` |
| Second `forRoot` silently wins | Options are bound statically on the class | Use `nestMiddleware()` for independent policies |

::: info Module shape
`MiniWafModule` is a plain class with no `@Module()` decorator, which keeps
`@nestjs/common` a genuinely optional peer — importing `mini-waf` never pulls
Nest into a non-Nest project.
:::

## Runnable sample

`integration/nestjs-express/` in the repository is a TypeScript Nest + Express
app used by the [integration scenarios](/guide/integrations/testing).
