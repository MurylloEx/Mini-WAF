# Installation

## Requirements

- **Node.js** — the package declares `>= 18`; CI builds and tests on **22, 24 and 26**
- **TypeScript** optional but fully supported (the package ships `.d.ts` files)

## Install the package

```bash
npm install mini-waf
```

Framework integrations are **optional peers**. Install only the framework you use:

```bash
# Express
npm install mini-waf express

# Fastify
npm install mini-waf fastify

# NestJS
npm install mini-waf @nestjs/common @nestjs/core
```

| Framework | Peer dependency | Import |
|-----------|-----------------|--------|
| Express | `express` `>= 4` | `mini-waf/express` |
| Fastify | `fastify` `>= 4` | `mini-waf/fastify` |
| NestJS | `@nestjs/common` / `@nestjs/core` `>= 9` | `mini-waf/nestjs` |
| Core / custom adapter | none beyond Node | `mini-waf` |

## Middleware order

**Order matters:** body parser (if any) → WAF → routes.

Without a parser first, `body` may be empty and payload rules will not fire.

```ts
// Express — correct order
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(expressWaf({ presets: ['default'], level: 'balanced' }));
```

Fastify has a built-in JSON parser; register the WAF plugin **before** routes.

Nest: apply `MiniWafMiddleware` early (`forRoutes('*')`) after the platform’s default body setup.

## Verify TypeScript

```ts
import type { WafConfig, WafRule } from 'mini-waf';
import { expressWaf } from 'mini-waf/express';

const config: WafConfig = {
  presets: ['default'],
  level: 'balanced',
};

app.use(expressWaf(config));
```

## Next

[Quick start](/guide/quick-start) — running in three steps, then the per-framework
guides under [Integrations](/guide/integrations/).
