# Integrations overview

Every integration wraps the **same engine**. `expressWaf`, `fastifyWaf` and
`MiniWafModule` all end up calling `createMiniWaf(config)`; the only thing that
differs is the adapter that maps the framework's request/response pair onto a
[`WafHttpContext`](/guide/api).

That means one `WafConfig` is portable across all of them:

```ts
import type { WafConfig } from 'mini-waf';

// Identical object for Express, Fastify and NestJS.
export const wafConfig: WafConfig = {
  presets: ['default'],
  level: 'balanced',
};
```

## Pick your framework

| Framework | Import | Peer | Wiring | Page |
|-----------|--------|------|--------|------|
| Express | `mini-waf/express` | `express >= 4` | `app.use(expressWaf(config))` | [Express](/guide/integrations/express) |
| Fastify | `mini-waf/fastify` | `fastify >= 4` | `app.register(fastifyWaf, { config })` | [Fastify](/guide/integrations/fastify) |
| NestJS | `mini-waf/nestjs` | `@nestjs/common` + `@nestjs/core >= 9` | `MiniWafModule.forRoot({ config })` | [NestJS](/guide/integrations/nestjs) |
| Anything else | `mini-waf` + `mini-waf/adapters` | none | `createAdapter` + `createMiniWaf` | [Custom adapters](/guide/integrations/custom-adapters) |

Peers are declared **optional** — installing Mini-WAF does not pull in a
framework you do not use.

## What every integration guarantees

- **Block ends the request.** The adapter's `drop(statusCode, body)` writes the
  response (default `403` / `Forbidden`) and downstream handlers never run.
- **Allow is transparent.** The WAF never rewrites, sanitizes or re-encodes
  input; a request that matches nothing is passed through untouched.
- **The body is read lazily.** Serializing an already-parsed body happens only
  the first time a rule actually resolves `field: 'body'`, and is memoized for
  the rest of that request.
- **Client IP is canonical.** `::ffff:a.b.c.d` is folded to `a.b.c.d` and IPv6
  is compressed before rules or rate-limit buckets see it.

## The one rule that applies everywhere

**Body parser → WAF → routes.**

If the WAF runs before anything parsed the request, `field: 'body'` resolves to
an empty string and every body-scoped rule silently passes. That is the single
most common integration mistake; each framework page shows the correct order.

## Shared troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Body rules never fire | WAF registered before the body parser | See the ordering section on your framework's page |
| Unexpected 403s | `level` too high for your traffic | Drop to `balanced` / `low`, narrow `presets`, or use `disabledRuleIds` — see [Security notes](/guide/security) |
| Health checks blocked | A preset matched a probe path | Add an early `allow` rule with `priority: 1` |

Framework-specific symptoms live on each page.
