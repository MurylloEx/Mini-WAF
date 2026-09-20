# Introduction

**Mini-WAF** is a minimal Web Application Firewall for Node.js. You plug it in as middleware or a plugin and evaluate each request with typed presets and declarative rules.

It is published on npm as [`mini-waf`](https://www.npmjs.com/package/mini-waf) — a v1 rewrite in TypeScript: framework-agnostic core plus thin adapters.

## Design goals

| Goal | What it means in practice |
|------|---------------------------|
| **Framework-agnostic core** | The engine only sees a `WafHttpContext`. Express, Fastify, NestJS, or a custom runtime map into that shape via adapters. |
| **Adapters, not forks** | Built-in packages export `mini-waf/express`, `mini-waf/fastify`, and `mini-waf/nestjs`. Anything else uses `createAdapter` + `createMiniWaf`. |
| **Immutability** | Preset rule arrays are never mutated. Resolving presets dedupes by `id` into a new list. Config is treated as read-only input. |
| **Typed rules** | Rules, conditions, fields, and actions are TypeScript types (`WafRule`, `WafCondition`, `WafField`, `WafAction`). |
| **Protection levels** | Each rule may declare `minLevel`. Your config `level` (`low` \| `balanced` \| `high` \| `paranoid`) decides which rules run. |
| **Optional I/O** | Logging is **off by default**. No color libraries, no built-in file sinks, no required peer frameworks beyond the one you use. |

## What it is (and is not)

**It is:** an in-process request filter for Node HTTP apps — pattern matching on query, path, body, headers, cookies, and related fields, plus simple per-key rate limiting.

**It is not:** a reverse proxy, a ModSecurity / full OWASP CRS parser, or a network firewall. Presets are **inspired by** CRS categories (e.g. SQLi ≈ REQUEST-942); they are a compact, typed subset for Node middleware.

## Package surface

| Import | Purpose |
|--------|---------|
| `mini-waf` | Core: `createMiniWaf`, domain types, presets helpers, adapters, logging utilities |
| `mini-waf/express` | `expressWaf`, `expressSecurityPolicy` |
| `mini-waf/fastify` | `fastifyWaf`, `fastifyPreHandler`, `fastifySecurityPolicy` |
| `mini-waf/nestjs` | `MiniWafModule`, `MiniWafMiddleware`, `nestMiddleware` |
| `mini-waf/adapters` | `createAdapter` and built-in adapter factories |
| `mini-waf/presets` | Preset rule arrays and `resolvePresets` |

## Next steps

- [Installation](/guide/installation) — requirements and peers
- [Quick start](/guide/quick-start) — running in three steps
- [Core concepts](/guide/concepts) — how rules and decisions work
