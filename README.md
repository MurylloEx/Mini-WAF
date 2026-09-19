<p align="center">
  <img src="https://user-images.githubusercontent.com/32225687/78806753-849c1480-7999-11ea-8ad5-4f15ce5ad5fa.png" alt="Mini WAF" width="192" height="192"/>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/mini-waf"><img src="https://badgen.net/npm/v/mini-waf" alt="npm version"/></a>
  <a href="https://www.npmjs.com/package/mini-waf"><img src="https://badgen.net/npm/dt/mini-waf" alt="npm downloads"/></a>
  <a href="https://www.npmjs.com/package/mini-waf"><img src="https://badgen.net/npm/license/mini-waf" alt="license"/></a>
  <a href="https://www.npmjs.com/package/mini-waf"><img src="https://badgen.net/npm/types/mini-waf" alt="types"/></a>
  <img src="https://badgen.net/badge/node/%3E=18/green" alt="node"/>
  <a href="https://github.com/MurylloEx"><img src="https://badgen.net/badge/author/MurylloEx/red?icon=label" alt="author"/></a>
</p>

# Mini WAF

Minimal Web Application Firewall for Node.js (**v3**). Plug it in as middleware/plugin and evaluate each request with typed presets and declarative rules.

Supports **Express**, **Fastify**, and **NestJS** (optional peers — install only the framework you use).

## Install

```bash
npm install mini-waf
```

Peers per framework:

```bash
# Express
npm install mini-waf express

# Fastify
npm install mini-waf fastify

# NestJS
npm install mini-waf @nestjs/common @nestjs/core
```

| Framework | Import |
|-----------|--------|
| Express | `mini-waf/express` |
| Fastify | `mini-waf/fastify` |
| NestJS | `mini-waf/nestjs` |
| Core / custom adapter | `mini-waf` |

**Order matters:** body parser (if any) → WAF → routes. Without a parser first, `body` may be empty and payload rules will not fire.

---

## Quick start

### Express

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

### Fastify

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

### NestJS

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

---

## Configuration

Everything goes through `WafConfig` in `expressWaf(config)`, `fastifyWaf` (`config` or `settings`), `MiniWafModule.forRoot({ config })`, or `createMiniWaf(config)`.

```ts
{
  level?: 'low' | 'balanced' | 'high' | 'paranoid'; // default: 'balanced'
  presets?: WafPresetName[];
  rules?: WafRule[];
  enabledRuleIds?: string[];   // optional allowlist (after merge + level)
  disabledRuleIds?: string[];  // drop by id (after allowlist)
  blockStatusCode?: number;    // default: 403
  blockBody?: string;          // default: 'Forbidden'
  logging?: false | true | { level?: 'error' | 'info' | 'debug'; sink?: WafLogger };
  // logging default: false (off — no I/O)
}
```

### Levels (`level`)

Each rule (preset or custom) may declare `minLevel`. It only applies when the configured level is **greater than or equal** to that minimum:

`low` < `balanced` < `high` < `paranoid`

Custom rules **without** `minLevel` are treated as `low` (active at any level).

| Level | Includes | Typical use | ≈ CRS PL |
|-------|----------|-------------|----------|
| `low` | Obvious scanners (UA), classic SQLi, OS path/LFI, RFI / PHP RCE, strong shell RCE, SSRF metadata | APIs sensitive to false positives | PL1 (core) |
| `balanced` (default) | `low` + XSS, null-byte, uploads, DoS rate-limit, protocol splitting/smuggling, SSTI, session fixation HTML | General production | PL1–PL2 |
| `high` | `balanced` + SSI, hex flood, pollution, advanced SQLi, CL+TE, shell `$()`, session ID in URL | Under attack / broader coverage | PL2 |
| `paranoid` | `high` + broad UAs, generic tags, empty UA, shebang, oversized headers | Max coverage; more FPs | PL3–PL4 |

```ts
expressWaf({
  level: 'high',
  presets: ['default'],
  rules: [
    {
      id: 'strict-probe',
      minLevel: 'high',
      action: 'block',
      when: { field: 'query.debug', equals: '1' },
      reason: 'Debug flag blocked at high+',
    },
  ],
});
```

### Presets

```ts
{ presets: ['default'] }
// same as: sqli + xss + scanners + path-traversal + rfi + rce + protocol
```

Individual presets: `'sqli' | 'xss' | 'scanners' | 'path-traversal' | 'rfi' | 'rce' | 'protocol' | 'default'`.

| Preset | Focus (CRS-derived) |
|--------|---------------------|
| `sqli` | REQUEST-942 |
| `xss` | REQUEST-941 (+ SSI) |
| `scanners` | REQUEST-913 / 912 (UA, DoS rate) |
| `path-traversal` | REQUEST-930 (LFI / traversal) |
| `rfi` | REQUEST-931 (+ PHP RCE / upload) |
| `rce` | REQUEST-932 / 934 (shell, SSTI, SSRF metadata) |
| `protocol` | REQUEST-920 / 921 / 943 |

Each preset rule already has a `minLevel`; your config `level` decides which ones run.

Only what you need:

```ts
expressWaf({
  level: 'balanced',
  presets: ['sqli', 'xss', 'scanners'],
});
```

### Enable / disable rules by id

After presets and custom rules are merged, the engine builds the active list in this order:

1. Resolve presets + custom `rules`
2. Filter by protection `level` (`minLevel`)
3. Apply `enabledRuleIds` (if present and **non-empty** — allowlist)
4. Apply `disabledRuleIds`
5. Drop `enabled: false` and sort by `priority`

```ts
expressWaf({
  presets: ['default'],
  level: 'balanced',
  // Turn off one noisy preset rule:
  disabledRuleIds: ['preset-scanners-ua'],
  // Or keep only a short allowlist (presets + custom):
  // enabledRuleIds: ['preset-sqli-classic-query', 'allow-health'],
  rules: [
    {
      id: 'allow-health',
      priority: 1,
      action: 'allow',
      when: { field: 'path', equals: '/health' },
    },
  ],
});
```

Empty `enabledRuleIds` / `disabledRuleIds` are no-ops.

### Logging (off by default)

Logging is **disabled by default** so production paths do no console I/O and no formatting. When off, the engine never calls the logger.

| Setting | Behavior |
|---------|----------|
| omitted / `false` | Silent (default) |
| `true` | Plain console at level `info` (blocks + audit) |
| `{ level, sink? }` | `error` = blocks only; `info` = blocks + audit; `debug` = + connections. Optional injectable `WafLogger` |

No color libraries — console output is plain text. File sinks are not built-in; pass a custom `sink` if you need them.

```ts
import type { WafLogger } from 'mini-waf';

const sink: WafLogger = {
  blocked: (ctx, rule) => myMetrics.inc('waf_block', { rule: rule.id }),
  audit: () => undefined,
  connection: () => undefined,
};

expressWaf({
  presets: ['default'],
  logging: true,
  // or: logging: { level: 'debug', sink },
});
```

You can also pass `{ logger }` in the second argument to `createMiniWaf` / `expressWaf` — it is used only when `logging` is enabled.

---

## Custom rules

```ts
import type { WafRule } from 'mini-waf';

const rules: WafRule[] = [
  {
    id: 'block-sqli-query',
    when: { field: 'query.id', matches: /('|OR\s+1=1)/i },
    action: 'block',
    reason: 'Possible SQL injection',
  },
  {
    id: 'rate-limit-ip',
    when: { field: 'ip', rateLimit: { max: 100, windowMs: 60_000 } },
    action: 'block',
    reason: 'Too many requests',
  },
  {
    id: 'allow-health',
    priority: 1, // lower = first; allow ends evaluation
    when: { field: 'path', equals: '/health' },
    action: 'allow',
  },
];
```

### Fields (`when.field`)

| Field | Description |
|-------|-------------|
| `ip`, `method`, `path`, `url`, `body`, `files` | simple values |
| `query`, `headers`, `cookies` | all values (OR) |
| `query.*`, `headers.*`, `cookies.*` | specific field |

### Matchers

- `matches`: `string` \| `RegExp` \| `readonly string[]`
- `equals`: exact equality
- `includes`: case-insensitive substring
- `rateLimit: { max, windowMs, keyPrefix? }`
- Compounds: `{ all: [...] }`, `{ anyOf: [...] }`, `{ not: ... }`

### Actions

- `allow` — allow and stop evaluation (whitelist)
- `block` — block (`blockStatusCode` / `blockBody`, default 403 + `Forbidden`)
- `log` — collect for audit (emitted only when logging is on at `info`+)

### JSON / serializable rules

`RegExp` and function predicates are not JSON-friendly. Use the serializable DSL (`JsonWafRule`) and compile with `parseRulesFromJson` / `loadRules`, then pass the result as `rules`:

```ts
import { parseRulesFromJson, createMiniWaf } from 'mini-waf';
import { readFileSync } from 'node:fs';

const rules = parseRulesFromJson(readFileSync('./rules.json', 'utf8'));
const waf = createMiniWaf({ presets: ['default'], rules });
```

`matches` in JSON:

| Shape | Meaning |
|-------|---------|
| `"exact"` | exact string equality (same as live `WafRule`) |
| `["a", "b"]` | OR list of exact strings |
| `{ "pattern": "...", "flags": "i" }` | compiled to `RegExp` |

Top-level input may be a rule array or `{ "rules": [ ... ] }`. Invalid shapes throw `RuleParseError` with a JSON path.

See `examples/rules.example.json`. The DSL is **inspired by** practical CRS categories / field targeting (e.g. SQLi ≈ REQUEST-942 on `query`/`body`) — it is **not** a ModSecurity / full OWASP CRS parser.

### Real case: admin path + User-Agent

```ts
import express from 'express';
import { expressWaf } from 'mini-waf/express';

const app = express();
app.use(express.json());

app.use(
  expressWaf({
    presets: ['default'],
    level: 'balanced',
    rules: [
      {
        id: 'block-admin-surface',
        action: 'block',
        reason: 'Admin path blocked at edge',
        when: {
          anyOf: [
            { field: 'path', equals: '/admin' },
            { field: 'path', matches: /^\/admin\// },
          ],
        },
      },
      {
        id: 'block-bad-ua',
        action: 'block',
        reason: 'Known scanner UA',
        when: {
          field: 'headers.user-agent',
          matches: /sqlmap|nikto|acunetix/i,
        },
      },
      {
        id: 'allow-health',
        priority: 1,
        action: 'allow',
        when: { field: 'path', equals: '/health' },
      },
    ],
  }),
);

app.get('/api/items', (_req, res) => res.json([]));
app.listen(3000);
```

The same `rules` / `presets` / `level` work with Fastify (`config`) and Nest (`MiniWafModule.forRoot({ config })`).

---

## Custom adapter (advanced)

For frameworks without a built-in integration, use `createAdapter` + `createMiniWaf`:

```ts
import { createAdapter, createMiniWaf } from 'mini-waf';

interface KoaCtx {
  method: string;
  url: string;
  ip: string;
  headers: Record<string, string>;
  query: Record<string, string>;
  request: { rawBody?: string };
  status: number;
  body: string;
  get(name: string): string | undefined;
  set(name: string, value: string): void;
}

const koaAdapter = createAdapter<KoaCtx, KoaCtx>({
  name: 'koa',
  getMethod: (ctx) => ctx.method,
  getUrl: (ctx) => ctx.url,
  getIp: (ctx) => ctx.ip,
  getHeader: (ctx, name) => ctx.get(name),
  getHeaders: (ctx) => ctx.headers,
  getQuery: (ctx) => ctx.query,
  getRawBody: (ctx) => ctx.request.rawBody ?? '',
  setResponseHeader: (ctx, name, value) => ctx.set(name, String(value)),
  drop: (ctx, _res, status, body) => {
    ctx.status = status;
    ctx.body = body;
  },
});

const waf = createMiniWaf({ presets: ['default'], level: 'balanced' });

// in middleware:
const result = await waf.protect(koaAdapter, ctx, ctx);
if (result.decision === 'allow') await next();
```

---

## Troubleshooting

| Symptom | Common cause | What to do |
|---------|--------------|------------|
| Unexpected blocks / many FPs | `level` too high (`high` / `paranoid`) | Drop to `balanced` or `low`; narrow `presets`; use `disabledRuleIds` or `allow` with low `priority` for legitimate routes |
| Body rule never fires | WAF before body parser (or no parser) | Express: `express.json()` / `urlencoded` **before** the WAF; Fastify: rely on the built-in parser and register the plugin before routes; Nest: apply middleware after the platform's default setup |
| Query/headers OK, body "empty" in WAF | `req.body` not populated yet | Check middleware order; in a custom adapter, `getRawBody` must read the already-parsed or raw payload |
| Health route blocked | Broad preset/scanner rule | Whitelist: `{ id: 'allow-health', priority: 1, action: 'allow', when: { field: 'path', equals: '/health' } }` |
| Nest does not block / allow | Middleware not applied | `consumer.apply(MiniWafMiddleware).forRoutes('*')` in `NestModule` |

---

## Development

```bash
npm install
npm run build
npm test
```

## License

MIT
