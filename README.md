<p align="center">
  <img src="./.github/assets/mini-waf-logo.png" alt="Mini-WAF — Web Application Firewall" width="420"/>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/mini-waf"><img src="https://badgen.net/npm/v/mini-waf" alt="npm version"/></a>
  <a href="https://www.npmjs.com/package/mini-waf"><img src="https://badgen.net/npm/dt/mini-waf" alt="npm downloads"/></a>
  <a href="https://www.npmjs.com/package/mini-waf"><img src="https://badgen.net/npm/license/mini-waf" alt="license"/></a>
  <a href="https://www.npmjs.com/package/mini-waf"><img src="https://badgen.net/npm/types/mini-waf" alt="types"/></a>
  <img src="https://badgen.net/badge/node/%3E=18/green" alt="node"/>
  <a href="https://github.com/MurylloEx"><img src="https://badgen.net/badge/author/MurylloEx/red?icon=label" alt="author"/></a>
  <a href="https://ko-fi.com/murylloex"><img src="https://badgen.net/badge/support/ko-fi/red" alt="support on Ko-fi"/></a>
</p>

# Mini WAF

Minimal Web Application Firewall for Node.js (**v1**). Plug it in as middleware/plugin and evaluate each request with typed presets and declarative rules.

Supports **Express**, **Fastify**, and **NestJS** (optional peers — install only the framework you use).

Ships **dual CommonJS + ESM** with per-condition types, so `require`, `import`, and every `moduleResolution` mode (`node10`, `node16`, `nodenext`, `bundler`) resolve — subpaths included. Tree-shakeable (`sideEffects: false`), zero runtime dependencies.

**Documentation:** [https://mini-waf.vercel.app/](https://mini-waf.vercel.app/)

| | |
|---|---|
| **Get running** | [Quick start](https://mini-waf.vercel.app/guide/quick-start) · [Express](https://mini-waf.vercel.app/guide/integrations/express) · [Fastify](https://mini-waf.vercel.app/guide/integrations/fastify) · [NestJS](https://mini-waf.vercel.app/guide/integrations/nestjs) · [Custom adapters](https://mini-waf.vercel.app/guide/integrations/custom-adapters) |
| **Understand it** | [Core concepts](https://mini-waf.vercel.app/guide/concepts) · [Conditions & matchers](https://mini-waf.vercel.app/guide/conditions) · [Protection levels](https://mini-waf.vercel.app/guide/protection-levels) |
| **Write rules** | [Presets](https://mini-waf.vercel.app/guide/presets) · [Custom rules](https://mini-waf.vercel.app/guide/custom-rules) · [JSON rules](https://mini-waf.vercel.app/guide/json-rules) |
| **Operate it** | [Logging](https://mini-waf.vercel.app/guide/logging) · [Performance](https://mini-waf.vercel.app/guide/performance) · [Benchmarking](https://mini-waf.vercel.app/guide/benchmarking) · [Security notes](https://mini-waf.vercel.app/guide/security) |

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

### Custom adapter

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

  // Performance (all optional)
  maxFieldLength?: number;     // truncate scanned field values; default 8192 (0 = unlimited)
  ruleYieldEvery?: number;     // yield to event loop every N rules; default 32 (0 = off)
  maxRateLimitKeys?: number;   // LRU cap on distinct rate-limit keys; default 10000
  decisionCache?: { max?: number; ttlMs?: number }; // short-TTL decision LRU; off by default
  decode?: { base64?: boolean; url?: boolean; comments?: boolean }; // decode whole-value Base64 (+ JSON body values), percent-encoding, and strip inline SQL comments, then rescan; auto-on at high+
}
```

### Performance knobs

| Option | Default | Purpose |
|--------|---------|---------|
| `maxFieldLength` | `8192` | Truncate each scanned field value (body, query, headers, …) **before** matching / regex. Limits regex cost on huge payloads without rejecting the HTTP body itself. Set `0` for unlimited (not recommended in production). |
| `ruleYieldEvery` | `32` | After every N rules, `handle` awaits `setImmediate` so large rule packs do not starve the event loop. Packs with fewer than N rules skip yielding (fully synchronous scan, still returns a `Promise`). Set `0` to always disable yielding. Safe together with `rateLimit` rules: counters live in a shared in-place store (no snapshot/replace race). |
| `maxRateLimitKeys` | `10000` | Cap on distinct rate-limit keys (usually per-IP buckets). Cold keys are evicted LRU-style when the cap is exceeded; idle keys are also pruned opportunistically. Bounds memory/CPU under IP floods even when `preset-dos-rate-limit` is active. |
| `decisionCache` | omitted (off) | Tiny LRU of allow/block decisions keyed by method + path + IP + query + UA + body hash. **Automatically disabled** when any active rule uses `rateLimit` so DoS counters still advance. Use only for mostly-static pattern rules; keep `max` / `ttlMs` small (defaults: 256 / 1000ms). |
| `decode` | auto-on at `high`+ | Three normalizers that rescan a decoded/de-obfuscated value with the existing rules: **base64** decodes a whole-value Base64 blob (padded or unpadded) — a query/cookie value, or a single JSON body value like `{"q":"<base64>"}`; **url** percent-decodes a value carrying a `%XX` escape, reaching payloads sent percent-encoded on surfaces the framework does not decode (URL path, multipart, raw bodies); **comments** strip inline SQL comments used as token separators (`SELECT/**/value/**/FROM`, the `space2comment` tamper), preserving versioned `/*!…*/`. A new false-positive axis, so all are **off at `low`/`balanced`** and add zero cost there; set `{ base64: false, url: false, comments: false }` to opt out at high+. Only Base64 values that survive a shape check **and** decode to mostly-printable text are rescanned, so tokens / UUIDs / image blobs are skipped. |

Normalized client IPs are also memoized in a process-local LRU (max 2048) — the same idea as geo/IP caches in lightweight WAF tutorials, without an external `lru-cache` dependency.

After the first matching `block`, later pure `block` rules (no `rateLimit` in their condition tree) are skipped. `allow`, `log`, and any rule with rate-limit side effects still run in order.

**Field bags vs specific fields:** Prefer `query.id` / `headers.user-agent` over bag fields (`query`, `headers`, `cookies`) when you know the target. Bags OR across every value and amplify matcher cost (especially regex and `includes`). Static `includes` needles are lowercased once at rule load; haystacks are memoized per request.

**Regex / CRS-like patterns:** Node has no sync RegExp timeout and no built-in RE2. Catastrophic backtracking on long strings is mitigated by `maxFieldLength` truncation before `matches`. Avoid nested quantifiers on attacker-controlled input (`(a+)+`, overlapping alternations on huge bodies). For hard guarantees, run matching in a worker with a wall-clock budget or use a linear-time engine outside this library.

### Levels (`level`)

Each rule (preset or custom) may declare `minLevel`. It only applies when the configured level is **greater than or equal** to that minimum:

`low` < `balanced` < `high` < `paranoid`

Custom rules **without** `minLevel` are treated as `low` (active at any level).

| Level | Rules (`default`) | Includes | Typical use | ≈ CRS PL |
|-------|-------------------|----------|-------------|----------|
| `low` | 19 | Obvious scanners (UA), classic SQLi + DBMS primitives, plain & encoded traversal / LFI, stream-wrapper RFI, PHP RCE, shell RCE, JNDI/Log4Shell, reverse shells, fetch-and-exec, Windows LOLBins, SSRF metadata | APIs sensitive to false positives | PL1 (core) |
| `balanced` (default) | 51 | `low` + XSS (incl. encoded tags, `data:` URIs, attribute vectors, path), SQLi tautologies & `SELECT … FROM`, NoSQL operators (quoted & unquoted), uploads & extension bypass, remote-URL RFI, SSTI, FreeMarker, Node/lang exec, deserialization (binary & YAML), null-byte, DoS rate-limit, protocol splitting/smuggling, encoded & double-encoded CRLF | General production | PL1–PL2 |
| `high` | 81 | `balanced` + SSI, hex flood, prototype pollution, advanced/blind/boolean-equality/compact-subquery/JSON SQLi, NoSQL driver API & `$where` timing DoS, LDAP filter & matching-rule, XXE, mail command / IMAP / QUIT injection, UNC paths, XSS JS primitives, indirect & breakout sink calls, CL+TE, shell `$()` and parameter-expansion tricks, session ID in URL | Under attack / broader coverage | PL2 |
| `paranoid` | 94 | `high` + broad UAs, generic HTML tags, empty UA, shebang, oversized headers, internal-host SSRF, GraphQL introspection, ASP concat obfuscation, NoSQL `$where` time-bomb, MSSQL `DECLARE`, cmd `set /a`, CRLF-less mail verbs | Max coverage; more FPs | PL3–PL4 |

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

| Preset | Rules | Focus (CRS-derived) |
|--------|-------|---------------------|
| `sqli` | 22 | REQUEST-942 — classic, tautology, DBMS primitives, blind, boolean equality, compact subquery, JSON functions, MSSQL `DECLARE`, NoSQL operators / driver API / `$where` DoS |
| `xss` | 14 | REQUEST-941 (+ SSI) — tags, encoded tags, `data:` URIs, attribute vectors, JS primitives, indirect & breakout sink calls |
| `scanners` | 12 | REQUEST-913 / 912 — scanner UAs, LDAP filter & matching-rule, GraphQL introspection, null-byte, pollution, hex flood, DoS rate |
| `path-traversal` | 5 | REQUEST-930 — plain and encoded traversal, UNC / admin-share paths, LFI |
| `rfi` | 7 | REQUEST-931 / 933 — stream wrappers, remote script include, PHP RCE, XXE, uploads |
| `rce` | 19 | REQUEST-932 / 934 — shell (incl. `set /a`), JNDI/Log4Shell, reverse shells, LOLBins, SSTI, FreeMarker, deserialization |
| `protocol` | 15 | REQUEST-920 / 921 / 943 — splitting, smuggling, CRLF, mail / IMAP / QUIT injection, header injection, CL+TE, Host IP, session |

The per-rule breakdown, with what each id catches, is in
[the presets guide](https://mini-waf.vercel.app/guide/presets).

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
| `query`, `headers`, `cookies` | all values (OR) — prefer dotted paths when possible |
| `query.*`, `headers.*`, `cookies.*` | specific field (cheaper than bags) |

### Matchers

- `matches`: `string` \| `RegExp` \| `readonly string[]` (runs on truncated field values when `maxFieldLength` > 0)
- `equals`: exact equality
- `includes`: case-insensitive substring (needle lowercased at rule load)
- `requires`: literal prefilter — see below
- `rateLimit: { max, windowMs, keyPrefix? }`
- Compounds: `{ all: [...] }`, `{ anyOf: [...] }`, `{ not: ... }`

#### `requires` — the literal prefilter

A value is only handed to `matches` when it contains one of these substrings
(case-insensitive). An `indexOf` scan is far cheaper than a regex pass over a
large body, and the lowercased view of each field is computed once per request
and shared by every rule, so this is how the presets keep a 94-rule pack cheap:

```ts
{
  id: 'block-jndi',
  action: 'block',
  reason: 'Log4Shell probe',
  when: {
    field: 'body',
    matches: /\$\{\s*(?:jndi|ctx|env|sys)\s*:/i,
    requires: ['${'], // every payload this regex can match contains "${"
  },
}
```

> **The list must be complete.** If a payload the pattern would match contains
> none of the literals, the rule silently misses it. Leave `requires` out when
> you are not sure, or when the pattern has no fixed literal (`/^\d+$/`).

It works in JSON rules too: `"requires": ["${"]`.

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

## Troubleshooting

| Symptom | Common cause | What to do |
|---------|--------------|------------|
| Unexpected blocks / many FPs | `level` too high (`high` / `paranoid`) | Drop to `balanced` or `low`; narrow `presets`; use `disabledRuleIds` or `allow` with low `priority` for legitimate routes |
| Body rule never fires | WAF before body parser (or no parser) | Express: `express.json()` / `urlencoded` **before** the WAF; Fastify: rely on the built-in parser and register the plugin before routes; Nest: apply middleware after the platform's default setup |
| Query/headers OK, body "empty" in WAF | `req.body` not populated yet | Check middleware order; in a custom adapter, `getRawBody` must read the already-parsed or raw payload |
| Health route blocked | Broad preset/scanner rule | Whitelist: `{ id: 'allow-health', priority: 1, action: 'allow', when: { field: 'path', equals: '/health' } }` |
| Nest does not block / allow | Middleware not applied | `consumer.apply(MiniWafMiddleware).forRoutes('*')` in `NestModule` |
| Requests carrying a remote URL get 403 | `preset-rfi-remote-url` fires on URLs ending in `.php`, `.txt`, `.jsp`… or a trailing `?` | `disabledRuleIds: ['preset-rfi-remote-url']`, or move the URL to the request body |
| A sort/report endpoint gets 403 at `high` | `preset-sqli-blind` (`ORDER BY 1`, `CASE WHEN`) | Stay on `balanced`, or `disabledRuleIds: ['preset-sqli-blind']` |
| `?user[$ne]=null` is not blocked | Query **names** are not scanned, and Express 5's default parser keeps the payload in the key | `app.set('query parser', 'extended')` so the nested object is flattened and inspected |
| Custom rule stopped matching | An incomplete `requires` list is filtering the value out before `matches` runs | Remove `requires`, or add every literal your pattern can match on |

---

## Development

```bash
npm install
npm run build
npm test
```

## Support the project

Mini-WAF is MIT-licensed and maintained in the open. If it protects something
you run in production, you can support its maintenance on
[Ko-fi](https://ko-fi.com/murylloex) — donations fund rule-set curation, the documentation site, and
the time that keeps both current.

## License

MIT
