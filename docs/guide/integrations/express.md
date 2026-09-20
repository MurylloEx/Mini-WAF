# Express

**Import:** `mini-waf/express` · **Peer:** `express >= 4`

```bash
npm install mini-waf express
```

## Minimal setup

```ts
import express from 'express';
import { expressWaf } from 'mini-waf/express';

const app = express();

// 1) parsers
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 2) WAF
app.use(expressWaf({ presets: ['default'], level: 'balanced' }));

// 3) routes
app.get('/health', (_req, res) => res.send('ok'));
app.listen(3000);
```

## Middleware order

**`parser → WAF → routes`.** `field: 'body'` is read from `req.body` /
`req.rawBody`. With no parser ahead of the WAF, the field resolver sees an empty
string and body-scoped rules (the SQLi/XSS body rules, any custom
`field: 'body'` rule) never fire. This is missing input, not a bug.

## Query parser

Express 5 defaults to the `simple` query parser, which keeps bracketed
parameters in the **key**: `?user[$ne]=null` becomes `{ 'user[$ne]': 'null' }`.
Rules only scan parameter *values*, so that payload is invisible.

```ts
// Express 5: opt back into nested objects so the WAF can see inside them.
// (Express 4 already does this by default.)
app.set('query parser', 'extended');
```

With `extended`, the same request arrives as `{ user: { $ne: 'null' } }`, which
the engine flattens to `$ne=null` and `preset-sqli-nosql-operator` catches. See
[Security notes](/guide/security) for the full list of coverage limits.

## How the adapter maps a request

`expressWaf(config, options?)` returns standard `(req, res, next)` middleware.
It calls `runWithAdapter(waf, createExpressAdapter(), req, res, next)`, which
builds a `WafHttpContext` and runs `engine.handle(ctx)`. On `allow` **and**
`!ctx.isBlocked()` it calls `next()`; on `block` the adapter's `drop()` has
already ended the response, so `next()` is skipped.

```ts
// src/adapters/express.adapter.ts (excerpt)
const ip = resolveIp(req); // req.ip → X-Forwarded-For first hop → socket.remoteAddress
const url = req.originalUrl || req.url || '/';
const path = url.match(/^[^?]*/)?.[0] || '/';
const getRawBody = lazyBodyToString(() => req.rawBody ?? req.body);
```

Two details worth internalizing:

- **`getRawBody` is lazy.** `JSON.stringify`-ing an already-parsed body happens
  only the first time a rule resolves `field: 'body'`, then it is memoized.
  Clean requests that never trigger a body rule pay nothing extra.
- **`path` is not decoded.** It is the raw on-the-wire path, which is why
  `preset-path-traversal-encoded` exists to catch `%2e%2e%2f`.
- **IP resolution order:** `req.ip` (when the app trusts a proxy) → first hop of
  `X-Forwarded-For` → `req.connection.remoteAddress` /
  `req.socket.remoteAddress`. All go through `normalizeClientIp`, so rate-limit
  buckets and `field: 'ip'` rules see one canonical form.

Behind a proxy or load balancer, set `app.set('trust proxy', true)` so `req.ip`
is the real client and per-IP rate limits do not collapse onto the proxy.

## Optional security headers

```ts
import { expressSecurityPolicy } from 'mini-waf/express';

app.use(expressSecurityPolicy());
```

Sets `X-Frame-Options: sameorigin`, `X-XSS-Protection: 1`,
`X-Content-Type-Options: nosniff`, removes `X-Powered-By` / `Server`, and
mirrors `Origin` into `Access-Control-Allow-Origin` (plus full preflight headers
on `OPTIONS`). It is independent of the WAF decision — apply it separately.

## Production-shaped example

```ts
import express, { type Request, type Response, type NextFunction } from 'express';
import { expressWaf, expressSecurityPolicy } from 'mini-waf/express';
import type { WafConfig } from 'mini-waf';

const app = express();

// Behind a load balancer: makes req.ip the real client address.
app.set('trust proxy', true);
// Express 5: nested query objects so bracketed params are inspectable.
app.set('query parser', 'extended');

// --- 1) Body parsers first --------------------------------------------
// Without this, `body`-scoped rules always see an empty string.
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// --- 2) Optional hardened response headers -----------------------------
app.use(expressSecurityPolicy());

// --- 3) WAF config -------------------------------------------------------
const wafConfig: WafConfig = {
  // 'default' = scanners + protocol + sqli + xss + path-traversal + rfi + rce
  presets: ['default'],
  // Only rules whose `minLevel` is <= 'balanced' run (low < balanced < high < paranoid).
  level: 'balanced',
  rules: [
    {
      // Whitelist health checks *before* any preset can match. `priority: 1`
      // runs it first; `action: 'allow'` short-circuits the scan, so a load
      // balancer's GET /health never risks a false positive.
      id: 'allow-health',
      priority: 1,
      action: 'allow',
      when: { field: 'path', equals: '/health' },
    },
    {
      // Compound AND: an admin surface reached without a session cookie —
      // i.e. an unauthenticated probe, not a logged-in operator.
      id: 'block-unauthenticated-admin-probe',
      action: 'block',
      reason: 'Unauthenticated request to an admin surface',
      when: {
        all: [
          { field: 'path', matches: /^\/admin(\/|$)/ },
          { not: { field: 'cookies.session', matches: /^.+$/ } },
        ],
      },
    },
  ],
  // Logging is off unless you opt in — see the Logging guide.
  logging: { level: 'info' },
  // Truncate scanned field values before matching (bounds regex cost).
  maxFieldLength: 8_192,
};

app.use(expressWaf(wafConfig));

// --- 4) Routes ------------------------------------------------------------
app.get('/health', (_req: Request, res: Response) => {
  res.json({ status: 'ok' });
});

app.get('/search', (req: Request, res: Response) => {
  // Legitimate query strings pass through untouched — the WAF never
  // rewrites or sanitizes input, it only allows or blocks.
  res.json({ query: req.query.q ?? null });
});

app.post('/orders', (req: Request, res: Response) => {
  // A payload like {"q":"' OR 1=1 --"} would have been blocked upstream by
  // `preset-sqli-classic-body` before reaching this handler.
  res.status(201).json({ id: 'order_123', ...req.body });
});

// --- 5) Error handling -----------------------------------------------------
// The WAF forwards adapter/body errors via `next(err)`; keep a generic
// handler last so those never crash the process.
app.use((err: Error, _req: Request, res: Response, _next: NextFunction) => {
  console.error('unhandled error', err);
  res.status(500).json({ error: 'internal_error' });
});

app.listen(3000, () => {
  console.log('listening on http://localhost:3000');
});
```

## Protecting only some routes

`expressWaf` is ordinary middleware, so mount it on a path or router:

```ts
// Stricter policy on the admin surface only.
app.use('/admin', expressWaf({ presets: ['default'], level: 'high' }));
```

Each call builds its own engine. If both engines use `rateLimit` rules and you
want one shared per-IP budget, pass the same `rateLimitStore` to both — see
[Performance](/guide/performance).

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Body rules never fire | WAF before `express.json()` | Move the parser above `expressWaf` |
| Every client shares one rate-limit bucket | Running behind a proxy without `trust proxy` | `app.set('trust proxy', true)` |
| `?a[b]=c` payloads not detected | Express 5 `simple` query parser | `app.set('query parser', 'extended')` |
| 500 instead of 403 | An error handler swallowed the block, or the WAF is mounted after the route | Keep the error handler last and the WAF above routes |

## Runnable sample

`integration/express/server.mjs` in the repository boots a real server used by
the [integration scenarios](/guide/integrations/testing).
