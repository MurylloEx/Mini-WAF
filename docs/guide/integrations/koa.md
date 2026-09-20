# Koa

**Import:** `mini-waf` + `mini-waf/adapters` · **Peer:** none

```bash
npm install mini-waf koa @koa/router koa-bodyparser
```

Koa has no dedicated entrypoint — it is wired through
[`createAdapter`](/guide/integrations/custom-adapters), which is the supported
path for any framework without a built-in integration. The code below is taken
from `integration/koa/server.mjs`, which runs in the project's integration
suite on every change.

## Minimal setup

```ts
import Koa from 'koa';
import bodyParser from 'koa-bodyparser';
import { createAdapter, createMiniWaf } from 'mini-waf';

const waf = createMiniWaf({ presets: ['default'], level: 'balanced' });

const koaAdapter = createAdapter({
  name: 'koa',
  getMethod: (ctx) => ctx.method,
  getUrl: (ctx) => ctx.url,
  getPath: (ctx) => ctx.path,
  getIp: (ctx) => ctx.ip,
  getHeader: (ctx, name) => ctx.get(name) || undefined,
  getHeaders: (ctx) => ctx.headers,
  getQuery: (ctx) => ctx.query,
  getRawBody: (ctx) => ctx.request.body ?? '',
  setResponseHeader: (ctx, name, value) => ctx.set(name, String(value)),
  drop: (ctx, _res, status, body) => {
    ctx.status = status;
    ctx.body = body;
  },
});

const app = new Koa();

// Body parser MUST run before the WAF so body rules can fire.
app.use(bodyParser({ enableTypes: ['json', 'form'] }));

app.use(async (ctx, next) => {
  const result = await waf.protect(koaAdapter, ctx, ctx);
  if (result.decision === 'allow') {
    await next();
  }
});

app.listen(3000);
```

Koa passes a single `ctx` for both request and response, so it is handed to
`protect` twice — once as the request, once as the response.

The middleware only calls `next()` on `allow`. On a block, `drop` already set
`ctx.status` and `ctx.body`, and skipping `next()` is what stops the request
from reaching your routes.

::: tip Proxies
Set `app.proxy = true` when running behind a load balancer so `ctx.ip` is the
real client rather than the proxy — otherwise every request shares one
rate-limit bucket.
:::

## Production-shaped example

```ts
import Koa from 'koa';
import Router from '@koa/router';
import bodyParser from 'koa-bodyparser';
import { createAdapter, createMiniWaf } from 'mini-waf';
import type { WafHttpContext } from 'mini-waf';

const waf = createMiniWaf({
  presets: ['default'],
  level: 'balanced',
  logging: { level: 'info' },
});

// Koa's `ctx` object plays double duty as both "request" and "response" in
// this codebase's terms, so both type parameters of createAdapter<TRequest, TResponse>
// resolve to the same Koa Context type.
const koaAdapter = createAdapter({
  name: 'koa',

  // Method / URL: Koa exposes these directly on ctx, mirroring the raw Node
  // IncomingMessage values (no normalization needed on Koa's side).
  getMethod: (ctx) => ctx.method,
  getUrl: (ctx) => ctx.url,

  // `ctx.path` is Koa's already-decoded, query-string-free pathname — cheaper
  // and more correct than deriving it from `ctx.url` ourselves, so we supply
  // the optional `getPath` handler instead of relying on createAdapter's
  // regex fallback (`url.match(/^[^?]*/)`).
  getPath: (ctx) => ctx.path,

  // `ctx.ip` already resolves X-Forwarded-For when Koa's `app.proxy = true`
  // is set; createAdapter still runs it through normalizeClientIp for
  // IPv4-mapped IPv6 collapsing and rate-limit-key canonicalization.
  getIp: (ctx) => ctx.ip,

  // `ctx.get(name)` is Koa's case-insensitive single-header getter. It
  // returns '' (not undefined) when absent, so coerce to `undefined` —
  // WafHttpContext.getHeader must distinguish "missing" from "empty string"
  // for correctness of `headers.*` field conditions.
  getHeader: (ctx, name) => ctx.get(name) || undefined,

  // Full header bag for `field: 'headers'` (OR-across-all-values rules) and
  // for cookie-header fallback parsing inside createAdapter.
  getHeaders: (ctx) => ctx.headers,

  // Parsed query object for `field: 'query'` / `field: 'query.<key>'`.
  getQuery: (ctx) => ctx.query,

  // koa-bodyparser stashes the parsed body on `ctx.request.body`. This MUST
  // run after the bodyParser middleware (see app.use order below) or every
  // body-scoped rule (SQLi/XSS presets, custom `field: 'body'` rules) sees
  // an empty string and never fires — a coverage gap, not a crash.
  getRawBody: (ctx) => ctx.request.body ?? '',

  // How the WAF's decision translates back into a Koa response: Koa uses
  // `ctx.status` / `ctx.body` assignment rather than an explicit `res.end()`
  // call, so `drop` just sets both. The engine passes the rule's configured
  // `blockStatusCode` (default 403) and `blockBody` (default 'Forbidden').
  setResponseHeader: (ctx, name, value) => ctx.set(name, String(value)),
  drop: (ctx, _res, status, body) => {
    ctx.status = status;
    ctx.body = body;
  },
});

const app = new Koa();
const router = new Router();

// Body parser MUST run before the WAF so body rules can fire (same ordering
// requirement as Express — see Installation → Middleware order).
app.use(bodyParser({ enableTypes: ['json', 'form'] }));

app.use(async (ctx, next) => {
  const result = await waf.protect(koaAdapter, ctx, ctx);
  // `result.decision === 'block'` means `drop()` already set ctx.status/body;
  // calling `next()` anyway would let downstream middleware overwrite them,
  // so only continue the chain on `allow`.
  if (result.decision === 'allow') {
    await next();
  }
  // Optional: inspect `result.loggedRules` here to forward audit events to
  // your own metrics/telemetry, independent of the built-in logging sink.
});

router.get('/', (ctx) => {
  ctx.body = { app: 'koa', ok: true };
});

router.get('/health', (ctx) => {
  ctx.body = { status: 'ok' };
});

router.get('/search', (ctx) => {
  ctx.body = { q: ctx.query.q ?? null };
});

router.post('/echo', (ctx) => {
  ctx.body = { body: ctx.request.body };
});

app.use(router.routes());
app.use(router.allowedMethods());

app.listen(3104, '127.0.0.1', () => {
  console.log('[koa] listening on http://127.0.0.1:3104');
});
```

## Why each field is mapped that way

| Context method | Koa source | Reasoning |
|---|---|---|
| `getMethod` | `ctx.method` | Same raw string Node exposes; no case normalization needed (`WafField: 'method'` rules typically use `equals`/`matches` against uppercase HTTP verbs). |
| `getPath` | `ctx.path` | Koa pre-strips the query string and decodes percent-escapes; avoids re-deriving it with a regex and gets consistent behavior with `path`-scoped presets like `preset-path-traversal`. |
| `getIp` | `ctx.ip` (→ `normalizeClientIp`) | Koa already understands `app.proxy` / `X-Forwarded-For`; the adapter layer only needs to canonicalize the *form* of the address, not re-derive which hop is "the" client. |
| `getHeader` | `ctx.get(name) \|\| undefined` | `WafHttpContext.getHeader` is used by `headers.<key>` field resolution (`src/engine/field-resolver.ts`); returning `''` instead of `undefined` would make `{ field: 'headers.x-api-key', matches: /.+/ }`-style presence checks behave incorrectly. |
| `getRawBody` | `ctx.request.body` | koa-bodyparser's output location; `bodyToString` (used internally by `createAdapter`) accepts the parsed JSON value directly and serializes it lazily. |
| `drop` | `ctx.status` / `ctx.body` assignment | Koa's response model is assignment-based rather than `res.end()`-based; mapping the WAF's abstract "end this request with a status + body" onto Koa's idiom is the entire job of a custom adapter. |

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Body rules never fire | `koa-bodyparser` registered after the WAF | Move the parser above the WAF middleware |
| Routes still run on a block | The middleware calls `next()` unconditionally | Only call `next()` when `result.decision === 'allow'` |
| Every client shares one rate-limit bucket | Behind a proxy without `app.proxy` | `app.proxy = true` |

## Runnable sample

`integration/koa/server.mjs` in the repository, exercised by the
[integration scenarios](/guide/integrations/testing) alongside Express, Fastify
and NestJS.
