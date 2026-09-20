# Hono

**Import:** `mini-waf` + `mini-waf/adapters` · **Peer:** none

```bash
npm install mini-waf hono @hono/node-server
```

Hono is the reference for a **web-standard** framework: the handler receives a
`Request` and *returns* a `Response`, with no mutable response object to end.
That changes one thing in the adapter — `drop` cannot write the response
itself, so it records the block and the middleware turns it into a `Response`.

::: warning Node only
Mini-WAF uses `node:net`, `node:buffer`, `node:perf_hooks` and `setImmediate`,
so it runs on Hono's **Node** adapter (`@hono/node-server`) and on Bun/Deno,
but **not** on Cloudflare Workers or other edge runtimes.
:::

## Minimal setup

```ts
import { serve } from '@hono/node-server';
import { Hono } from 'hono';
import { createAdapter, createMiniWaf } from 'mini-waf';

const waf = createMiniWaf({ presets: ['default'], level: 'balanced' });

const honoAdapter = createAdapter({
  name: 'hono',
  getMethod: (c) => c.req.method,
  getUrl: (c) => new URL(c.req.url).pathname + new URL(c.req.url).search,
  getPath: (c) => new URL(c.req.url).pathname,
  getIp: (c) =>
    c.req.header('x-forwarded-for')?.split(',')[0].trim() ?? '127.0.0.1',
  getHeader: (c, name) => c.req.header(name),
  getHeaders: (c) => c.req.header(),
  getQuery: (c) => c.req.query(),
  // The body is a stream, so read it here — `getRawBody` may be async.
  // `clone()` keeps it readable by your handler afterwards.
  getRawBody: async (c) => {
    if (c.req.method === 'GET' || c.req.method === 'HEAD') return '';
    return await c.req.raw.clone().text();
  },
  setResponseHeader: (c, name, value) => c.header(name, String(value)),
  // No response object to end: record the block, return it below.
  drop: (c, _res, status, body) => {
    c.set('wafBlock', { status, body });
  },
});

const app = new Hono();

app.use('*', async (c, next) => {
  const result = await waf.protect(honoAdapter, c, c);
  if (result.decision === 'block') {
    const blocked = c.get('wafBlock') ?? { status: 403, body: 'Forbidden' };
    return c.text(blocked.body, blocked.status);
  }
  await next();
});

app.get('/search', (c) => c.json({ q: c.req.query('q') ?? null }));

serve({ fetch: app.fetch, port: 3000 });
```

## The two things that differ from Express

**1. The body must be read, not looked up.** There is no body-parser
middleware populating `req.body`; the payload is a stream. `getRawBody` accepts
a `Promise`, so `await c.req.raw.clone().text()` is enough. The `clone()` is
what matters: reading a request body consumes it, and without the clone your
handler would receive an empty stream.

**2. Blocking returns instead of ending.** `drop` is synchronous and returns
nothing, which is all an Express-style adapter needs. Here it stores the status
and body on the Hono context, and the middleware converts that into a real
response — returning early, so `next()` never runs and downstream handlers are
skipped.

The same shape applies to any web-standard framework: Remix, SvelteKit, Nitro
route handlers, and [Next.js route handlers](/guide/integrations/nextjs).

## TypeScript

Type the context variable so `c.get('wafBlock')` is not `unknown`:

```ts
type WafBlock = { readonly status: number; readonly body: string };

const app = new Hono<{ Variables: { wafBlock?: WafBlock } }>();
```

## Client IP

`c.req.header('x-forwarded-for')` is only trustworthy behind a proxy you
control. When running `@hono/node-server` directly, take the address from the
connection info instead:

```ts
import { getConnInfo } from '@hono/node-server/conninfo';

getIp: (c) => getConnInfo(c).remote.address ?? '127.0.0.1',
```

Otherwise a client can spoof the header and dodge per-IP rate limits.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Handler receives an empty body | The WAF consumed the stream | Read through `c.req.raw.clone()`, not `c.req.raw` |
| Body rules never fire | `getRawBody` returns `''` for every method | Only short-circuit `GET`/`HEAD` |
| Blocks return 200 | The middleware awaited `next()` anyway | `return` the response instead of falling through |
| `node:net` not found | Running on an edge runtime | Use the Node/Bun/Deno adapter |

## Verified behaviour

This example was run against a live server; every case below is the observed
status:

| Request | Status |
|---------|--------|
| `GET /search?q=shoes` | `200` |
| `GET /search?q=1' OR 1=1` | `403` |
| `GET /search?q=<script>alert(1)</script>` | `403` |
| `GET /` with `User-Agent: sqlmap/1.7` | `403` |
| `GET /` with `User-Agent: ${jndi:ldap://…}` | `403` |
| `POST /echo` with `{"m":"1 OR 1=1"}` | `403` |
| `POST /echo` with `{"m":"hello"}` | `200` |
