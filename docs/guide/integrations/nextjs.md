# Next.js

**Import:** `mini-waf` + `mini-waf/adapters` · **Peer:** none

```bash
npm install mini-waf
```

Next.js route handlers are web-standard: they receive a `Request` and return a
`Response`. The adapter therefore records the block instead of writing it, and
a small `withWaf` wrapper turns that into the response.

::: danger Not in `middleware.ts`
Next.js middleware runs on the **Edge runtime**, which has no `node:net`,
`node:buffer` or `setImmediate` — all of which Mini-WAF uses. Importing it
there fails at runtime with `Native module not found: node:net`.

Protect **route handlers** with `runtime = 'nodejs'` instead. Next.js 16 has
deprecated the Edge runtime in favour of `nodejs`, so this is also where the
framework is heading.
:::

## The shared wrapper

```ts
// lib/waf.ts
import { createAdapter, createMiniWaf } from 'mini-waf';

const waf = createMiniWaf({ presets: ['default'], level: 'balanced' });

type WafBlock = { readonly status: number; readonly body: string };
const blocks = new WeakMap<Request, WafBlock>();

const adapter = createAdapter({
  name: 'next',
  getMethod: (req: Request) => req.method,
  getUrl: (req: Request) => new URL(req.url).pathname + new URL(req.url).search,
  getPath: (req: Request) => new URL(req.url).pathname,
  getIp: (req: Request) =>
    req.headers.get('x-forwarded-for')?.split(',')[0].trim() ??
    req.headers.get('x-real-ip') ??
    '127.0.0.1',
  getHeader: (req: Request, name: string) => req.headers.get(name) ?? undefined,
  getHeaders: (req: Request) => Object.fromEntries(req.headers),
  getQuery: (req: Request) => Object.fromEntries(new URL(req.url).searchParams),
  // Reading a body consumes it — clone so the handler can still read it.
  getRawBody: async (req: Request) =>
    req.method === 'GET' || req.method === 'HEAD'
      ? ''
      : await req.clone().text(),
  setResponseHeader: () => {},
  drop: (req: Request, _res: unknown, status: number, body: string) => {
    blocks.set(req, { status, body });
  },
});

/** Wrap a route handler so the WAF runs before it. */
export function withWaf<C>(
  handler: (request: Request, context: C) => Promise<Response> | Response,
) {
  return async (request: Request, context: C): Promise<Response> => {
    const result = await waf.protect(adapter, request, request);
    if (result.decision === 'block') {
      const blocked = blocks.get(request) ?? { status: 403, body: 'Forbidden' };
      return new Response(blocked.body, { status: blocked.status });
    }
    return handler(request, context);
  };
}
```

## Using it in a route handler

```ts
// app/api/search/route.ts
import { withWaf } from '@/lib/waf';

// Required: the WAF needs Node built-ins.
export const runtime = 'nodejs';

export const GET = withWaf(async (request) => {
  const q = new URL(request.url).searchParams.get('q');
  return Response.json({ q });
});

export const POST = withWaf(async (request) => {
  const body = await request.json().catch(() => null);
  return Response.json({ body });
});
```

Wrap each exported method you want protected. A handler you do not wrap is not
scanned.

::: tip One engine, not one per request
`createMiniWaf` is called once at module scope. Next caches modules across
requests, so the rule list is compiled once rather than on every call — which
matters, since building it is the expensive part.
:::

## Client IP on Vercel

`x-forwarded-for` is set by Vercel's edge network and is trustworthy there. On
a self-hosted deployment behind your own proxy, make sure that proxy overwrites
the header rather than appending to it — otherwise a client can spoof the first
hop and dodge per-IP rate limits.

## Pages Router

API routes under `pages/api` receive Node-style `req`/`res`, so they can reuse
the built-in Express adapter shape instead of this wrapper:

```ts
// pages/api/search.ts
import { createExpressAdapter } from 'mini-waf/adapters';
import { createMiniWaf } from 'mini-waf';
import type { NextApiRequest, NextApiResponse } from 'next';

const waf = createMiniWaf({ presets: ['default'], level: 'balanced' });
const adapter = createExpressAdapter();

export default async function handler(
  req: NextApiRequest,
  res: NextApiResponse,
) {
  const result = await waf.protect(adapter, req, res);
  if (result.decision === 'block') return; // the adapter already replied
  res.json({ q: req.query.q ?? null });
}
```

Next parses the JSON body before the handler runs, so body rules work here
without extra wiring, and `NextApiRequest`/`NextApiResponse` satisfy the
adapter's types directly — no casts needed.

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Native module not found: node:net` | Handler is on the Edge runtime | `export const runtime = 'nodejs'` |
| Handler receives an empty body | The WAF consumed the stream | Read through `request.clone()` |
| A route is never scanned | Its handler is not wrapped | Wrap every exported method |
| Rules seem stale after editing | The module was cached | Restart the dev server |

## Verified behaviour

Run against `next dev` (Next.js 16, App Router, `runtime = 'nodejs'`); every
case below is the observed status:

| Request | Status |
|---------|--------|
| `GET /api/search?q=shoes` | `200` |
| `GET /api/search?q=1' OR 1=1` | `403` |
| `GET /api/search?q=<script>alert(1)</script>` | `403` |
| `GET /api/search` with `User-Agent: sqlmap/1.7` | `403` |
| `GET /api/search` with `User-Agent: ${jndi:ldap://…}` | `403` |
| `POST /api/search` with `{"m":"1 OR 1=1"}` | `403` |
| `POST /api/search` with `{"m":"hello"}` | `200` |
| Same wrapper with `runtime = 'edge'` | `500` — `node:net` unavailable |

And the Pages Router handler above, on the same server:

| Request | Status |
|---------|--------|
| `GET /api/legacy?q=shoes` | `200` |
| `GET /api/legacy?q=1' OR 1=1` | `403` |
| `GET /api/legacy?q=<script>alert(1)</script>` | `403` |
| `GET /api/legacy` with `User-Agent: sqlmap/1.7` | `403` |
| `POST /api/legacy` with `{"m":"1 OR 1=1"}` | `403` |
| `POST /api/legacy` with `{"m":"hi"}` | `200` |
