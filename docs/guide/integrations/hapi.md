# Hapi

**Import:** `mini-waf` + `mini-waf/adapters` · **Peer:** none

```bash
npm install mini-waf @hapi/hapi
```

Hapi is wired through [`createAdapter`](/guide/integrations/custom-adapters)
and a server extension. Two Hapi specifics shape the integration: the request
lifecycle decides whether the payload is available, and interrupting a request
requires `takeover()`.

## Minimal setup

```ts
import Hapi from '@hapi/hapi';
import { createAdapter, createMiniWaf } from 'mini-waf';

const waf = createMiniWaf({ presets: ['default'], level: 'balanced' });

// Hapi has no mutable response object during an extension, so the block is
// recorded here and turned into a response below.
const blocks = new WeakMap();

const hapiAdapter = createAdapter({
  name: 'hapi',
  getMethod: (request) => request.method.toUpperCase(),
  getUrl: (request) => request.url.pathname + request.url.search,
  getPath: (request) => request.url.pathname,
  getIp: (request) => request.info.remoteAddress,
  getHeader: (request, name) => request.headers[name.toLowerCase()],
  getHeaders: (request) => request.headers,
  getQuery: (request) => request.query,
  getRawBody: (request) => request.payload ?? '',
  setResponseHeader: () => {},
  drop: (request, _res, status, body) => {
    blocks.set(request, { status, body });
  },
});

const server = Hapi.server({ port: 3000, host: '127.0.0.1' });

// onPostAuth runs after the payload is parsed, so body rules can fire.
server.ext('onPostAuth', async (request, h) => {
  const result = await waf.protect(hapiAdapter, request, request);
  if (result.decision === 'block') {
    const blocked = blocks.get(request) ?? { status: 403, body: 'Forbidden' };
    return h.response(blocked.body).code(blocked.status).takeover();
  }
  return h.continue;
});

server.route({
  method: 'GET',
  path: '/search',
  handler: (request) => ({ q: request.query.q ?? null }),
});

await server.start();
```

## Pick the right lifecycle point

Hapi parses the payload partway through its request lifecycle, so the
extension point decides whether body rules can work at all:

| Extension | `request.payload` | Use it? |
|-----------|-------------------|---------|
| `onRequest` | **not parsed yet** | Only if you never inspect the body |
| `onPreAuth` | not parsed yet | No |
| `onPostAuth` | **parsed** | **Yes — the default choice** |
| `onPreHandler` | parsed | Also fine; runs later, after validation |

`onPostAuth` is the earliest point where the full request is visible, which is
what you want from a WAF: as early as possible, but not before the body exists.

::: tip Running before authentication
If you want the WAF to run before auth — so probes never reach your auth code —
use `onRequest` and accept that `body`-scoped rules will not fire, or run two
extensions: `onRequest` with a query/header-only config, and `onPostAuth` with
the full preset.
:::

## `takeover()` is what stops the request

Returning a response from a Hapi extension is not enough on its own — without
`.takeover()` the lifecycle continues to your handler. The three parts matter
together:

```ts
return h.response(blocked.body)   // the body
  .code(blocked.status)           // the status (403 by default)
  .takeover();                    // stop the lifecycle here
```

On `allow`, return `h.continue` so the request proceeds normally.

## Client IP

`request.info.remoteAddress` is the socket address. Behind a proxy, read the
forwarded header instead — and only when you control that proxy:

```ts
getIp: (request) =>
  request.headers['x-forwarded-for']?.split(',')[0].trim() ??
  request.info.remoteAddress,
```

## Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Handler still runs on a block | Missing `.takeover()` | Chain it after `.code()` |
| Body rules never fire | Extension is `onRequest`/`onPreAuth` | Move to `onPostAuth` |
| Every client shares one rate-limit bucket | Behind a proxy using the socket address | Read `x-forwarded-for` |
| `Cannot read properties of undefined` in `getQuery` | Extension runs before routing | `request.query` is available from `onPostAuth` |

## Verified behaviour

This example was run against a live server; every case below is the observed
status:

| Request | Status |
|---------|--------|
| `GET /search?q=shoes` | `200` |
| `GET /search?q=1' OR 1=1` | `403` |
| `GET /search?q=<script>alert(1)</script>` | `403` |
| `GET /files/%2e%2e%2f%2e%2e%2fetc/passwd` | `403` |
| `GET /` with `User-Agent: sqlmap/1.7` | `403` |
| `GET /` with `User-Agent: ${jndi:ldap://…}` | `403` |
| `POST /echo` with `{"m":"1 OR 1=1"}` | `403` |
| `POST /echo` with `{"m":"hello"}` | `200` |
