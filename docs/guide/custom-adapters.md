# Custom adapters

For frameworks without a built-in integration, map your request/response onto the engine with `createAdapter` and call `createMiniWaf(...).protect(...)`.

## APIs

### `WafHttpContext`

Framework-agnostic HTTP view consumed by the engine: method, URL, path, IP, headers, query, cookies, body, files, plus `drop()` / `isBlocked()`.

### `WafAdapter<TRequest, TResponse, TNext>`

```ts
interface WafAdapter<TRequest, TResponse, TNext = void> {
  readonly name: string;
  createContext(
    request: TRequest,
    response: TResponse,
    next?: TNext,
  ): WafHttpContext | Promise<WafHttpContext>;
}
```

### `createAdapter(handlers)`

Supply typed mappers (`CustomAdapterHandlers`). Required handlers include `name`, `getMethod`, `getUrl`, `getIp`, `getHeader`, `getHeaders`, `getQuery`, `getRawBody`, `setResponseHeader`, and `drop`. Optional: `getPath`, `getProtocol`, `getLocalPort`, `getCookies`, `getFiles`, `removeResponseHeader`.

The factory normalizes IPs (`normalizeClientIp`), derives path from URL when needed, parses cookies from the `Cookie` header if you omit `getCookies`, and stringifies the body via `bodyToString`.

### `createMiniWaf(config).protect(adapter, request, response)`

Builds a `WafHttpContext` through the adapter and runs `engine.handle`. Returns `WafEvaluationResult` (`decision`, `matchedRule`, `reason`, `loggedRules`).

## Koa example

Taken from `integration/koa/server.mjs` (no built-in Koa package — this is the supported extension path):

```ts
import Koa from 'koa';
import bodyParser from 'koa-bodyparser';
import { createAdapter, createMiniWaf } from 'mini-waf';

const waf = createMiniWaf({
  presets: ['default'],
  level: 'balanced',
});

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
```

## Built-in adapter factories

Also exported from `mini-waf/adapters` (and the root package):

- `createExpressAdapter()`
- `createFastifyAdapter()`
- `createNestAdapter(platform?: 'express' | 'fastify' | 'auto')`

Prefer the framework entrypoints (`expressWaf`, etc.) unless you need to compose the engine yourself.

## Shared helper

`runWithAdapter(waf, adapter, request, response, next?)` is what the built-in integrations use: create context → `handle` → return `{ result, ctx }`.
