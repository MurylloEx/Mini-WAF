# Custom adapters

For frameworks without a built-in integration — Koa, Hapi, a raw `node:http`
server, a serverless handler — map your request/response onto the engine with
`createAdapter` and call `createMiniWaf(...).protect(...)`.

This page walks through the full `WafHttpContext` / `WafAdapter` shape and a
complete Koa adapter, field by field. Everything the built-in
[Express](/guide/integrations/express), [Fastify](/guide/integrations/fastify)
and [NestJS](/guide/integrations/nestjs) integrations do, they do through this
same interface.

## APIs

### `WafHttpContext`

Framework-agnostic HTTP view consumed by the engine (`src/domain/context.ts`):

```ts
interface WafHttpContext {
  readonly framework: string;

  getMethod(): string;
  getUrl(): string;
  getPath(): string;
  getIp(): string;
  getProtocol(): string;
  getLocalPort(): number;

  getHeader(name: string): string | undefined;
  getHeaders(): HeaderMap;
  getQuery(): QueryMap;
  getCookies(): CookieMap;
  getRawBody(): string;
  getFiles(): readonly UploadedFile[];

  setResponseHeader(name: string, value: string | number): void;
  removeResponseHeader(name: string): void;

  isBlocked(): boolean;
  /** Ends the request with a block response (typically 403). */
  drop(statusCode?: number, body?: string): void;
}
```

Every rule field (`WafField` — `'ip' | 'method' | 'path' | 'url' | 'body' | 'files' | 'query' | 'headers' | 'cookies' | 'query.*' | 'headers.*' | 'cookies.*'`) is resolved by the engine's `field-resolver` **exclusively** through these getters — an adapter that returns the wrong value for `getIp()`, for example, silently breaks every `field: 'ip'` rule and rate-limit bucket, with no compile-time signal.

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

`createContext` runs **once per request**, before rule evaluation. It should be cheap and, where possible, defer expensive work (see `getRawBody` below) until a rule actually needs it.

### `createAdapter(handlers)`

Supply typed mappers (`CustomAdapterHandlers<TRequest, TResponse>`, `src/adapters/create-adapter.ts`):

```ts
interface CustomAdapterHandlers<TRequest, TResponse> {
  readonly name: string;
  readonly getMethod: (request: TRequest) => string;
  readonly getUrl: (request: TRequest) => string;
  readonly getPath?: (request: TRequest) => string;
  readonly getIp: (request: TRequest) => string;
  readonly getProtocol?: (request: TRequest) => string;
  readonly getLocalPort?: (request: TRequest, response: TResponse) => number;
  readonly getHeader: (request: TRequest, name: string) => string | undefined;
  readonly getHeaders: (request: TRequest) => HeaderMap;
  readonly getQuery: (request: TRequest) => QueryMap;
  readonly getCookies?: (request: TRequest) => CookieMap;
  readonly getRawBody: (
    request: TRequest,
  ) => string | Buffer | JsonValue | undefined | Promise<string | Buffer | JsonValue | undefined>;
  readonly getFiles?: (request: TRequest) => FilesBag | readonly UploadedFile[];
  readonly setResponseHeader: (response: TResponse, name: string, value: string | number) => void;
  readonly removeResponseHeader?: (response: TResponse, name: string) => void;
  readonly drop: (request: TRequest, response: TResponse, statusCode: number, body: string) => void;
}
```

Required handlers: `name`, `getMethod`, `getUrl`, `getIp`, `getHeader`, `getHeaders`, `getQuery`, `getRawBody`, `setResponseHeader`, `drop`. Optional: `getPath` (derived from `getUrl` via `url.match(/^[^?]*/)?.[0] || url` when omitted), `getProtocol` (defaults `'http'`), `getLocalPort` (defaults `0`), `getCookies` (derived from the `Cookie` header via `parseCookies` when omitted), `getFiles` (defaults to `[]`), `removeResponseHeader`.

What `createAdapter` does for you, beyond wiring the handlers:

- **IP normalization** — `getIp()` on the context always runs the raw value from your `handlers.getIp` through `normalizeClientIp` (dual-stack IPv4/IPv6 canonicalization, memoized in a small LRU). You should return the *rawest* address you have (e.g. `ctx.ip` from the framework); do not pre-normalize it yourself.
- **Lazy body stringification** — `getRawBody` is awaited once inside `createContext` and cached as a plain string for the rest of the request (`bodyToString`, handling `string | Buffer | JsonValue`). Unlike the Express/Fastify adapters, this one is *not* deferred past `createContext` — if your framework's raw body read is itself expensive/async, be mindful of doing it unconditionally.
- **`isBlocked()` / `drop()` bookkeeping** — the adapter tracks a local `blocked` flag flipped by `drop()`, so `isBlocked()` reflects reality regardless of what your `drop` handler does downstream.

### `createMiniWaf(config).protect(adapter, request, response)`

Builds a `WafHttpContext` through the adapter and runs `engine.handle`. Returns `WafEvaluationResult`:

```ts
interface WafEvaluationResult {
  readonly decision: 'allow' | 'block';
  readonly matchedRule: WafRule | undefined;
  readonly reason: string | undefined;
  readonly loggedRules: readonly WafRule[]; // rules with action: 'log' that matched
}
```

## Koa example (complete)

No built-in Koa package ships with `mini-waf` — this is the officially supported extension path, taken from `integration/koa/server.mjs` and expanded here with the reasoning behind each field mapping.

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

### Why each field is mapped that way

| Context method | Koa source | Reasoning |
|---|---|---|
| `getMethod` | `ctx.method` | Same raw string Node exposes; no case normalization needed (`WafField: 'method'` rules typically use `equals`/`matches` against uppercase HTTP verbs). |
| `getPath` | `ctx.path` | Koa pre-strips the query string and decodes percent-escapes; avoids re-deriving it with a regex and gets consistent behavior with `path`-scoped presets like `preset-path-traversal`. |
| `getIp` | `ctx.ip` (→ `normalizeClientIp`) | Koa already understands `app.proxy` / `X-Forwarded-For`; the adapter layer only needs to canonicalize the *form* of the address, not re-derive which hop is "the" client. |
| `getHeader` | `ctx.get(name) || undefined` | `WafHttpContext.getHeader` is used by `headers.<key>` field resolution (`src/engine/field-resolver.ts`); returning `''` instead of `undefined` would make `{ field: 'headers.x-api-key', matches: /.+/ }`-style presence checks behave incorrectly. |
| `getRawBody` | `ctx.request.body` | koa-bodyparser's output location; `bodyToString` (used internally by `createAdapter`) accepts the parsed JSON value directly and serializes it lazily. |
| `drop` | `ctx.status` / `ctx.body` assignment | Koa's response model is assignment-based rather than `res.end()`-based; mapping the WAF's abstract "end this request with a status + body" onto Koa's idiom is the entire job of a custom adapter. |

## Built-in adapter factories

Also exported from `mini-waf/adapters` (and the root package):

- `createAdapter(handlers)`
- `createExpressAdapter()`
- `createFastifyAdapter()`
- `createNestAdapter(platform?: 'express' | 'fastify' | 'auto')`

Prefer the framework entrypoints (`expressWaf`, `fastifyWaf`, `MiniWafModule`/`nestMiddleware`) unless you need to compose the engine yourself — they already wire the right adapter and the `runWithAdapter` helper described below.

## Shared helper

`runWithAdapter(waf, adapter, request, response, next?)` is what the built-in integrations use internally:

```ts
// src/adapters/create-adapter.ts (excerpt)
export async function runWithAdapter<TRequest, TResponse, TNext>(
  waf: WafEngine,
  adapter: WafAdapter<TRequest, TResponse, TNext>,
  request: TRequest,
  response: TResponse,
  next?: TNext,
): Promise<{ readonly result: WafEvaluationResult; readonly ctx: WafHttpContext }> {
  const ctx = await Promise.resolve(adapter.createContext(request, response, next));
  const result = await waf.handle(ctx);
  return { result, ctx };
}
```

Use it directly when you need both the raw `WafHttpContext` (e.g. to read `ctx.getIp()` for your own logging) and the `WafEvaluationResult` in the same call, instead of going through `.protect(...)` which only returns the result.

## Checklist before you ship it

A custom adapter is where integration bugs hide. Verify each of these against a
real server — [Testing your integration](/guide/integrations/testing) has a
runnable harness, and the repository's `integration/koa/` app is a working
reference:

| Check | Why |
|-------|-----|
| `getRawBody()` returns the parsed payload | Otherwise every body rule silently passes |
| `drop()` actually ends the response | Otherwise a "blocked" request still reaches your handler |
| `isBlocked()` reflects `drop()` | The engine uses it to decide whether to continue |
| `getIp()` is the client, not the proxy | Rate-limit buckets collapse onto one key otherwise |
| `getPath()` is the raw, still-encoded path | Encoded-traversal rules depend on it |
| Header lookups are case-insensitive | `headers.user-agent` must find `User-Agent` |
