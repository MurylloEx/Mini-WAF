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

## A complete worked example

[Koa](/guide/integrations/koa) is the reference implementation of everything on
this page: a real adapter, field by field, with the reasoning behind each
mapping. Start there, then come back for the interface details.

Other frameworks that follow the same path have their own pages —
[Hono](/guide/integrations/hono), [Hapi](/guide/integrations/hapi) and
[Next.js](/guide/integrations/nextjs).


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
