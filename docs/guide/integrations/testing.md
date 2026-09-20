# Testing your integration

Unit tests prove a rule matches. Integration tests prove the **adapter** wired
it up correctly — that a block really ends the request, that the body reached
the engine, and that all frameworks agree. Mini-WAF ships both layers and you
can reuse the pattern in your own app.

## Running the bundled suite

From the repository root:

```bash
npm run integration
```

That builds the library (the apps import from `dist/`, resolved through the package `exports`), installs the
`integration/` workspace, boots one server per framework, and drives real HTTP
requests against all of them:

| App | Path | Port |
|-----|------|------|
| Express | `integration/express/server.mjs` | 3101 |
| Fastify | `integration/fastify/server.mjs` | 3102 |
| NestJS + Express | `integration/nestjs-express/` | 3103 |
| Koa (custom adapter) | `integration/koa/server.mjs` | 3104 |

`integration/scenarios/run.mjs` asserts the same allow/block outcome on every
target, so an adapter that silently fails to read the body or to end the
response shows up immediately. The scenario catalog lives in
`integration/scenarios.md`.

Some scenarios spin up **ephemeral** servers instead of the long-lived apps —
used for things that need their own config, like `disabledRuleIds` behavior or
an Express instance with `query parser: 'extended'`.

The per-IP rate-limit scenario is **opt-in**, because 120+ requests are slow and
can interfere with other assertions:

```bash
RUN_RATE_LIMIT=1 npm run integration
```

## Unit-testing rules without a server

The engine only ever sees a `WafHttpContext`, so you can drive it directly — no
HTTP, no framework. There is no mock helper in the published package; write a
small factory for the fields your rules touch:

```ts
import { createWafEngine, type WafHttpContext } from 'mini-waf';

interface MockInput {
  readonly method?: string;
  readonly path?: string;
  readonly query?: Record<string, string>;
  readonly headers?: Record<string, string>;
  readonly body?: string;
}

function mockContext(input: MockInput = {}): WafHttpContext {
  const path = input.path ?? '/';
  const headers = input.headers ?? {};
  return {
    framework: 'test',
    getMethod: () => input.method ?? 'GET',
    getUrl: () => path,
    getPath: () => path,
    getIp: () => '127.0.0.1',
    getProtocol: () => 'http',
    getLocalPort: () => 3000,
    getHeader: (name) => headers[name.toLowerCase()],
    getHeaders: () => headers,
    getQuery: () => input.query ?? {},
    getCookies: () => ({}),
    getRawBody: () => input.body ?? '',
    getFiles: () => [],
    setResponseHeader: () => {},
    removeResponseHeader: () => {},
    isBlocked: () => false,
    drop: () => {},
  };
}
```

Then assert on the decision **and the rule that produced it**:

```ts
const engine = createWafEngine({ presets: ['default'], level: 'balanced' });

const result = await engine.handle(
  mockContext({
    path: '/search',
    query: { q: "1' OR 1=1" },
    headers: { 'user-agent': 'Mozilla/5.0' },
  }),
);

expect(result.decision).toBe('block');
expect(result.matchedRule?.id).toBe('preset-sqli-classic-query');
```

Checking `matchedRule?.id`, not just `decision`, is what catches a rule that
"still blocks" for the wrong reason after a pattern change.

> The repository's own helpers — `tests/helpers/mock-context.ts` (typed, tracks
> `drop()` calls) and `benchmarks/lib/mock-context.mjs` — are fuller versions of
> the same idea if you want something to copy.

## Build a false-positive corpus

The failure mode that gets a WAF switched off is blocking real traffic, so test
that explicitly. Collect query strings and bodies your app actually receives and
assert they survive at the level you deploy — plus one above it:

```ts
const BENIGN = [
  { redirect_uri: 'https://app.example.com/callback' },
  { include: 'author,comments' },
  { tags: 'rails|php|node' },
  { label: 'Total: ${amount}' },
];

it.each(BENIGN)('allows benign query %j', async (query) => {
  const result = await engine.handle(mockContext({ query }));
  // Surfacing the rule id makes a failure self-diagnosing.
  expect(`${result.decision}:${result.matchedRule?.id ?? ''}`).toBe('allow:');
});
```

Run it at one level **above** production: if `high` is clean, `balanced` has
headroom, and raising the level during an incident is safe.

## Testing a custom adapter

Point the bundled scenarios at your own server instead of writing new ones:

```bash
# Start your app on one of the scenario ports, then:
node integration/scenarios/run.mjs --no-start
```

The Koa app is the reference for this path — see
[Custom adapters](/guide/integrations/custom-adapters).

## Checklist for any adapter

| Check | Why it matters |
|-------|----------------|
| A blocked request returns your `blockStatusCode` | Proves `drop()` actually ends the response |
| A blocked request never reaches the handler | Proves the adapter skips `next()` after a block |
| A body payload is blocked | Proves the parser runs before the WAF |
| A clean request returns 200 unchanged | Proves the WAF does not rewrite input |
| The client IP is not the proxy's | Proves `trust proxy` / forwarded headers are wired |
