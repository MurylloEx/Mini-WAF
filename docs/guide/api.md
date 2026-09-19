# API reference

Curated surface from the package `exports` map. Prefer these entrypoints over deep imports into `dist/`.

## Entry points

| Subpath | Main exports |
|---------|----------------|
| `mini-waf` | Core factory, domain types, engine helpers, adapters, presets, logging, IP/cookie/LRU utils; also re-exports framework helpers |
| `mini-waf/express` | `expressWaf`, `expressSecurityPolicy` |
| `mini-waf/fastify` | `fastifyWaf`, `fastifyPreHandler`, `fastifySecurityPolicy` |
| `mini-waf/nestjs` | `MiniWafModule`, `MiniWafMiddleware`, `nestMiddleware`, `MINI_WAF_OPTIONS` |
| `mini-waf/adapters` | `createAdapter`, `createExpressAdapter`, `createFastifyAdapter`, `createNestAdapter` |
| `mini-waf/presets` | `resolvePresets`, `defaultRules`, `sqliRules`, `xssRules`, `scannerRules`, `pathTraversalRules`, `rfiRules`, `rceRules`, `protocolRules` |

## Core

### `createMiniWaf(config?, options?)`

Returns `MiniWafInstance`:

- `rules` / `config` / `rateLimitStore` — resolved engine state
- `handle(ctx)` — evaluate a `WafHttpContext`
- `protect(adapter, request, response, next?)` — adapter path

### `createWafEngine(config?, options?)`

Lower-level engine without the `protect` sugar.

### `runWithAdapter(waf, adapter, request, response, next?)`

Shared integration helper → `{ result, ctx }`.

```ts
import { createMiniWaf, runWithAdapter } from 'mini-waf';
import { createExpressAdapter } from 'mini-waf/adapters';

const waf = createMiniWaf({ presets: ['default'] });
const adapter = createExpressAdapter();

app.use(async (req, res, next) => {
  const { result, ctx } = await runWithAdapter(waf, adapter, req, res, next);
  // Unlike `expressWaf`, you get both the WafHttpContext (e.g. ctx.getIp())
  // and the full WafEvaluationResult here — useful for custom telemetry
  // without re-implementing the adapter wiring yourself.
  if (result.decision === 'allow' && !ctx.isBlocked()) {
    next();
  }
});
```

### Rule loading

- `parseRulesFromJson(source: string)` → `WafRule[]`
- `loadRules(...)` — load/compile serializable rules
- `RuleParseError` — invalid JSON DSL (includes path)

### Filtering / building

- `buildRuleList`, `filterRulesByLevel`, `filterRulesByEnabledIds`, `filterRulesByDisabledIds`
- `normalizeRule` / `normalizeRules` / `normalizeCondition`
- `conditionHasRateLimit` / `rulesHaveRateLimit`

### Matching & evaluation

- `evaluateCondition`, `matchesPattern`, `includesIgnoreCase`, `includesLower`
- `resolveFieldValues`, `resolveFieldValuesLower`, `resolveFieldJoined`
- `requestFingerprint`, `hashString`
- `scanRules` / `scanRulesAsync`

### Rate limit

- `RateLimitStore`, `emptyRateLimitState`, `applyRateLimitHit`, `pruneRateLimitState`
- Defaults: `DEFAULT_MAX_RATE_LIMIT_KEYS`, `DEFAULT_RATE_LIMIT_IDLE_MS`, `DEFAULT_RATE_LIMIT_PRUNE_EVERY`

## Domain types

- `WafConfig`, `WafRule`, `WafCondition`, `WafField`, `WafAction`, `WafPresetName`
- `WafEvaluationResult`, `WafDecision`
- `ProtectionLevel`, `PROTECTION_LEVELS`, `isLevelActive`, `protectionLevelRank`, …
- `JsonWafRule`, `SerializableWafRule`, JSON condition types
- `WafHttpContext`, `WafAdapter`
- Type guards: `isFieldCondition`, `isAllCondition`, `isAnyOfCondition`, `isNotCondition`

## Logging

- `createConsoleLogger`, `silentLogger`, `resolveLogging`, `pickLoggerSink`
- `isLogLevelActive`, `isWafLogLevel`
- Types: `WafLogger`, `WafLogLevel`, `WafLoggingOptions`, `WafLoggingSetting`, `ResolvedLogging`

## Utilities

- `parseCookies`
- `normalizeClientIp`, `pickClientIpFromXff`, `isHostIpLiteral`, `clearIpNormalizeCache`, `ipNormalizeCacheSize`
- `LruCache`

## Framework modules

Documented with examples in [Quick start](/guide/quick-start) and [Integrations](/guide/integrations). Types such as `FastifyPluginOptions`, `NestMiniWafOptions`, and `CustomAdapterHandlers` follow the source in `src/fastify.ts`, `src/nestjs.ts`, and `src/adapters/create-adapter.ts`.
