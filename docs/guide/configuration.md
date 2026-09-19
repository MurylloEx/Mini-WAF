# Configuration reference

All options are fields on `WafConfig`. Passed to `expressWaf(config)`, `fastifyWaf` (`config` or `settings`), `MiniWafModule.forRoot({ config })`, or `createMiniWaf(config)`.

```ts
{
  level?: 'low' | 'balanced' | 'high' | 'paranoid'; // default: 'balanced'
  presets?: WafPresetName[];
  rules?: WafRule[];
  enabledRuleIds?: string[];   // optional allowlist (after merge + level)
  disabledRuleIds?: string[];  // drop by id (after allowlist)
  blockStatusCode?: number;    // default: 403
  blockBody?: string;          // default: 'Forbidden'
  logging?: false | true | { level?: 'error' | 'info' | 'debug'; sink?: WafLogger };
  // logging default: false (off — no I/O)

  // Performance (all optional)
  maxFieldLength?: number;     // truncate scanned field values; default 8192 (0 = unlimited)
  ruleYieldEvery?: number;     // yield to event loop every N rules; default 32 (0 = off)
  maxRateLimitKeys?: number;   // LRU cap on distinct rate-limit keys; default 10000
  decisionCache?: { max?: number; ttlMs?: number }; // short-TTL decision LRU; off by default
}
```

A fully annotated instance, mirroring the exact fields and defaults resolved by `resolveConfig` / `resolvePerformance` in `src/engine/engine.ts`:

```ts
import type { WafConfig } from 'mini-waf';

const config: WafConfig = {
  // Gate for `minLevel` on every rule (preset or custom). Ordering:
  // low(0) < balanced(1) < high(2) < paranoid(3) — see src/domain/levels.ts.
  level: 'balanced',

  // Built-in packs, resolved + deduped by rule id via `resolvePresets`.
  presets: ['default'],

  // Your own rules, merged AFTER presets (same id namespace for filters below).
  rules: [
    { id: 'allow-health', priority: 1, action: 'allow', when: { field: 'path', equals: '/health' } },
  ],

  // If set and non-empty, ONLY these rule ids survive the level filter.
  // Leave undefined/empty to keep everything (the common case).
  enabledRuleIds: undefined,

  // Drop these rule ids after the allowlist above is applied. Safe to
  // combine with presets you otherwise want, minus a few noisy entries.
  disabledRuleIds: ['preset-scanners-ua-broad'],

  // HTTP status written by WafHttpContext.drop() on a block decision.
  blockStatusCode: 403,

  // Response body written alongside blockStatusCode. Plain text by default;
  // set a JSON string yourself if your API contract expects a JSON error body.
  blockBody: 'Forbidden',

  // false (default) = zero logging I/O. true = console at 'info'. Object =
  // explicit level + optional custom sink — see the Logging guide.
  logging: { level: 'info' },

  // Truncates each scanned field value before any matcher/regex runs. Bounds
  // worst-case regex cost on huge bodies; 0 disables truncation entirely.
  maxFieldLength: 8_192,

  // Yields to the event loop roughly every N rules on the async scan path
  // (subject to an internal ~1ms sync-time budget) so a large custom rule
  // set cannot starve other requests. 0 disables yielding entirely.
  ruleYieldEvery: 32,

  // Upper bound on distinct rate-limit buckets (usually one per client IP).
  // Oldest buckets are evicted once exceeded — bounds memory under a flood
  // from many distinct source addresses.
  maxRateLimitKeys: 10_000,

  // Optional short-TTL LRU of full decisions keyed by a request fingerprint.
  // Automatically disabled whenever any ACTIVE rule carries `rateLimit`, so
  // DoS counters keep advancing instead of being served from cache.
  decisionCache: { max: 256, ttlMs: 1_000 },
};
```

## Field details

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `level` | `ProtectionLevel` | `'balanced'` | Only rules with `minLevel <= level` run |
| `presets` | `WafPresetName[]` | — | Built-in packs to include |
| `rules` | `WafRule[]` | — | Custom rules merged after presets |
| `enabledRuleIds` | `string[]` | — | Non-empty allowlist after level filter |
| `disabledRuleIds` | `string[]` | — | Drop listed ids after allowlist |
| `blockStatusCode` | `number` | `403` | HTTP status on block |
| `blockBody` | `string` | `'Forbidden'` | Response body on block |
| `logging` | `WafLoggingSetting` | `false` | See [Logging](/guide/logging) |
| `maxFieldLength` | `number` | `8192` | Truncate scanned values; `0` = unlimited |
| `ruleYieldEvery` | `number` | `32` | Yield interval; `0` = never |
| `maxRateLimitKeys` | `number` | `10000` | Cap distinct rate-limit keys |
| `decisionCache` | `{ max?, ttlMs? }` | off | Decision LRU; auto-off if any active rule has `rateLimit` |

`WafPresetName`: `'default' | 'sqli' | 'xss' | 'scanners' | 'path-traversal' | 'rfi' | 'rce' | 'protocol'`.

## Engine options (second argument)

`createMiniWaf(config, options?)` and framework helpers accept `WafEngineOptions`, which may include an injectable `logger` (honored only when logging is enabled). Nest / Fastify wrappers also accept `platform` / plugin-specific fields — see [Integrations](/guide/integrations).

## Constants

Exported from the package (among others):

- `DEFAULT_PROTECTION_LEVEL` → `'balanced'`
- `DEFAULT_RULE_MIN_LEVEL` → `'low'`
- `DEFAULT_MAX_FIELD_LENGTH` → `8192`
- `DEFAULT_MAX_RATE_LIMIT_KEYS` → `10000`
- `PROTECTION_LEVELS` → `['low','balanced','high','paranoid']`
