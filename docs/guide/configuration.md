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
