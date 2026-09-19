# Core concepts

Everything flows through `WafConfig` passed to `expressWaf(config)`, `fastifyWaf` (`config` or `settings`), `MiniWafModule.forRoot({ config })`, or `createMiniWaf(config)`.

## Rules

A `WafRule` is a declarative unit:

```ts
import type { WafRule } from 'mini-waf';

const rule: WafRule = {
  id: 'block-sqli-query',                        // string; must be unique across the active rule list
  when: { field: 'query.id', matches: /('|OR\s+1=1)/i },
  action: 'block',                                // 'allow' | 'block' | 'log'
  reason: 'Possible SQL injection',               // optional; surfaced in logs (not in the HTTP response body)
  minLevel: 'low',                                // optional; defaults to 'low' — active at every configured level
  priority: 100,                                  // optional; lower runs first; default 100
  enabled: true,                                  // optional; default true — false removes it from the built list entirely
};
```

Full type, for reference (`src/domain/rules.ts`):

```ts
interface WafRule {
  readonly id: string;
  readonly when: WafCondition;
  readonly action: WafAction; // 'allow' | 'block' | 'log'
  readonly reason?: string;
  readonly enabled?: boolean;      // default true
  readonly priority?: number;      // default 100; ties broken by original array order
  readonly minLevel?: ProtectionLevel; // default 'low'
}
```

Rules come from:

1. **Presets** — named packs (`sqli`, `xss`, …, `default`)
2. **Custom `rules`** — your array, merged after presets
3. **JSON** — `parseRulesFromJson` / `loadRules` → same `WafRule[]`

## Conditions (`when`)

| Shape | Meaning |
|-------|---------|
| `{ field, matches? / equals? / includes? / rateLimit? }` | Match one field |
| `{ all: [...] }` | Logical AND |
| `{ anyOf: [...] }` | Logical OR |
| `{ not: ... }` | Negation |

### Fields (`when.field`)

| Field | Description |
|-------|-------------|
| `ip`, `method`, `path`, `url`, `body`, `files` | Simple values |
| `query`, `headers`, `cookies` | All values (OR) — prefer dotted paths when possible |
| `query.*`, `headers.*`, `cookies.*` | Specific key (cheaper than bags) |

### Matchers

- **`matches`**: `string` \| `RegExp` \| `readonly string[]` \| predicate `(value: string) => boolean`
- **`equals`**: exact equality
- **`includes`**: case-insensitive substring (needle lowercased at rule load)
- **`rateLimit`**: `{ max, windowMs, keyPrefix? }` — condition matches after the limit is exceeded

`matches` is polymorphic (`src/engine/matcher.ts` — `matchesPattern`), and a `FieldCondition` may combine `equals` / `includes` / `matches` together (matched with OR-across-candidates — see `patternMatchesField` in `src/engine/evaluate.ts`):

```ts
// String — exact equality, same semantics as `equals` (kept for symmetry with
// the JSON DSL, where `matches` can also carry a plain string).
{ field: 'method', matches: 'TRACE' }

// RegExp — tested with .test(value); lastIndex is reset before each test so
// /g or /y flags never leak match position across requests.
{ field: 'headers.user-agent', matches: /sqlmap|nikto|acunetix/i }

// readonly string[] — OR list of exact strings (cheaper than a regex
// alternation when every option is a literal, no partial/prefix matching).
{ field: 'method', matches: ['TRACE', 'CONNECT', 'TRACK'] }

// Predicate — arbitrary logic; NOT JSON-serializable (see custom-rules.md).
// Runs once per resolved candidate string for the field.
{ field: 'ip', matches: (value) => value.startsWith('10.') }
```

When `maxFieldLength` > 0 (default `8192`), scanned field values are truncated **before** matching — see [Performance & caching](/guide/performance) for the trade-offs.

### How field resolution works

`resolveFieldValues(ctx, field, options)` (`src/engine/field-resolver.ts`) turns a `WafField` into one or more candidate strings pulled straight from `WafHttpContext`:

| Field kind | Resolution |
|---|---|
| `ip`, `method`, `path`, `url`, `body` | Single value from the matching `ctx.get*()` call |
| `files` | `ctx.getFiles()` mapped to display names (`fieldname`/`name`/`filename`/`originalname`), empty names filtered out |
| `query`, `headers`, `cookies` (bag) | **Every** value in the bag, matched with OR — a match on any key matches the field |
| `query.<key>`, `headers.<key>`, `cookies.<key>` | Single value for that key (`headers.<key>` prefers `ctx.getHeader(key)` when available) |

Resolved values (and their lowercased variants for `includes`) are memoized **per request** in `FieldResolveOptions.memo` / `memoLower` — if five different rules all check `headers.user-agent`, the header bag is only read and lowercased once per request, not five times.

## Actions

| Action | Behavior |
|--------|----------|
| `allow` | Allow and **stop** evaluation (whitelist). Prefer low `priority` so it runs early. |
| `block` | Block with `blockStatusCode` / `blockBody` (defaults `403` / `Forbidden`). |
| `log` | Collect for audit; emitted only when logging is on at `info`+. |

After the first matching `block`, later pure `block` rules (no `rateLimit` in their condition tree) are skipped. `allow`, `log`, and any rule with rate-limit side effects still run in order.

## Protection levels

Order: `low` < `balanced` < `high` < `paranoid`

Each rule may declare `minLevel`. It only applies when the configured `level` is **greater than or equal** to that minimum. Custom rules **without** `minLevel` are treated as `low` (active at any level). Default config level: **`balanced`**.

| Level | Includes | Typical use | ≈ CRS PL |
|-------|----------|-------------|----------|
| `low` | Obvious scanners (UA), classic SQLi, OS path/LFI, RFI / PHP RCE, strong shell RCE, SSRF metadata | APIs sensitive to false positives | PL1 (core) |
| `balanced` (default) | `low` + XSS, null-byte, uploads, DoS rate-limit, protocol splitting/smuggling, SSTI, session fixation HTML | General production | PL1–PL2 |
| `high` | `balanced` + SSI, hex flood, pollution, advanced SQLi, CL+TE, shell `$()`, session ID in URL | Under attack / broader coverage | PL2 |
| `paranoid` | `high` + broad UAs, generic tags, empty UA, shebang, oversized headers | Max coverage; more FPs | PL3–PL4 |

```ts
expressWaf({
  level: 'high',
  presets: ['default'],
  rules: [
    {
      id: 'strict-probe',
      minLevel: 'high',
      action: 'block',
      when: { field: 'query.debug', equals: '1' },
      reason: 'Debug flag blocked at high+',
    },
  ],
});
```

## Enable / disable by id

After presets and custom rules are merged, the engine builds the active list in this order:

1. Resolve presets + custom `rules`
2. Filter by protection `level` (`minLevel`)
3. Apply `enabledRuleIds` (if present and **non-empty** — allowlist)
4. Apply `disabledRuleIds`
5. Drop `enabled: false` and sort by `priority`

```ts
expressWaf({
  presets: ['default'],
  level: 'balanced',
  disabledRuleIds: ['preset-scanners-ua'],
  // Or keep only a short allowlist:
  // enabledRuleIds: ['preset-sqli-classic-query', 'allow-health'],
  rules: [
    {
      id: 'allow-health',
      priority: 1,
      action: 'allow',
      when: { field: 'path', equals: '/health' },
    },
  ],
});
```

Empty `enabledRuleIds` / `disabledRuleIds` are no-ops.

## Serializable JSON rules

`RegExp` and function predicates are not JSON-friendly. Use `JsonWafRule` and compile with `parseRulesFromJson` / `loadRules`:

```ts
import { parseRulesFromJson, createMiniWaf } from 'mini-waf';
import { readFileSync } from 'node:fs';

const rules = parseRulesFromJson(readFileSync('./rules.json', 'utf8'));
const waf = createMiniWaf({ presets: ['default'], rules });
```

See [Custom rules](/guide/custom-rules) for the JSON `matches` shapes and `RuleParseError`.
