# Core concepts

Everything flows through one object: a `WafConfig` handed to `expressWaf(config)`,
`fastifyWaf` (`config` or `settings`), `MiniWafModule.forRoot({ config })`, or
`createMiniWaf(config)`.

Inside, the flow is always the same:

```
request → adapter → WafHttpContext → rule list → decision (allow | block)
```

The adapter is the only framework-aware part. Everything below it works on a
`WafHttpContext` and a list of `WafRule`s.

## A rule

A `WafRule` is a declarative unit — a condition plus what to do when it matches:

```ts
import type { WafRule } from 'mini-waf';

const rule: WafRule = {
  id: 'block-sqli-query',                         // unique across the active list
  when: { field: 'query.id', matches: /('|OR\s+1=1)/i },
  action: 'block',                                 // 'allow' | 'block' | 'log'
  reason: 'Possible SQL injection',                // logged, never sent in the response
  minLevel: 'low',                                 // default 'low' — active at every level
  priority: 100,                                   // lower runs first; default 100
  enabled: true,                                   // false removes it from the built list
};
```

The full type (`src/domain/rules.ts`):

```ts
interface WafRule {
  readonly id: string;
  readonly when: WafCondition;
  readonly action: WafAction;           // 'allow' | 'block' | 'log'
  readonly reason?: string;
  readonly enabled?: boolean;           // default true
  readonly priority?: number;           // default 100; ties keep array order
  readonly minLevel?: ProtectionLevel;  // default 'low'
}
```

`reason` is deliberately **not** returned to the client — the HTTP response is
just `blockStatusCode` / `blockBody` (default `403` / `Forbidden`), so a probe
learns nothing about which rule caught it.

## Where rules come from

| Source | How |
|--------|-----|
| **Presets** | Named packs (`sqli`, `xss`, …, `default`) — see [Presets](/guide/presets) |
| **Custom `rules`** | Your array, merged *after* presets — see [Custom rules](/guide/custom-rules) |
| **JSON** | `parseRulesFromJson` / `loadRules` → the same `WafRule[]` — see [JSON rules](/guide/json-rules) |

All three land in one flat list. Which entries actually run is decided by
[protection levels and id filters](/guide/protection-levels).

## Actions

| Action | Behavior |
|--------|----------|
| `allow` | Allow and **stop** evaluation (whitelist). Give it a low `priority` so it runs early. |
| `block` | Block with `blockStatusCode` / `blockBody` (defaults `403` / `Forbidden`). |
| `log` | Collect for audit only; never blocks. Emitted when logging is on at `info`+. |

## Evaluation order

1. Rules run sorted by `priority` (lower first; ties keep their original order).
2. The first matching `allow` **short-circuits** — nothing after it runs.
3. After the first matching `block`, later *pure* `block` rules are skipped.
   `allow`, `log`, and any rule whose condition tree contains `rateLimit` still
   run, so counters keep advancing and audit rules still fire.

That last point is why a blocked request can be **faster** than a clean one: it
exits the scan early.

## The decision

`engine.handle(ctx)` resolves to a `WafEvaluationResult`:

```ts
interface WafEvaluationResult {
  readonly decision: 'allow' | 'block';
  readonly matchedRule: WafRule | undefined;  // what produced a block
  readonly reason: string | undefined;
  readonly loggedRules: readonly WafRule[];   // every `action: 'log'` that matched
}
```

On a block the adapter has already ended the response via
`WafHttpContext.drop()` before `handle` resolves.

## Where to go next

| You want to… | Page |
|--------------|------|
| Understand `when` — fields, matchers, `requires` | [Conditions & matchers](/guide/conditions) |
| Control which rules run | [Protection levels](/guide/protection-levels) |
| Know what the built-in packs catch | [Presets](/guide/presets) |
| Write your own rules | [Custom rules](/guide/custom-rules) |
| Ship rules as config, not code | [JSON rules](/guide/json-rules) |
| Bound CPU and memory | [Performance & caching](/guide/performance) |
