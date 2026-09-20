# Custom rules

Compose rules in TypeScript or load them from JSON. Both end up as the same `WafRule` type (`src/domain/rules.ts`) passed through `WafConfig.rules`. This page builds up from a single field match to protection-level gating and runtime-loaded JSON, in increasing order of complexity.

## The rule shape

```ts
interface WafRule {
  readonly id: string;
  readonly when: WafCondition;
  readonly action: 'allow' | 'block' | 'log';
  readonly reason?: string;   // human-readable; surfaced in block responses / logs
  readonly enabled?: boolean; // default true
  readonly priority?: number; // lower runs first; default 100
  readonly minLevel?: ProtectionLevel; // default 'low' (see Core concepts)
}
```

`when` is a `WafCondition` tree: a leaf `FieldCondition`, or a compound `{ all }` / `{ anyOf }` / `{ not }` node wrapping other conditions.

## 1. Simple field match

The smallest useful rule: one field, one matcher.

```ts
import type { WafRule } from 'mini-waf';

const blockSqliInQueryId: WafRule = {
  id: 'block-sqli-query-id',
  // `matches` accepts string | RegExp | readonly string[] | ((value: string) => boolean).
  // A RegExp is tested as-is against the resolved field value(s); the engine
  // resets `lastIndex` before each test so /g or /y flags never carry state
  // across requests (see src/engine/matcher.ts).
  when: { field: 'query.id', matches: /('|OR\s+1=1)/i },
  action: 'block',
  reason: 'Possible SQL injection in query.id',
};
```

## 2. Composite AND / OR conditions

`all` (AND) and `anyOf` (OR) nest arbitrarily. Evaluation is short-circuiting: `all` stops at the first non-match, `anyOf` stops at the first match (`src/engine/evaluate.ts` — `foldAllSeq` / `foldAnyOfSeq`).

```ts
const blockUnauthenticatedAdminProbe: WafRule = {
  id: 'block-unauthenticated-admin-probe',
  action: 'block',
  reason: 'Unauthenticated request to an admin surface',
  when: {
    all: [
      // OR: any admin-looking path...
      {
        anyOf: [
          { field: 'path', equals: '/admin' },
          { field: 'path', matches: /^\/admin\// },
        ],
      },
      // ...AND no session cookie present (negation of a "cookie exists" check).
      { not: { field: 'cookies.session', matches: /^.+$/ } },
    ],
  },
};
```

`not` wraps exactly one child condition and inverts its `matched` flag; it forwards the child's `rateLimitInfo` unchanged (negating a rate-limit condition does not un-record the hit — the counter still advances, only the pass/fail interpretation flips).

## 3. Regex-based detection

Regex is the most expressive matcher, but also the most expensive and the only one with unbounded worst-case cost (Node has no RegExp timeout). Anchor and bound quantifiers deliberately; `maxFieldLength` (default `8192`, see [Performance](/guide/performance)) truncates the haystack before any regex runs, which is your main backstop against catastrophic backtracking on attacker-controlled input.

```ts
const blockSsrfToMetadataService: WafRule = {
  id: 'block-ssrf-metadata-custom',
  action: 'block',
  minLevel: 'balanced',
  reason: 'Outbound-fetch parameter targets a cloud metadata endpoint',
  when: {
    anyOf: [
      // Cloud metadata IP literals across providers, in `url`-typed query params.
      { field: 'query.url', matches: /169\.254\.169\.254|metadata\.google\.internal/i },
      { field: 'body', matches: /169\.254\.169\.254|metadata\.google\.internal/i },
    ],
  },
};
```

The built-in `preset-rce-ssrf-metadata` rule (part of the `rce` pack) covers the same class of attack more broadly — write custom regex rules like this one when you need a narrower or app-specific variant (e.g. matching your own proxy/webhook parameter names).

### Making a regex rule cheap with `requires`

Add `requires` whenever every payload your pattern can match necessarily
contains a fixed substring. The value is skipped with an `indexOf` scan before
the regex runs, and the lowercased field view is shared across all rules:

```ts
const blockSsrfToMetadataServiceFast: WafRule = {
  ...blockSsrfToMetadataService,
  id: 'block-ssrf-metadata-custom-fast',
  when: {
    anyOf: [
      {
        field: 'query.url',
        matches: /169\.254\.169\.254|metadata\.google\.internal/i,
        // Both alternatives are literals, so the list is provably complete.
        requires: ['169.254', 'metadata.google'],
      },
      {
        field: 'body',
        matches: /169\.254\.169\.254|metadata\.google\.internal/i,
        requires: ['169.254', 'metadata.google'],
      },
    ],
  },
};
```

The gain grows with the payload: on an 8 KB body a prefiltered rule costs a
substring scan instead of a full regex pass. Every preset rule whose pattern
allows it ships one.

::: warning The list must be exhaustive
`requires` is not a hint — a value containing none of the literals is **never**
matched. If your pattern can match something the list does not cover, the rule
silently stops detecting it. Drop `requires` when the pattern has no fixed
literal, e.g. `/^\d{3,}$/` or a predicate function.
:::

## 4. Rate-limit rule

`rateLimit` turns a `FieldCondition` into a stateful counter instead of a pure predicate. The condition **matches once the limit is exceeded**, not on every hit:

```ts
interface RateLimitSpec {
  readonly max: number;       // hits allowed inside the window before matching
  readonly windowMs: number;  // sliding window length in ms
  readonly keyPrefix?: string; // key namespace; defaults to the field name
}
```

```ts
const rateLimitLoginAttempts: WafRule = {
  id: 'rate-limit-login-attempts',
  action: 'block',
  reason: 'Too many login attempts from this IP',
  when: {
    field: 'ip',
    rateLimit: {
      max: 10,        // allow up to 10 hits...
      windowMs: 60_000, // ...per rolling 60-second window
      // Namespacing the key avoids colliding with the built-in
      // `preset-dos-rate-limit` bucket (keyPrefix: 'preset-dos'), which also
      // counts on `field: 'ip'` — without a distinct prefix both rules would
      // share (and prematurely exhaust) the same counter.
      keyPrefix: 'login-attempts',
    },
  },
};
```

Only apply `rateLimit` on `POST /login`-style routes by combining it with a path check:

```ts
const rateLimitLoginRoute: WafRule = {
  id: 'rate-limit-login-route',
  action: 'block',
  reason: 'Too many login attempts',
  when: {
    all: [
      { field: 'path', equals: '/login' },
      { field: 'method', equals: 'POST' },
      { field: 'ip', rateLimit: { max: 10, windowMs: 60_000, keyPrefix: 'login' } },
    ],
  },
};
```

Because `all` evaluates children in order and short-circuits on the first non-match, the rate-limit hit is only recorded for requests that already matched `path` and `method` — non-login traffic never touches this counter. Counters live in a single shared `RateLimitStore` per engine instance, capped by `maxRateLimitKeys` (default `10000`, LRU-evicted) — see [Performance & caching](/guide/performance). Any active rule using `rateLimit` also **disables the optional `decisionCache`** automatically (`rulesHaveRateLimit`, `src/engine/condition-utils.ts`), since a cached "allow" would stop the counter from advancing.

## 5. Composing with presets

Custom rules are merged **after** resolved presets, into the same id namespace
that `enabledRuleIds` / `disabledRuleIds` operate on — so pick ids that will not
collide with `preset-*`.

Presets mostly use priorities in the 40–90 range, so a `priority: 1` custom
`allow` rule reliably runs first:

```ts
createMiniWaf({
  presets: ['sqli', 'xss'],
  level: 'balanced',
  disabledRuleIds: ['preset-xss-generic-tags'],
  rules: [
    {
      id: 'allow-health',
      priority: 1,
      action: 'allow',
      when: { field: 'path', equals: '/health' },
    },
    // ...your rules from the sections above
  ],
});
```

## Testing what you wrote

Two assertions catch most regressions:

```ts
// 1. The attack is blocked — by the rule you think.
expect(result.matchedRule?.id).toBe('block-unauthenticated-admin-probe');

// 2. Real traffic still passes.
expect(`${result.decision}:${result.matchedRule?.id ?? ''}`).toBe('allow:');
```

The second one matters more. A rule that over-blocks is how a WAF gets turned
off in production — build a corpus of query strings and bodies your app
actually receives and assert them at one level *above* what you deploy. See
[Testing your integration](/guide/integrations/testing) for a runnable setup.

## Where to go next

- [Protection levels](/guide/protection-levels) — `minLevel` gating and enabling
  or disabling rules by id
- [JSON rules](/guide/json-rules) — ship the same DSL as configuration
- [Presets](/guide/presets) — every built-in rule id, and what it catches
- [Conditions & matchers](/guide/conditions) — the full `when` reference
