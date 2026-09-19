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

## 5. JSON-serializable rules loaded at runtime

`RegExp` instances and function predicates cannot round-trip through JSON. The serializable DSL (`src/domain/serializable.ts`) replaces `RegExp` with `{ pattern, flags? }` and is compiled with `loadRules` / `parseRulesFromJson` (`src/engine/load-rules.ts`), which validates every field and throws a `RuleParseError` (with a JSON-path-like `path`, e.g. `rules[0].when.matches.pattern`) on malformed input.

`rules.json`:

```json
{
  "rules": [
    {
      "id": "block-sqli-query-id",
      "when": { "field": "query.id", "matches": { "pattern": "('|OR\\s+1=1)", "flags": "i" } },
      "action": "block",
      "reason": "Possible SQL injection in query.id"
    },
    {
      "id": "block-known-bad-referrers",
      "when": { "field": "headers.referer", "matches": ["http://evil.example", "http://phish.example"] },
      "action": "block",
      "reason": "Known malicious referrer"
    },
    {
      "id": "rate-limit-login-attempts",
      "when": { "field": "ip", "rateLimit": { "max": 10, "windowMs": 60000, "keyPrefix": "login-attempts" } },
      "action": "block",
      "reason": "Too many login attempts",
      "minLevel": "low"
    }
  ]
}
```

Loading it:

```ts
import { readFileSync } from 'node:fs';
import { parseRulesFromJson, RuleParseError, createMiniWaf } from 'mini-waf';

let rules;
try {
  rules = parseRulesFromJson(readFileSync('./rules.json', 'utf8'));
} catch (err) {
  if (err instanceof RuleParseError) {
    // `err.path` pinpoints exactly which key failed, e.g. "rules[2].when.rateLimit.max".
    console.error(`Invalid rule at ${err.path}: ${err.message}`);
    process.exit(1);
  }
  throw err;
}

const waf = createMiniWaf({ presets: ['default'], rules });
```

`loadRules(value)` accepts either a top-level JSON array of rules or `{ "rules": [...] }` — both forms are shown implicitly above (the top-level object form is what `rules.json` uses). Top-level `matches` accepts a plain string (exact equality), a string array (OR list), or `{ pattern, flags? }` (compiled via `new RegExp(pattern, flags)` — invalid flags or an invalid pattern also throw `RuleParseError`).

## 6. Protection-level gating (`minLevel`)

Every rule (preset or custom) declares (or inherits) a `minLevel`. It only runs when the configured `WafConfig.level` is **at least** that strict — `low < balanced < high < paranoid` (`isLevelActive`, `src/domain/levels.ts`). Rules without an explicit `minLevel` default to `'low'`, i.e. always active regardless of configured level.

```ts
import { expressWaf } from 'mini-waf/express';

app.use(
  expressWaf({
    level: 'high',
    presets: ['default'],
    rules: [
      {
        id: 'strict-debug-flag',
        // Only enforced when level is 'high' or 'paranoid'; silently inert
        // at 'low'/'balanced' so staging (level: 'balanced') can keep
        // using ?debug=1 while production (level: 'high') cannot.
        minLevel: 'high',
        action: 'block',
        when: { field: 'query.debug', equals: '1' },
        reason: 'Debug flag blocked at high+ protection level',
      },
      {
        id: 'always-block-internal-header-spoof',
        // No minLevel — defaults to 'low', so this runs at every level.
        action: 'block',
        when: { field: 'headers.x-internal-auth', matches: /^.+$/ },
        reason: 'Client attempted to spoof an internal-only header',
      },
    ],
  }),
);
```

## 7. Enabling / disabling rules by id

After presets and custom rules are merged, `buildRuleList` (`src/engine/engine.ts`) applies, **in this exact order**: (1) resolve presets + custom `rules`, (2) filter by `level`/`minLevel`, (3) apply `enabledRuleIds` if non-empty (allowlist), (4) apply `disabledRuleIds`, (5) drop `enabled: false` and sort by `priority`.

```ts
createMiniWaf({
  presets: ['default'],
  level: 'balanced',
  // Turn off a specific preset rule that produces false positives for this app...
  disabledRuleIds: ['preset-scanners-ua-broad', 'preset-xss-generic-tags'],
  rules: [
    {
      // ...and add a targeted allowlist rule instead, running first
      // (priority 1) so 'allow' short-circuits before any preset scans.
      id: 'allow-health',
      priority: 1,
      action: 'allow',
      when: { field: 'path', equals: '/health' },
    },
    {
      id: 'log-suspicious-referrer',
      // `action: 'log'` never blocks — it only collects into
      // WafEvaluationResult.loggedRules and, if logging is enabled at
      // level 'info'+, is emitted via WafLogger.audit(ctx, rule).
      action: 'log',
      when: { field: 'headers.referer', includes: 'pastebin' },
      reason: 'Referrer includes pastebin — audit only, not blocked',
    },
  ],
});
```

`enabledRuleIds` is an allowlist: when present **and non-empty**, only listed ids survive; an empty array or `undefined` is a no-op (does not lock you out of every rule by accident). Prefer `disabledRuleIds` for "keep everything except X" and `enabledRuleIds` for "keep only X" — mixing both is legal (allowlist applies first, then the denylist further narrows it).

## Composing with presets

Custom rules are merged **after** resolved presets (same id space for enable/disable filters, so pick ids that will not collide with `preset-*`). Use `priority` so `allow` / early blocks run when you intend — presets mostly use priorities in the 40-90 range, so a `priority: 1` custom `allow` rule reliably runs first.

```ts
createMiniWaf({
  presets: ['sqli', 'xss'],
  level: 'balanced',
  disabledRuleIds: ['preset-xss-generic-tags'],
  rules: [/* your rules from sections 1-6 above */],
});
```

See [Presets](/guide/presets) for the full list of built-in rule ids available for `enabledRuleIds`/`disabledRuleIds`, and [Core concepts](/guide/concepts) for how `WafField`, matchers, and actions fit together.
