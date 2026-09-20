# JSON rules

`RegExp` instances and function predicates cannot round-trip through JSON. The
serializable DSL (`src/domain/serializable.ts`) replaces `RegExp` with
`{ pattern, flags? }`, so a rule set can live in a config file, a database row,
or a ConfigMap instead of your bundle.

`loadRules` / `parseRulesFromJson` (`src/engine/load-rules.ts`) validate every
field and compile the result into ordinary `WafRule[]`.

## A rule file

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
      "id": "block-log4shell",
      "when": {
        "field": "body",
        "matches": { "pattern": "\\$\\{\\s*(?:jndi|ctx|env|sys)\\s*:", "flags": "i" },
        "requires": ["${"]
      },
      "action": "block",
      "reason": "JNDI lookup in body"
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

The top level may be either this `{ "rules": [...] }` object **or** a bare array
of rules.

## Loading it

```ts
import { readFileSync } from 'node:fs';
import { parseRulesFromJson, RuleParseError, createMiniWaf } from 'mini-waf';

let rules;
try {
  rules = parseRulesFromJson(readFileSync('./rules.json', 'utf8'));
} catch (err) {
  if (err instanceof RuleParseError) {
    // `err.path` pinpoints the failing key, e.g. "rules[3].when.rateLimit.max".
    console.error(`Invalid rule at ${err.path}: ${err.message}`);
    process.exit(1);
  }
  throw err;
}

const waf = createMiniWaf({ presets: ['default'], rules });
```

`parseRulesFromJson(text)` parses a JSON string; `loadRules(value)` takes an
already-parsed value — use it when the rules come from an API or a database.

Validation is strict on purpose: unknown keys are rejected, so a typo like
`"minlevel"` fails loudly at boot instead of silently changing behavior.

## `matches` shapes

| JSON | Compiles to |
|------|-------------|
| `"exact"` | Exact string equality |
| `["a", "b"]` | OR list of exact strings |
| `{ "pattern": "...", "flags": "i" }` | `new RegExp(pattern, flags)` |

An invalid pattern or invalid flags also throws `RuleParseError`.

## What JSON cannot express

| Not serializable | Use instead |
|------------------|-------------|
| Predicate functions (`matches: (v) => …`) | A `pattern`, or keep that rule in code |
| Anything needing closures or imports | A code rule merged alongside the JSON ones |

Mixing is normal — load JSON rules and concatenate your code-only ones:

```ts
createMiniWaf({
  presets: ['default'],
  rules: [...rules, ...codeOnlyRules],
});
```

## Reloading at runtime

Rule lists are immutable once an engine is built, so "reloading" means building
a new engine and swapping the reference:

```ts
import { expressWaf } from 'mini-waf/express';

// `expressWaf` returns the middleware function itself, so hot-swapping is
// just reassigning that reference.
let waf = expressWaf({ presets: ['default'], rules: load() });

// One indirection, so the swap is atomic for in-flight requests.
app.use((req, res, next) => waf(req, res, next));

process.on('SIGHUP', () => {
  try {
    // Build first: if `load()` throws, the old middleware stays installed.
    const next = expressWaf({ presets: ['default'], rules: load() });
    waf = next;
  } catch (err) {
    // Keep serving with the last known-good rule set.
    console.error('rule reload failed, keeping previous rules', err);
  }
});
```

Always validate before swapping — a `RuleParseError` should leave the running
engine untouched.

::: warning Rate-limit counters
Building a new engine also builds a new rate-limit store, so per-IP counters
reset on reload. Pass a shared `rateLimitStore` through `WafEngineOptions` if
counters must survive — see [Performance](/guide/performance).
:::

See `examples/rules.example.json` in the repository for a fuller file.
