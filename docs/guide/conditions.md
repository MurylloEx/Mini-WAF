# Conditions & matchers

A rule's `when` is a `WafCondition`. It is either a **field condition** (match
one field) or a **compound** that combines others.

| Shape | Meaning |
|-------|---------|
| `{ field, matches? / equals? / includes? / requires? / rateLimit? }` | Match one field |
| `{ all: [...] }` | Logical AND |
| `{ anyOf: [...] }` | Logical OR |
| `{ not: ... }` | Negation |

Compounds nest freely:

```ts
when: {
  all: [
    { field: 'path', matches: /^\/admin(\/|$)/ },
    { not: { field: 'cookies.session', matches: /^.+$/ } },
  ],
}
```

`not` wraps exactly one child and inverts its `matched` flag. It forwards the
child's rate-limit info unchanged — negating a `rateLimit` condition does not
un-record the hit, the counter still advances, only the pass/fail reading flips.

## Fields (`when.field`)

| Field | Description |
|-------|-------------|
| `ip`, `method`, `path`, `url`, `body`, `files` | Simple values |
| `query`, `headers`, `cookies` | **Every** value in the bag, OR-matched |
| `query.*`, `headers.*`, `cookies.*` | One specific key — cheaper than a bag |

Prefer a dotted path when you know the key: `headers.user-agent` reads one
value, `headers` reads and matches every header on the request.

::: warning Values, not names
Bag fields resolve parameter/header/cookie **values**. A payload hidden in a
parameter *name* (`?<script>x</script>=1`, or `?user[$ne]=null` under a
non-nesting query parser) is not seen. See [Security notes](/guide/security).
:::

## Matchers

- **`matches`** — `string` | `RegExp` | `readonly string[]` | predicate `(value: string) => boolean`
- **`equals`** — exact, case-sensitive equality
- **`includes`** — case-insensitive substring (needle lowercased at rule load)
- **`requires`** — literal prefilter, run *before* the matchers ([below](#the-requires-prefilter))
- **`rateLimit`** — `{ max, windowMs, keyPrefix? }`; matches once the limit is exceeded

A single `FieldCondition` may combine `equals` / `includes` / `matches`; they are
OR-ed, and the condition matches if any candidate value satisfies any of them
(`patternMatchesField` in `src/engine/evaluate.ts`).

```ts
// String — exact equality, same semantics as `equals` (kept for symmetry with
// the JSON DSL, where `matches` can also carry a plain string).
{ field: 'method', matches: 'TRACE' }

// RegExp — tested with .test(value); lastIndex is reset before each test so
// /g or /y flags never leak match position across requests.
{ field: 'headers.user-agent', matches: /sqlmap|nikto|acunetix/i }

// readonly string[] — OR list of exact strings (cheaper than a regex
// alternation when every option is a literal; no partial/prefix matching).
{ field: 'method', matches: ['TRACE', 'CONNECT', 'TRACK'] }

// Predicate — arbitrary logic; NOT JSON-serializable.
// Runs once per resolved candidate string for the field.
{ field: 'ip', matches: (value) => value.startsWith('10.') }
```

When `maxFieldLength` > 0 (default `8192`), values are truncated **before**
matching — see [Performance & caching](/guide/performance).

## The `requires` prefilter

`requires` gates a candidate value before any matcher runs: unless the value
contains one of the listed substrings (case-insensitively), it is skipped
entirely. An `indexOf` scan costs a fraction of a regex pass, and the lowercased
view of each field is memoized per request, so the check is paid once no matter
how many rules use it.

```ts
{
  field: 'body',
  matches: /\$\{\s*(?:jndi|ctx|env|sys)\s*:/i,
  requires: ['${'], // no "${" in the body ⇒ the regex never runs
}
```

This is what keeps the 94-rule `default` pack affordable on large bodies: most
preset rules declare one, so a clean request costs a handful of substring scans
instead of dozens of regex passes. On an 8 KB body it roughly doubled
throughput at an unchanged rule count.

::: danger The list is a promise, not a hint
Every string the pattern can match **must** contain at least one of the
literals. An incomplete list is a silent detection gap, not a slowdown. Omit
`requires` when the pattern has no fixed literal (`/^\d+$/`, a predicate) or
when you are unsure.
:::

## How field resolution works

`resolveFieldValues(ctx, field, options)` (`src/engine/field-resolver.ts`) turns
a `WafField` into one or more candidate strings pulled from `WafHttpContext`:

| Field kind | Resolution |
|---|---|
| `ip`, `method`, `path`, `url`, `body` | Single value from the matching `ctx.get*()` call |
| `files` | `ctx.getFiles()` mapped to display names (`fieldname`/`name`/`filename`/`originalname`), empty names filtered out |
| `query`, `headers`, `cookies` (bag) | **Every** value in the bag, OR-matched — a hit on any key matches the field |
| `query.<key>`, `headers.<key>`, `cookies.<key>` | Single value for that key (`headers.<key>` prefers `ctx.getHeader(key)`) |

Nested query values — what Express's `extended` parser produces for
`?filter[status]=open` — are flattened back to `key=value&key=value` (depth
capped at 6), which is how bracketed parameter names become visible to rules.

Resolved values, and their lowercased variants, are memoized **per request** in
`FieldResolveOptions.memo` / `memoLower`. If five rules all check
`headers.user-agent`, the header bag is read and lowercased once, not five
times.

::: tip Cost model
A rule costs one matcher run **per candidate value of each field it targets**.
A rule on `query` against a request with ten parameters is ten runs, not one.
That is the main reason to prefer `query.id` over `query`.
:::

## Rate-limit conditions

`rateLimit` turns a field condition into a stateful counter: it matches **once
the limit is exceeded**, not on every hit.

```ts
{
  id: 'rate-limit-login',
  action: 'block',
  reason: 'Too many login attempts',
  when: {
    field: 'ip',
    rateLimit: { max: 10, windowMs: 60_000, keyPrefix: 'login-attempts' },
  },
}
```

The bucket key is the resolved field value, optionally namespaced by
`keyPrefix`. Combine with a pattern in the same condition to scope the counter —
the pattern is checked first, and only matching requests advance the counter.

Any active `rateLimit` rule disables `decisionCache` automatically, so counters
never get served from cache. Details in [Performance](/guide/performance).
