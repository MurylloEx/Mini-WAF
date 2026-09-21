# Protection levels & rule selection

Two mechanisms decide which rules actually run: the **protection level**
(coarse, by risk appetite) and **id filters** (surgical, by name). They compose.

## Levels

Order: `low` < `balanced` < `high` < `paranoid`. Default: **`balanced`**.

Each rule declares a `minLevel`; it runs only when the configured `level` is
**greater than or equal** to it. Rules without an explicit `minLevel` are
treated as `low`, i.e. active at every level.

| Level | Rules (`default`) | Includes | Typical use | ≈ CRS PL |
|-------|-------------------|----------|-------------|----------|
| `low` | 19 | Obvious scanners (UA), classic SQLi + DBMS primitives, plain & encoded traversal / LFI, stream-wrapper RFI, PHP RCE, shell RCE, JNDI/Log4Shell, reverse shells, fetch-and-exec, Windows LOLBins, SSRF metadata | APIs sensitive to false positives | PL1 (core) |
| `balanced` (default) | 51 | `low` + XSS (incl. encoded tags, `data:` URIs, attribute vectors, path), SQLi tautologies & `SELECT … FROM`, NoSQL operators (quoted & unquoted), uploads & extension bypass, remote-URL RFI, SSTI, FreeMarker, Node/lang exec, deserialization (binary & YAML), null-byte, DoS rate-limit, protocol splitting/smuggling, encoded & double-encoded CRLF | General production | PL1–PL2 |
| `high` | 78 | `balanced` + SSI, hex flood, prototype pollution, advanced/blind/boolean-equality/compact-subquery/JSON SQLi, NoSQL driver API, LDAP filter & matching-rule, XXE, mail command injection, UNC paths, XSS JS primitives, indirect & breakout sink calls, CL+TE, shell `$()`/`${IFS}`, session ID in URL | Under attack / broader coverage | PL2 |
| `paranoid` | 89 | `high` + broad UAs, generic HTML tags, empty UA, shebang, oversized headers, internal-host SSRF, GraphQL introspection, ASP concat obfuscation, NoSQL `$where` time-bomb, CRLF-less mail verbs | Max coverage; more FPs | PL3–PL4 |

Counts assume `presets: ['default']`. Cost tracks rule count roughly linearly,
so the level is also your main performance dial — see
[Performance](/guide/performance).

## Gating your own rules

`minLevel` on a custom rule lets one config behave differently per environment:

```ts
import { expressWaf } from 'mini-waf/express';

app.use(
  expressWaf({
    level: 'high',
    presets: ['default'],
    rules: [
      {
        id: 'strict-debug-flag',
        // Only enforced at 'high' or 'paranoid'; inert at 'low'/'balanced',
        // so staging can keep using ?debug=1 while production cannot.
        minLevel: 'high',
        action: 'block',
        when: { field: 'query.debug', equals: '1' },
        reason: 'Debug flag blocked at high+ protection level',
      },
      {
        // No minLevel — defaults to 'low', so this runs at every level.
        id: 'always-block-internal-header-spoof',
        action: 'block',
        when: { field: 'headers.x-internal-auth', matches: /^.+$/ },
        reason: 'Client attempted to spoof an internal-only header',
      },
    ],
  }),
);
```

## How the active list is built

`buildRuleList` (`src/engine/engine.ts`) applies these steps **in this exact
order**:

1. Resolve `presets` + custom `rules` (presets first, deduped by `id`)
2. Filter by `level` vs each rule's `minLevel`
3. Apply `enabledRuleIds` — only if present **and non-empty** (allowlist)
4. Apply `disabledRuleIds` (denylist)
5. Drop `enabled: false`, then sort by `priority`

Two consequences worth remembering:

- Custom rules share the id namespace with presets, so `disabledRuleIds` can
  target either. Avoid naming your own rules `preset-*`.
- An **empty** `enabledRuleIds` is a no-op, not "block nothing" — you cannot
  accidentally disable every rule with an empty array.

## Enable / disable by id

```ts
createMiniWaf({
  presets: ['default'],
  level: 'balanced',
  // Turn off specific preset rules that produce false positives here...
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
      // `action: 'log'` never blocks — it collects into
      // WafEvaluationResult.loggedRules and, when logging is on at 'info'+,
      // is emitted via WafLogger.audit(ctx, rule).
      id: 'log-suspicious-referrer',
      action: 'log',
      when: { field: 'headers.referer', includes: 'pastebin' },
      reason: 'Referrer includes pastebin — audit only, not blocked',
    },
  ],
});
```

Rules of thumb:

- `disabledRuleIds` for **"keep everything except X"** — the common case.
- `enabledRuleIds` for **"keep only X"** — a deliberately tiny policy.
- Mixing both is legal: the allowlist applies first, the denylist narrows it.

Every built-in id, with what it catches and its `minLevel`, is listed in
[Presets](/guide/presets).

## Choosing a level

Dial coverage in this order:

1. **`level`** — the blunt instrument, and the one that also buys performance.
2. **Narrow `presets`** — drop whole packs you do not need (`rfi` on a
   Node-only API, `protocol` behind a strict reverse proxy).
3. **`disabledRuleIds`** — remove the two or three rules your traffic trips.
4. **Early `allow` rules** — carve out known-good routes.

Start one level *above* what you intend to deploy, measure against real traffic,
then settle. See [Security notes](/guide/security) for the false-positive
sources to look for.
