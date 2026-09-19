# Custom rules

Compose rules in TypeScript or load them from JSON. Both end up as the same `WafRule` type passed through `WafConfig.rules`.

## Declarative DSL

```ts
import type { WafRule } from 'mini-waf';
import { expressWaf } from 'mini-waf/express';

const rules: WafRule[] = [
  {
    id: 'block-sqli-query',
    when: { field: 'query.id', matches: /('|OR\s+1=1)/i },
    action: 'block',
    reason: 'Possible SQL injection',
  },
  {
    id: 'rate-limit-ip',
    when: { field: 'ip', rateLimit: { max: 100, windowMs: 60_000 } },
    action: 'block',
    reason: 'Too many requests',
  },
  {
    id: 'allow-health',
    priority: 1, // lower = first; allow ends evaluation
    when: { field: 'path', equals: '/health' },
    action: 'allow',
  },
];

expressWaf({
  presets: ['default'],
  level: 'balanced',
  rules,
});
```

### Compounds

```ts
{
  id: 'block-admin-surface',
  action: 'block',
  reason: 'Admin path blocked at edge',
  when: {
    anyOf: [
      { field: 'path', equals: '/admin' },
      { field: 'path', matches: /^\/admin\// },
    ],
  },
}
```

Use `all` for AND and `not` for negation.

### Real case: admin path + User-Agent

```ts
expressWaf({
  presets: ['default'],
  level: 'balanced',
  rules: [
    {
      id: 'block-admin-surface',
      action: 'block',
      reason: 'Admin path blocked at edge',
      when: {
        anyOf: [
          { field: 'path', equals: '/admin' },
          { field: 'path', matches: /^\/admin\// },
        ],
      },
    },
    {
      id: 'block-bad-ua',
      action: 'block',
      reason: 'Known scanner UA',
      when: {
        field: 'headers.user-agent',
        matches: /sqlmap|nikto|acunetix/i,
      },
    },
    {
      id: 'allow-health',
      priority: 1,
      action: 'allow',
      when: { field: 'path', equals: '/health' },
    },
  ],
});
```

The same `rules` / `presets` / `level` work with Fastify (`config`) and Nest (`MiniWafModule.forRoot({ config })`).

## JSON / serializable format

`RegExp` and function predicates are not JSON-friendly. Use `JsonWafRule` (`SerializableWafRule`) and compile:

```ts
import { parseRulesFromJson, createMiniWaf } from 'mini-waf';
import { readFileSync } from 'node:fs';

const rules = parseRulesFromJson(readFileSync('./rules.json', 'utf8'));
const waf = createMiniWaf({ presets: ['default'], rules });
```

`loadRules` is also exported for loading from a path/source (see `src/engine/load-rules.ts`).

### `matches` in JSON

| Shape | Meaning |
|-------|---------|
| `"exact"` | Exact string equality (same as live `WafRule`) |
| `["a", "b"]` | OR list of exact strings |
| `{ "pattern": "...", "flags": "i" }` | Compiled to `RegExp` |

Top-level input may be a rule array or `{ "rules": [ ... ] }`. Invalid shapes throw `RuleParseError` with a JSON path.

See `examples/rules.example.json` in the repository. The DSL is **inspired by** practical CRS categories / field targeting — it is **not** a ModSecurity / full OWASP CRS parser.

## Composing with presets

Custom rules are merged **after** resolved presets (same id space for enable/disable filters). Prefer unique `id` values. Use `priority` so `allow` / early blocks run when you intend.

```ts
createMiniWaf({
  presets: ['sqli', 'xss'],
  level: 'balanced',
  disabledRuleIds: ['preset-xss-generic-tags'],
  rules: [/* your rules */],
});
```
