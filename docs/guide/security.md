# Security notes

Mini-WAF reduces common probe and injection noise at the edge of your Node app. It does not replace input validation, authz, TLS, dependency hygiene, or a network WAF/CDN.

## Choosing a protection level

| Level | When to use | False-positive risk |
|-------|-------------|---------------------|
| `low` | Public APIs with noisy legitimate query strings; start here if FPs hurt | Lowest |
| `balanced` | Default for general production | Moderate |
| `high` | Active probing / need broader SQLi & protocol coverage | Higher |
| `paranoid` | Temporary hardening or dedicated honeypot surfaces | Highest |

Dial coverage with **`level` first**, then **narrow `presets`**, then **`disabledRuleIds` / early `allow` rules** for known-good routes.

## False positives

Common sources:

- Broad UA / XSS / generic-tag rules at `high` / `paranoid`
- Bag fields (`query`, `body`) matching substrings that appear in legitimate content
- Admin or CMS paths that look like traversal or SSI

Mitigations:

```ts
expressWaf({
  presets: ['default'],
  level: 'balanced',
  disabledRuleIds: ['preset-scanners-ua-broad', 'preset-xss-generic-tags'],
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

## Body parsing & empty payloads

If body rules never fire, the WAF is usually **before** the body parser (or there is no parser). This is a security-coverage gap for POST/PUT payloads, not an engine bug — fix middleware order.

## Rate limiting

`preset-dos-rate-limit` and custom `rateLimit` conditions use an in-memory store capped by `maxRateLimitKeys`. That protects a **single Node process** from simple floods; it is not a distributed rate limiter. Place a reverse proxy / CDN limit in front for multi-instance deployments.

When any active rule has `rateLimit`, **`decisionCache` is disabled** so counters keep advancing.

## Regex & ReDoS

Truncation via `maxFieldLength` bounds haystack size. Still avoid pathological custom patterns (`(a+)+`, heavy overlapping alternations) on attacker-controlled input. Prefer `equals` / `includes` / string lists when sufficient.

## What presets do not cover

- Authenticated business-logic abuse
- Full OWASP CRS parity / ModSecurity rule language
- Encrypted or out-of-band channels
- Supply-chain / runtime sandboxing

Treat Mini-WAF as one layer in depth.

## Troubleshooting table

| Symptom | Common cause | What to do |
|---------|--------------|------------|
| Unexpected blocks / many FPs | `level` too high | Drop to `balanced` or `low`; narrow presets; `disabledRuleIds` or early `allow` |
| Body rule never fires | WAF before body parser | Parser before WAF |
| Health route blocked | Broad scanner rule | Whitelist with `action: 'allow'`, low `priority` |
| Nest does not block | Middleware not applied | `consumer.apply(MiniWafMiddleware).forRoutes('*')` |
