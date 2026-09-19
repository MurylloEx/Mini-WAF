# Logging

Logging is **disabled by default** so production paths do no console I/O and no formatting. When off, the engine never calls the logger — `resolveEngineLogger` (`src/engine/engine.ts`) returns `silentLogger`, whose three methods are no-ops, so there is zero allocation cost for `blocked`/`audit`/`connection` calls that would otherwise happen on every request.

## Settings

| Setting | Behavior |
|---------|----------|
| omitted / `false` | Silent (default) |
| `true` | Plain console at level `info` (blocks + audit) |
| `{ level, sink? }` | Structured options |

### Levels (`WafLogLevel`)

| Level | Emits |
|-------|-------|
| `error` | Blocks only |
| `info` | Blocks + audit (`log` action rules) |
| `debug` | Above + connection events |

No color libraries — console output is plain text. File sinks are not built-in; pass a custom `sink` if you need them.

## The `WafLogger` port

```ts
// src/logging/port.ts
interface WafLogger {
  blocked(ctx: WafHttpContext, rule: WafRule): void;  // fired once, right after ctx.drop(...)
  audit(ctx: WafHttpContext, rule: WafRule): void;     // fired per matched `log`-action rule
  connection(ctx: WafHttpContext): void;               // fired on a clean allow (no matched rule)
}
```

Each method is called from `resultFromScan` in `src/engine/engine.ts`, gated by `emitIfLevel(resolved.logging, minimumLevel, emit)` — so even with logging enabled, `connection` is skipped unless `level: 'debug'`, and `audit` is skipped unless `level: 'info'` or `'debug'`.

## Custom sink integrating a real logging library

The example below shapes a sink around `pino`'s API (`logger.info(obj, msg)`), which generalizes directly to any structured logger (`winston`, `bunyan`, or a plain `console`-based JSON emitter) since `WafLogger` only needs three plain functions.

```ts
import pino from 'pino';
import type { WafLogger } from 'mini-waf';
import { expressWaf } from 'mini-waf/express';

const log = pino({ level: 'info', name: 'mini-waf' });

const pinoSink: WafLogger = {
  // Triggered once per blocked request, right after `ctx.drop()` ran —
  // the response has already been ended by the time this fires, so this
  // is purely for observability, not for altering the response.
  blocked: (ctx, rule) => {
    log.warn(
      {
        event: 'waf.blocked',
        ruleId: rule.id,
        reason: rule.reason ?? rule.id,
        ip: ctx.getIp(),
        method: ctx.getMethod(),
        path: ctx.getPath(),
      },
      'Mini-WAF blocked a request',
    );
  },
  // Triggered per `action: 'log'` rule that matched on an otherwise-allowed
  // request. Use this for "watch, don't block yet" rules while you tune FPs.
  audit: (ctx, rule) => {
    log.info(
      { event: 'waf.audit', ruleId: rule.id, ip: ctx.getIp(), path: ctx.getPath() },
      rule.reason ?? `Audit match: ${rule.id}`,
    );
  },
  // Triggered on every clean allow, only at level 'debug' — high-volume by
  // design, so most deployments should NOT enable 'debug' in production.
  connection: (ctx) => {
    log.debug(
      { event: 'waf.connection', ip: ctx.getIp(), ua: ctx.getHeader('user-agent') },
      'connection',
    );
  },
};

app.use(
  expressWaf({
    presets: ['default'],
    level: 'balanced',
    // 'info' → blocked + audit are emitted; 'debug' would add connection too.
    logging: { level: 'info', sink: pinoSink },
  }),
);
```

### Console-based structured logger (no dependency)

If you do not want a logging library dependency at all, the same shape works with plain `console` calls emitting single-line JSON — easy to pipe into `jq` or a log aggregator that parses JSON lines:

```ts
import type { WafLogger } from 'mini-waf';

function structuredConsoleLogger(): WafLogger {
  const emit = (level: 'warn' | 'info' | 'debug', event: string, fields: Record<string, unknown>) => {
    // One JSON object per line — trivially parseable by most log shippers.
    console[level](JSON.stringify({ ts: new Date().toISOString(), event, ...fields }));
  };

  return {
    blocked: (ctx, rule) =>
      emit('warn', 'waf.blocked', { ruleId: rule.id, reason: rule.reason, ip: ctx.getIp(), path: ctx.getPath() }),
    audit: (ctx, rule) =>
      emit('info', 'waf.audit', { ruleId: rule.id, ip: ctx.getIp(), path: ctx.getPath() }),
    connection: (ctx) =>
      emit('debug', 'waf.connection', { ip: ctx.getIp(), method: ctx.getMethod() }),
  };
}

expressWaf({
  presets: ['default'],
  logging: { level: 'info', sink: structuredConsoleLogger() },
});
```

## What triggers each log entry

| Sink method | Triggered when | Minimum `level` to emit |
|---|---|---|
| `blocked` | A `block`-action rule matched and no earlier `allow` short-circuited the scan; `ctx.drop(statusCode, body)` already ran | `error` |
| `audit` | One or more `action: 'log'` rules matched on a request that ultimately resolved to `allow` | `info` |
| `connection` | The request resolved to `allow` with **no** matched rule at all (or an explicit `allow`-action match) — i.e. "nothing to report, just a normal request" | `debug` |

Because `error` is the least verbose level and still includes `blocked`, a production deployment that only cares about "what did the WAF block" should use `logging: { level: 'error' }` (or `true`, which defaults to `'info'` and therefore also includes audit events) rather than `'debug'`, which adds a log line for *every allowed request*.

## Engine options logger

You can also pass `{ logger }` in the second argument to `createMiniWaf` / `expressWaf` / `fastifyWaf` / `nestMiddleware` — it is used only when `logging` is enabled, and takes priority over `logging.sink`:

```ts
import { createMiniWaf } from 'mini-waf';

const waf = createMiniWaf(
  { presets: ['default'], logging: { level: 'info' } },
  { logger: pinoSink }, // WafEngineOptions.logger
);
```

Resolution order for the sink (`pickLoggerSink`, `src/logging/port.ts`): options `logger` → `logging.sink` → plain console (`createConsoleLogger()`) when logging is enabled without an explicit sink, or `silentLogger` when logging is disabled entirely.

## Built-in plain console logger

`createConsoleLogger()` (used automatically when `logging: true` or `logging: { level }` without a `sink`) formats each event as multi-line, human-readable text — meant for local development, not production log pipelines:

```
-> Mini-WAF blocked a request
   IP: 203.0.113.7 at 9/19/2026, 4:22:10 PM
   Rule: preset-sqli-classic-query
   Reason: Possible SQL injection
   Method: GET
   Path: /search
   Event: 0x...
```

## Helpers exported from `mini-waf`

- `createConsoleLogger`
- `silentLogger`
- `resolveLogging`
- `pickLoggerSink`
- `isLogLevelActive` / `isWafLogLevel`
- Types: `WafLogger`, `WafLogLevel`, `WafLoggingOptions`, `WafLoggingSetting`, `ResolvedLogging`
