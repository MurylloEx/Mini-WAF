# Logging

Logging is **disabled by default** so production paths do no console I/O and no formatting. When off, the engine never calls the logger.

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

## Custom sink

```ts
import type { WafLogger } from 'mini-waf';
import { expressWaf } from 'mini-waf/express';

const sink: WafLogger = {
  blocked: (ctx, rule) => myMetrics.inc('waf_block', { rule: rule.id }),
  audit: () => undefined,
  connection: () => undefined,
};

expressWaf({
  presets: ['default'],
  logging: true,
  // or: logging: { level: 'debug', sink },
});
```

`WafLogger` port:

```ts
interface WafLogger {
  blocked(ctx: WafHttpContext, rule: WafRule): void;
  audit(ctx: WafHttpContext, rule: WafRule): void;
  connection(ctx: WafHttpContext): void;
}
```

## Engine options logger

You can also pass `{ logger }` in the second argument to `createMiniWaf` / `expressWaf` — it is used only when `logging` is enabled. Resolution order for the sink: options `logger` → `logging.sink` → console (or silent when disabled).

## Helpers exported from `mini-waf`

- `createConsoleLogger`
- `silentLogger`
- `resolveLogging`
- `pickLoggerSink`
- `isLogLevelActive` / `isWafLogLevel`
- Types: `WafLogger`, `WafLogLevel`, `WafLoggingOptions`, `WafLoggingSetting`
