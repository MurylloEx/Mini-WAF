import type { WafHttpContext } from '@/domain/context';
import type { WafRule } from '@/domain/rules';

/**
 * Logging port — side effects live behind this interface so the
 * matching/decision core stays free of I/O when logging is off.
 */
export interface WafLogger {
  readonly blocked: (ctx: WafHttpContext, rule: WafRule) => void;
  readonly audit: (ctx: WafHttpContext, rule: WafRule) => void;
  readonly connection: (ctx: WafHttpContext) => void;
}

/** No-op logger — zero I/O, zero formatting. */
export const silentLogger: WafLogger = {
  blocked: () => undefined,
  audit: () => undefined,
  connection: () => undefined,
};

/** Verbosity when logging is enabled. */
export type WafLogLevel = 'error' | 'info' | 'debug';

/**
 * Structured logging options.
 * - `level` — default `'info'` (`error` = blocks only; `info` = blocks + audit; `debug` = + connections)
 * - `sink` — injectable {@link WafLogger} (defaults to plain console)
 */
export interface WafLoggingOptions {
  readonly level?: WafLogLevel;
  readonly sink?: WafLogger;
}

/**
 * `false` / omitted — logging off (default).
 * `true` — console logger at `info`.
 * object — level + optional custom sink.
 */
export type WafLoggingSetting = boolean | WafLoggingOptions;

export interface ResolvedLogging {
  readonly enabled: boolean;
  readonly level: WafLogLevel;
}

const LOG_LEVEL_RANK: Readonly<Record<WafLogLevel, number>> = {
  error: 0,
  info: 1,
  debug: 2,
};

export function isWafLogLevel(value: string): value is WafLogLevel {
  return value === 'error' || value === 'info' || value === 'debug';
}

/** True when the configured level is at least as verbose as `minimum`. */
export function isLogLevelActive(
  configured: WafLogLevel,
  minimum: WafLogLevel,
): boolean {
  return LOG_LEVEL_RANK[configured] >= LOG_LEVEL_RANK[minimum];
}

/**
 * Resolve `WafConfig.logging` into a stable enabled/level pair.
 * Default: disabled.
 */
export function resolveLogging(
  setting: WafLoggingSetting | undefined,
): ResolvedLogging {
  if (setting === undefined || setting === false) {
    return { enabled: false, level: 'info' };
  }
  if (setting === true) {
    return { enabled: true, level: 'info' };
  }
  return {
    enabled: true,
    level: setting.level ?? 'info',
  };
}

/** Pick the sink: options.logger > logging.sink > fallback (caller supplies console/silent). */
export function pickLoggerSink(
  setting: WafLoggingSetting | undefined,
  optionsLogger: WafLogger | undefined,
  fallback: WafLogger,
): WafLogger {
  if (optionsLogger !== undefined) {
    return optionsLogger;
  }
  if (
    setting !== undefined &&
    setting !== false &&
    setting !== true &&
    setting.sink !== undefined
  ) {
    return setting.sink;
  }
  return fallback;
}
