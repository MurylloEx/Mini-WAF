import type { WafHttpContext } from '@/domain/context';
import type { WafRule } from '@/domain/rules';
import type { WafLogger } from '@/logging/port';
import { silentLogger } from '@/logging/port';

function eventCode(): string {
  return `0x${(Date.now() + Math.floor(1e9 * Math.random())).toString(16)}`;
}

export interface ConsoleLoggerOptions {
  /** When false, returns {@link silentLogger}. Default: true. */
  readonly enabled?: boolean;
}

function formatBlocked(ctx: WafHttpContext, rule: WafRule): string {
  const reason = rule.reason ?? rule.id;
  return [
    '-> Mini-WAF blocked a request',
    `   IP: ${ctx.getIp()} at ${new Date().toLocaleString()}`,
    `   Rule: ${rule.id}`,
    `   Reason: ${reason}`,
    `   Method: ${ctx.getMethod()}`,
    `   Path: ${ctx.getPath()}`,
    `   Event: ${eventCode()}`,
  ].join('\n');
}

function formatAudit(ctx: WafHttpContext, rule: WafRule): string {
  const reason = rule.reason ?? rule.id;
  return [
    '-> Mini-WAF audit event',
    `   IP: ${ctx.getIp()} at ${new Date().toLocaleString()}`,
    `   Rule: ${rule.id}`,
    `   Reason: ${reason}`,
    `   Method: ${ctx.getMethod()}`,
    `   Event: ${eventCode()}`,
  ].join('\n');
}

function formatConnection(ctx: WafHttpContext): string {
  const ua = ctx.getHeader('user-agent') ?? '';
  return `[${new Date().toLocaleTimeString()}] [${ctx.getProtocol().toUpperCase()} ${ctx.getMethod()}] [INFO] connection from [${ctx.getIp()}] ua=[${ua}].`;
}

/**
 * Plain-console logger (no color deps, no file I/O).
 * Prefer leaving `WafConfig.logging` off in production.
 */
export function createConsoleLogger(
  options: ConsoleLoggerOptions = {},
): WafLogger {
  if (options.enabled === false) {
    return silentLogger;
  }

  return {
    blocked(ctx, rule) {
      console.log(formatBlocked(ctx, rule));
    },
    audit(ctx, rule) {
      console.log(formatAudit(ctx, rule));
    },
    connection(ctx) {
      console.log(formatConnection(ctx));
    },
  };
}

export { silentLogger } from '@/logging/port';
export type {
  WafLogger,
  WafLogLevel,
  WafLoggingOptions,
  WafLoggingSetting,
  ResolvedLogging,
} from '@/logging/port';
export {
  resolveLogging,
  pickLoggerSink,
  isLogLevelActive,
  isWafLogLevel,
} from '@/logging/port';
