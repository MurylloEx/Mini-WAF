import { describe, expect, it, vi } from 'vitest';
import { createWafEngine } from '@/engine/engine';
import type { WafLogger } from '@/logging/port';
import type { WafRule } from '@/domain/rules';
import { createMockContext } from './helpers/mock-context';

const blockSql: WafRule = {
  id: 'block-sqli',
  action: 'block',
  reason: 'Possible SQL injection',
  when: { field: 'query.id', matches: /('|OR\s+1=1)/i },
};

const logUa: WafRule = {
  id: 'log-ua',
  action: 'log',
  when: { field: 'headers.user-agent', includes: 'curl' },
};

function trackingLogger(): {
  readonly logger: WafLogger;
  readonly blocked: ReturnType<typeof vi.fn>;
  readonly audit: ReturnType<typeof vi.fn>;
  readonly connection: ReturnType<typeof vi.fn>;
} {
  const blocked = vi.fn();
  const audit = vi.fn();
  const connection = vi.fn();
  return {
    blocked,
    audit,
    connection,
    logger: { blocked, audit, connection },
  };
}

describe('logging (off by default)', () => {
  it('does not call logger when logging is omitted', async () => {
    const track = trackingLogger();
    const engine = createWafEngine(
      { rules: [blockSql] },
      { logger: track.logger },
    );
    await engine.handle(
      createMockContext({ query: { id: "1' OR 1=1" } }).ctx,
    );
    expect(engine.config.logging.enabled).toBe(false);
    expect(track.blocked).not.toHaveBeenCalled();
    expect(track.audit).not.toHaveBeenCalled();
    expect(track.connection).not.toHaveBeenCalled();
  });

  it('does not call logger when logging is false', async () => {
    const track = trackingLogger();
    const engine = createWafEngine(
      { rules: [blockSql], logging: false },
      { logger: track.logger },
    );
    await engine.handle(
      createMockContext({ query: { id: "1' OR 1=1" } }).ctx,
    );
    expect(track.blocked).not.toHaveBeenCalled();
  });

  it('calls blocked on logging: true', async () => {
    const track = trackingLogger();
    const engine = createWafEngine(
      { rules: [blockSql], logging: true },
      { logger: track.logger },
    );
    await engine.handle(
      createMockContext({ query: { id: "1' OR 1=1" } }).ctx,
    );
    expect(engine.config.logging.enabled).toBe(true);
    expect(engine.config.logging.level).toBe('info');
    expect(track.blocked).toHaveBeenCalledOnce();
  });

  it('calls audit at info level for log-action rules', async () => {
    const track = trackingLogger();
    const engine = createWafEngine(
      { rules: [logUa], logging: { level: 'info', sink: track.logger } },
    );
    await engine.handle(
      createMockContext({ headers: { 'user-agent': 'curl/8' } }).ctx,
    );
    expect(track.audit).toHaveBeenCalledOnce();
    expect(track.connection).not.toHaveBeenCalled();
  });

  it('logs connections only at debug', async () => {
    const track = trackingLogger();
    const engine = createWafEngine(
      {
        rules: [blockSql],
        logging: { level: 'debug', sink: track.logger },
      },
    );
    await engine.handle(createMockContext({ query: { id: '42' } }).ctx);
    expect(track.connection).toHaveBeenCalledOnce();
    expect(track.blocked).not.toHaveBeenCalled();
  });

  it('error level skips audit but still logs blocks', async () => {
    const track = trackingLogger();
    const engine = createWafEngine({
      rules: [logUa, blockSql],
      logging: { level: 'error', sink: track.logger },
    });
    await engine.handle(
      createMockContext({
        query: { id: "1' OR 1=1" },
        headers: { 'user-agent': 'curl' },
      }).ctx,
    );
    expect(track.blocked).toHaveBeenCalledOnce();
    expect(track.audit).not.toHaveBeenCalled();
  });
});
