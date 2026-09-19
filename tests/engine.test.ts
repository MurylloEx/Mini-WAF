import { describe, expect, it } from 'vitest';
import { createWafEngine, scanRules } from '@/engine/engine';
import { emptyRateLimitState } from '@/engine/rate-limit';
import type { WafRule } from '@/domain/rules';
import { createMockContext } from './helpers/mock-context';

const blockSql: WafRule = {
  id: 'block-sqli',
  action: 'block',
  reason: 'Possible SQL injection',
  when: { field: 'query.id', matches: /('|OR\s+1=1)/i },
};

const allowLocal: WafRule = {
  id: 'allow-local',
  action: 'allow',
  priority: 1,
  when: { field: 'ip', equals: '127.0.0.1' },
};

const logUa: WafRule = {
  id: 'log-ua',
  action: 'log',
  priority: 10,
  when: { field: 'headers.user-agent', includes: 'curl' },
};

describe('engine block/allow', () => {
  it('blocks matching malicious query', async () => {
    const engine = createWafEngine(
      { rules: [blockSql] },
    );
    const mock = createMockContext({
      query: { id: "1' OR 1=1" },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('block-sqli');
    expect(mock.ctx.isBlocked()).toBe(true);
  });

  it('allows when no rule matches', async () => {
    const engine = createWafEngine(
      { rules: [blockSql] },
    );
    const mock = createMockContext({ query: { id: '42' } });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('allow');
    expect(result.matchedRule).toBeUndefined();
  });

  it('short-circuits on allow with higher priority', async () => {
    const engine = createWafEngine(
      { rules: [blockSql, allowLocal] },
    );
    const mock = createMockContext({
      ip: '127.0.0.1',
      query: { id: "1' OR 1=1" },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('allow');
    expect(result.matchedRule?.id).toBe('allow-local');
    expect(mock.ctx.isBlocked()).toBe(false);
  });

  it('collects log rules without blocking', async () => {
    const engine = createWafEngine(
      { rules: [logUa] },
    );
    const mock = createMockContext({
      headers: { 'user-agent': 'curl/8.0' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('allow');
    expect(result.loggedRules.map((r) => r.id)).toEqual(['log-ua']);
  });
});

describe('scanRules immutability', () => {
  it('does not mutate the input rules array', () => {
    const rules: readonly WafRule[] = [blockSql, logUa];
    const frozen = Object.freeze([...rules]);
    const mock = createMockContext({
      query: { id: 'safe' },
      headers: { 'user-agent': 'curl' },
    });
    const scan = scanRules(mock.ctx, frozen, emptyRateLimitState());
    expect(frozen).toHaveLength(2);
    expect(scan.loggedRules).toHaveLength(1);
    expect(scan.loggedRules).not.toBe(frozen);
  });
});

describe('rate limit rule', () => {
  it('blocks after exceeding max', async () => {
    const rule: WafRule = {
      id: 'rate-limit',
      action: 'block',
      reason: 'Too many requests',
      when: { field: 'ip', rateLimit: { max: 2, windowMs: 60_000 } },
    };
    const engine = createWafEngine(
      { rules: [rule] },
    );

    const r1 = await engine.handle(createMockContext({ ip: '10.0.0.1' }).ctx);
    const r2 = await engine.handle(createMockContext({ ip: '10.0.0.1' }).ctx);
    const r3 = await engine.handle(createMockContext({ ip: '10.0.0.1' }).ctx);

    expect(r1.decision).toBe('allow');
    expect(r2.decision).toBe('allow');
    expect(r3.decision).toBe('block');
  });
});
