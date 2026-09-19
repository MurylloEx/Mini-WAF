import { describe, expect, it, beforeEach } from 'vitest';
import { RateLimitStore } from '@/engine/rate-limit';
import {
  createWafEngine,
  scanRulesAsync,
  DEFAULT_MAX_FIELD_LENGTH,
} from '@/engine/engine';
import {
  resolveFieldValues,
  resolveFieldValuesLower,
} from '@/engine/field-resolver';
import { LruCache } from '@/utils/lru';
import {
  clearIpNormalizeCache,
  ipNormalizeCacheSize,
  normalizeClientIp,
} from '@/utils/ip';
import type { WafField, WafRule } from '@/domain/rules';
import { createMockContext } from './helpers/mock-context';

describe('maxFieldLength', () => {
  it('defaults to a production-safe cap on the engine', () => {
    const engine = createWafEngine({ rules: [] });
    expect(engine.config.performance.maxFieldLength).toBe(
      DEFAULT_MAX_FIELD_LENGTH,
    );
    expect(DEFAULT_MAX_FIELD_LENGTH).toBe(8_192);
  });

  it('allows unlimited scan when explicitly set to 0', () => {
    const engine = createWafEngine({ maxFieldLength: 0, rules: [] });
    expect(engine.config.performance.maxFieldLength).toBe(0);
  });

  it('truncates body candidates before matching', () => {
    const mock = createMockContext({
      body: `SAFE${'A'.repeat(200)}UNION SELECT`,
    });
    const full = resolveFieldValues(mock.ctx, 'body', { maxFieldLength: 0 });
    const capped = resolveFieldValues(mock.ctx, 'body', { maxFieldLength: 10 });
    expect(full[0]?.includes('UNION')).toBe(true);
    expect(capped[0]).toBe('SAFEAAAAAA');
    expect(capped[0]?.length).toBe(10);
  });

  it('does not block when the attack signature is beyond the scan window', async () => {
    const engine = createWafEngine({
      maxFieldLength: 8,
      rules: [
        {
          id: 'block-union',
          action: 'block',
          when: { field: 'body', includes: 'UNION' },
        },
      ],
    });
    const mock = createMockContext({
      body: `${'x'.repeat(20)}UNION SELECT`,
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('allow');
  });

  it('still blocks when the signature sits inside the truncated window', async () => {
    const engine = createWafEngine({
      maxFieldLength: 64,
      rules: [
        {
          id: 'block-union',
          action: 'block',
          when: { field: 'body', includes: 'UNION' },
        },
      ],
    });
    const mock = createMockContext({
      body: `UNION SELECT ${'x'.repeat(500)}`,
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
  });

  it('default cap still blocks signatures near the start of a huge body', async () => {
    const engine = createWafEngine({
      rules: [
        {
          id: 'block-union',
          action: 'block',
          when: { field: 'body', includes: 'UNION' },
        },
      ],
    });
    const mock = createMockContext({
      body: `UNION SELECT ${'x'.repeat(50_000)}`,
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
  });
});

describe('includes lowercase memo', () => {
  it('memoizes lowercased bag values across lookups', () => {
    const mock = createMockContext({
      query: { a: 'Hello', b: 'WORLD' },
    });
    const memo = new Map<WafField, readonly string[]>();
    const memoLower = new Map<WafField, readonly string[]>();
    const options = { maxFieldLength: 0, memo, memoLower };

    const first = resolveFieldValuesLower(mock.ctx, 'query', options);
    const second = resolveFieldValuesLower(mock.ctx, 'query', options);

    expect(first).toEqual(['hello', 'world']);
    expect(second).toBe(first);
    expect(memoLower.get('query')).toBe(first);
  });

  it('matches includes case-insensitively after rule normalize', async () => {
    const engine = createWafEngine({
      maxFieldLength: 0,
      rules: [
        {
          id: 'block-curl',
          action: 'block',
          when: { field: 'headers.user-agent', includes: 'CuRl' },
        },
      ],
    });
    const mock = createMockContext({
      headers: { 'user-agent': 'curl/8.0' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(engine.rules[0]?.when).toMatchObject({
      field: 'headers.user-agent',
      includes: 'curl',
    });
  });
});

describe('ruleYieldEvery', () => {
  it('still blocks correctly when yielding every rule', async () => {
    const filler: WafRule[] = Array.from({ length: 40 }, (_, index) => ({
      id: `filler-${index}`,
      action: 'log',
      when: { field: 'path', equals: '/never' },
    }));
    const blockSql: WafRule = {
      id: 'block-sqli',
      action: 'block',
      reason: 'sqli',
      when: { field: 'query.id', matches: /OR\s+1=1/i },
    };
    const engine = createWafEngine({
      ruleYieldEvery: 1,
      rules: [...filler, blockSql],
    });
    const mock = createMockContext({
      query: { id: '1 OR 1=1' },
    });
    const result = await engine.handle(mock.ctx);
    expect(result.decision).toBe('block');
    expect(result.matchedRule?.id).toBe('block-sqli');
  });

  it('scanRulesAsync preserves allow short-circuit with yields', async () => {
    const rules: readonly WafRule[] = [
      {
        id: 'allow-health',
        priority: 1,
        action: 'allow',
        when: { field: 'path', equals: '/health' },
      },
      {
        id: 'block-all',
        action: 'block',
        when: { field: 'path', includes: '/' },
      },
    ];
    const mock = createMockContext({ path: '/health' });
    const scan = await scanRulesAsync(mock.ctx, rules, {
      ruleYieldEvery: 1,
      rateLimits: new RateLimitStore(),
      evaluate: { fields: { maxFieldLength: 0 } },
    });
    expect(scan.allowRule?.id).toBe('allow-health');
    expect(scan.blockCandidate).toBeUndefined();
  });

  it('skips yielding for packs smaller than ruleYieldEvery', async () => {
    const rules: readonly WafRule[] = [
      {
        id: 'block-admin',
        action: 'block',
        when: { field: 'path', equals: '/admin' },
      },
    ];
    const mock = createMockContext({ path: '/admin' });
    const scan = await scanRulesAsync(mock.ctx, rules, {
      ruleYieldEvery: 32,
      rateLimits: new RateLimitStore(),
      evaluate: { fields: { maxFieldLength: 0 } },
    });
    expect(scan.blockCandidate?.id).toBe('block-admin');
  });
});

describe('rate limit with async scan', () => {
  it('still counts and blocks after exceeding max when yielding', async () => {
    const rule: WafRule = {
      id: 'rate-limit',
      action: 'block',
      reason: 'Too many requests',
      when: { field: 'ip', rateLimit: { max: 2, windowMs: 60_000 } },
    };
    const engine = createWafEngine({
      ruleYieldEvery: 1,
      rules: [rule],
    });

    const r1 = await engine.handle(createMockContext({ ip: '10.0.0.9' }).ctx);
    const r2 = await engine.handle(createMockContext({ ip: '10.0.0.9' }).ctx);
    const r3 = await engine.handle(createMockContext({ ip: '10.0.0.9' }).ctx);

    expect(r1.decision).toBe('allow');
    expect(r2.decision).toBe('allow');
    expect(r3.decision).toBe('block');
  });

  it('does not lose counters under concurrent handle + yields', async () => {
    const fillers: WafRule[] = Array.from({ length: 8 }, (_, index) => ({
      id: `filler-${index}`,
      action: 'log',
      when: { field: 'path', equals: '/never' },
    }));
    const engine = createWafEngine({
      ruleYieldEvery: 1,
      rules: [
        ...fillers,
        {
          id: 'rate-limit',
          action: 'block',
          when: { field: 'ip', rateLimit: { max: 5, windowMs: 60_000 } },
        },
      ],
    });

    const results = await Promise.all(
      Array.from({ length: 6 }, () =>
        engine.handle(createMockContext({ ip: '10.9.9.9' }).ctx),
      ),
    );

    const allows = results.filter((r) => r.decision === 'allow').length;
    const blocks = results.filter((r) => r.decision === 'block').length;
    expect(allows).toBe(5);
    expect(blocks).toBe(1);
  });

  it('caps distinct rate-limit keys via maxRateLimitKeys', async () => {
    const engine = createWafEngine({
      maxRateLimitKeys: 2,
      rules: [
        {
          id: 'rate-limit',
          action: 'block',
          when: { field: 'ip', rateLimit: { max: 1, windowMs: 60_000 } },
        },
      ],
    });

    await engine.handle(createMockContext({ ip: '10.0.0.1' }).ctx);
    await engine.handle(createMockContext({ ip: '10.0.0.2' }).ctx);
    await engine.handle(createMockContext({ ip: '10.0.0.3' }).ctx);
    expect(engine.rateLimitStore.size()).toBe(2);
    expect(engine.config.performance.maxRateLimitKeys).toBe(2);
  });

  it('does not use decision cache when rateLimit rules are present', async () => {
    const engine = createWafEngine({
      decisionCache: { max: 32, ttlMs: 60_000 },
      rules: [
        {
          id: 'rate-limit',
          action: 'block',
          when: { field: 'ip', rateLimit: { max: 1, windowMs: 60_000 } },
        },
      ],
    });

    const first = await engine.handle(createMockContext({ ip: '10.1.1.1' }).ctx);
    const second = await engine.handle(createMockContext({ ip: '10.1.1.1' }).ctx);

    expect(first.decision).toBe('allow');
    expect(second.decision).toBe('block');
  });
});

describe('decisionCache LRU', () => {
  it('reuses allow/block for identical fingerprints', async () => {
    const engine = createWafEngine({
      decisionCache: { max: 16, ttlMs: 60_000 },
      rules: [
        {
          id: 'block-admin',
          action: 'block',
          when: { field: 'path', equals: '/admin' },
        },
      ],
    });

    const first = await engine.handle(
      createMockContext({ path: '/admin', ip: '10.2.2.2' }).ctx,
    );
    const second = await engine.handle(
      createMockContext({ path: '/admin', ip: '10.2.2.2' }).ctx,
    );

    expect(first.decision).toBe('block');
    expect(second.decision).toBe('block');
    expect(second.matchedRule?.id).toBe('block-admin');
  });
});

describe('LruCache + IP normalize cache', () => {
  beforeEach(() => {
    clearIpNormalizeCache();
  });

  it('evicts the least-recently used entry', () => {
    const cache = new LruCache<string>(2);
    cache.set('a', '1');
    cache.set('b', '2');
    expect(cache.get('a')).toBe('1'); // refresh a
    cache.set('c', '3'); // evicts b
    expect(cache.get('b')).toBeUndefined();
    expect(cache.get('a')).toBe('1');
    expect(cache.get('c')).toBe('3');
  });

  it('memoizes normalizeClientIp results', () => {
    expect(ipNormalizeCacheSize()).toBe(0);
    const once = normalizeClientIp('::ffff:127.0.0.1');
    const twice = normalizeClientIp('::ffff:127.0.0.1');
    expect(once).toBe('127.0.0.1');
    expect(twice).toBe('127.0.0.1');
    expect(ipNormalizeCacheSize()).toBeGreaterThanOrEqual(1);
  });
});

describe('skip later pure blocks', () => {
  it('keeps the first block and still applies later rateLimit side effects', async () => {
    const rules: WafRule[] = [
      {
        id: 'block-first',
        action: 'block',
        when: { field: 'path', equals: '/x' },
      },
      {
        id: 'block-second-expensive',
        action: 'block',
        when: { field: 'body', matches: /./ },
      },
      {
        id: 'rate-limit-tail',
        action: 'block',
        when: { field: 'ip', rateLimit: { max: 1, windowMs: 60_000 } },
      },
    ];
    const engine = createWafEngine({ rules });

    const first = await engine.handle(
      createMockContext({ path: '/x', ip: '10.3.3.3', body: 'payload' }).ctx,
    );
    expect(first.decision).toBe('block');
    expect(first.matchedRule?.id).toBe('block-first');

    // Second request: rate-limit must have advanced on the first pass.
    const second = await engine.handle(
      createMockContext({ path: '/ok', ip: '10.3.3.3' }).ctx,
    );
    expect(second.decision).toBe('block');
    expect(second.matchedRule?.id).toBe('rate-limit-tail');
  });
});
