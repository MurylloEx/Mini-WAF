import { describe, expect, it } from 'vitest';
import {
  isHostIpLiteral,
  normalizeClientIp,
  pickClientIpFromXff,
} from '@/utils/ip';
import { createExpressAdapter } from '@/adapters/express.adapter';
import { createWafEngine } from '@/engine/engine';
import type { WafRule } from '@/domain/rules';
import { createMockContext } from './helpers/mock-context';

describe('normalizeClientIp', () => {
  it('trims and keeps IPv4', () => {
    expect(normalizeClientIp('  127.0.0.1  ')).toBe('127.0.0.1');
  });

  it('strips brackets around IPv6', () => {
    expect(normalizeClientIp('[2001:db8::1]')).toBe('2001:db8::1');
  });

  it('unifies IPv4-mapped IPv6 to dotted IPv4', () => {
    expect(normalizeClientIp('::ffff:127.0.0.1')).toBe('127.0.0.1');
    expect(normalizeClientIp('::FFFF:7f00:1')).toBe('127.0.0.1');
    expect(normalizeClientIp('[::ffff:192.0.2.10]')).toBe('192.0.2.10');
  });

  it('collapses equivalent IPv6 forms to one canonical value', () => {
    expect(normalizeClientIp('2001:0db8:0000:0000:0000:0000:0000:0001')).toBe(
      '2001:db8::1',
    );
    expect(normalizeClientIp('2001:db8::1')).toBe('2001:db8::1');
    expect(normalizeClientIp('::1')).toBe('::1');
    expect(normalizeClientIp('0:0:0:0:0:0:0:1')).toBe('::1');
  });

  it('strips IPv6 zone identifiers', () => {
    expect(normalizeClientIp('fe80::1%eth0')).toBe('fe80::1');
    expect(normalizeClientIp('[fe80::1%25eth0]')).toBe('fe80::1');
  });
});

describe('pickClientIpFromXff', () => {
  it('takes the first hop, trims spaces, and normalizes', () => {
    expect(pickClientIpFromXff('  ::ffff:127.0.0.1  , 10.0.0.1')).toBe(
      '127.0.0.1',
    );
    expect(pickClientIpFromXff(' [2001:db8::1] , 10.0.0.1')).toBe(
      '2001:db8::1',
    );
  });

  it('supports multi-value header arrays', () => {
    expect(pickClientIpFromXff(['  203.0.113.5 ', '10.0.0.1'])).toBe(
      '203.0.113.5',
    );
  });
});

describe('isHostIpLiteral', () => {
  it('detects IPv4 Host with optional port', () => {
    expect(isHostIpLiteral('127.0.0.1')).toBe(true);
    expect(isHostIpLiteral('127.0.0.1:8080')).toBe(true);
    expect(isHostIpLiteral('example.com')).toBe(false);
  });

  it('detects bracketed IPv6 Host with optional port', () => {
    expect(isHostIpLiteral('[2001:db8::1]')).toBe(true);
    expect(isHostIpLiteral('[2001:db8::1]:443')).toBe(true);
    expect(isHostIpLiteral('[::ffff:127.0.0.1]')).toBe(true);
  });
});

describe('adapters + rate-limit dual-stack', () => {
  it('Express XFF with spaces yields a normalized IP', async () => {
    const adapter = createExpressAdapter();
    const ctx = await Promise.resolve(
      adapter.createContext(
        {
          method: 'GET',
          url: '/',
          headers: {
            'x-forwarded-for': '  ::ffff:203.0.113.9 , 10.0.0.1',
          },
        },
        { end: () => undefined },
      ),
    );

    expect(ctx.getIp()).toBe('203.0.113.9');
  });

  it('unifies mapped IPv6 and IPv4 in rate-limit buckets', async () => {
    const rule: WafRule = {
      id: 'rate-limit',
      action: 'block',
      reason: 'Too many requests',
      when: { field: 'ip', rateLimit: { max: 2, windowMs: 60_000 } },
    };
    const engine = createWafEngine(
      { rules: [rule] },
    );

    const r1 = await engine.handle(
      createMockContext({ ip: '::ffff:10.0.0.1' }).ctx,
    );
    const r2 = await engine.handle(createMockContext({ ip: '10.0.0.1' }).ctx);
    const r3 = await engine.handle(createMockContext({ ip: '10.0.0.1' }).ctx);

    expect(r1.decision).toBe('allow');
    expect(r2.decision).toBe('allow');
    expect(r3.decision).toBe('block');
  });

  it('unifies equivalent IPv6 forms for equals matches', async () => {
    const rule: WafRule = {
      id: 'block-loopback-v6',
      action: 'block',
      reason: 'loopback',
      when: { field: 'ip', equals: '::1' },
    };
    const engine = createWafEngine(
      { rules: [rule] },
    );

    const result = await engine.handle(
      createMockContext({ ip: '0:0:0:0:0:0:0:1' }).ctx,
    );
    expect(result.decision).toBe('block');
  });
});
