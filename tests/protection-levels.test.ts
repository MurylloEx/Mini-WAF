import { describe, expect, it } from 'vitest';
import { createWafEngine, filterRulesByLevel } from '@/engine/engine';
import {
  DEFAULT_PROTECTION_LEVEL,
  isLevelActive,
  protectionLevelRank,
  type WafRule,
} from '@/domain';
import { createMockContext } from './helpers/mock-context';

describe('protection levels', () => {
  it('defaults to balanced', () => {
    const engine = createWafEngine(
      { presets: ['default'] },
    );
    expect(engine.config.level).toBe(DEFAULT_PROTECTION_LEVEL);
    expect(engine.config.level).toBe('balanced');
  });

  it('low does not include high-only rules', () => {
    const engine = createWafEngine(
      { presets: ['default'], level: 'low' },
    );
    const ids = engine.rules.map((r) => r.id);
    expect(ids).toContain('preset-scanners-ua');
    expect(ids).toContain('preset-path-traversal');
    expect(ids).toContain('preset-sqli-classic-query');
    expect(ids).not.toContain('preset-xss-query');
    expect(ids).not.toContain('preset-ssi-injection');
    expect(ids).not.toContain('preset-prototype-pollution');
    expect(ids).not.toContain('preset-sqli-advanced-query');
    expect(ids).not.toContain('preset-dangerous-upload');
  });

  it('balanced includes XSS but not SSI / pollution', () => {
    const engine = createWafEngine(
      { presets: ['default'], level: 'balanced' },
    );
    const ids = engine.rules.map((r) => r.id);
    expect(ids).toContain('preset-xss-query');
    expect(ids).toContain('preset-null-byte');
    expect(ids).toContain('preset-dangerous-upload');
    expect(ids).toContain('preset-protocol-response-splitting');
    expect(ids).toContain('preset-rce-ssti');
    expect(ids).toContain('preset-lfi-restricted-files');
    expect(ids).not.toContain('preset-ssi-injection');
    expect(ids).not.toContain('preset-prototype-pollution');
    expect(ids).not.toContain('preset-xss-eval-alert');
    expect(ids).not.toContain('preset-protocol-empty-ua');
  });

  it('high includes aggressive heuristics', () => {
    const engine = createWafEngine(
      { presets: ['default'], level: 'high' },
    );
    const ids = engine.rules.map((r) => r.id);
    expect(ids).toContain('preset-ssi-injection');
    expect(ids).toContain('preset-prototype-pollution');
    expect(ids).toContain('preset-hex-flood');
    expect(ids).toContain('preset-sqli-advanced-query');
    expect(ids).toContain('preset-protocol-cl-te-conflict');
    expect(ids).toContain('preset-rce-shell-expression');
    expect(ids).not.toContain('preset-scanners-ua-broad');
    expect(ids).not.toContain('preset-protocol-empty-ua');
  });

  it('paranoid includes legacy high-FP rules', () => {
    const engine = createWafEngine(
      { presets: ['default'], level: 'paranoid' },
    );
    const ids = engine.rules.map((r) => r.id);
    expect(ids).toContain('preset-scanners-ua-broad');
    expect(ids).toContain('preset-xss-generic-tags');
    expect(ids).toContain('preset-xss-eval-alert');
    expect(ids).toContain('preset-shebang');
    expect(ids).toContain('preset-excessive-header');
    expect(ids).toContain('preset-protocol-empty-ua');
  });

  it('low includes high-signal RCE / LFI derived from CRS PL1', () => {
    const engine = createWafEngine(
      { presets: ['default'], level: 'low' },
    );
    const ids = engine.rules.map((r) => r.id);
    expect(ids).toContain('preset-rce-unix-cmd');
    expect(ids).toContain('preset-rce-ssrf-metadata');
    expect(ids).toContain('preset-lfi-os-files');
    expect(ids).not.toContain('preset-rce-ssti');
    expect(ids).not.toContain('preset-protocol-response-splitting');
  });

  it('low allows traffic that only high would block (SSI)', async () => {
    const low = createWafEngine(
      { presets: ['xss'], level: 'low' },
    );
    const high = createWafEngine(
      { presets: ['xss'], level: 'high' },
    );
    const mock = createMockContext({
      query: { page: '<!--#exec cmd="id"-->' },
    });
    expect((await low.handle(mock.ctx)).decision).toBe('allow');
    expect((await high.handle(createMockContext({
      query: { page: '<!--#exec cmd="id"-->' },
    }).ctx)).decision).toBe('block');
  });

  it('balanced blocks XSS while low allows it', async () => {
    const payload = { query: { q: '<script>alert(1)</script>' } };
    const low = createWafEngine(
      { presets: ['xss'], level: 'low' },
    );
    const balanced = createWafEngine(
      { presets: ['xss'], level: 'balanced' },
    );
    expect((await low.handle(createMockContext(payload).ctx)).decision).toBe(
      'allow',
    );
    expect(
      (await balanced.handle(createMockContext(payload).ctx)).decision,
    ).toBe('block');
  });

  it('filters custom rules by minLevel', () => {
    const rules: readonly WafRule[] = [
      {
        id: 'always',
        action: 'block',
        when: { field: 'path', equals: '/a' },
      },
      {
        id: 'only-high',
        action: 'block',
        minLevel: 'high',
        when: { field: 'path', equals: '/b' },
      },
    ];
    const atLow = filterRulesByLevel(rules, 'low').map((r) => r.id);
    const atHigh = filterRulesByLevel(rules, 'high').map((r) => r.id);
    expect(atLow).toEqual(['always']);
    expect(atHigh).toEqual(['always', 'only-high']);
  });

  it('isLevelActive follows low < balanced < high < paranoid', () => {
    expect(protectionLevelRank('low')).toBeLessThan(
      protectionLevelRank('balanced'),
    );
    expect(isLevelActive('balanced', 'low')).toBe(true);
    expect(isLevelActive('low', 'balanced')).toBe(false);
    expect(isLevelActive('paranoid', 'high')).toBe(true);
    expect(isLevelActive('high', 'paranoid')).toBe(false);
  });
});
