import { describe, expect, it } from 'vitest';
import {
  buildRuleList,
  createWafEngine,
  filterRulesByDisabledIds,
  filterRulesByEnabledIds,
} from '@/engine';
import type { WafRule } from '@/domain/rules';
import { createMockContext } from './helpers/mock-context';

const customBlock: WafRule = {
  id: 'custom-block-admin',
  action: 'block',
  when: { field: 'path', equals: '/admin' },
};

describe('enabledRuleIds / disabledRuleIds', () => {
  it('disables one preset rule by id', () => {
    const rules = buildRuleList({
      presets: ['sqli'],
      level: 'low',
      disabledRuleIds: ['preset-sqli-classic-query'],
    });
    const ids = rules.map((r) => r.id);
    expect(ids).not.toContain('preset-sqli-classic-query');
    expect(ids).toContain('preset-sqli-classic-body');
  });

  it('allowlists only the listed ids', () => {
    const rules = buildRuleList({
      presets: ['sqli'],
      level: 'low',
      enabledRuleIds: ['preset-sqli-classic-query'],
    });
    expect(rules.map((r) => r.id)).toEqual(['preset-sqli-classic-query']);
  });

  it('allowlist interacts with custom rules', () => {
    const rules = buildRuleList({
      presets: ['sqli'],
      level: 'low',
      rules: [customBlock],
      enabledRuleIds: ['custom-block-admin', 'preset-sqli-classic-query'],
    });
    expect(rules.map((r) => r.id).sort()).toEqual(
      ['custom-block-admin', 'preset-sqli-classic-query'].sort(),
    );
  });

  it('disabledRuleIds applies after allowlist', () => {
    const rules = buildRuleList({
      presets: ['sqli'],
      level: 'low',
      rules: [customBlock],
      enabledRuleIds: ['custom-block-admin', 'preset-sqli-classic-query'],
      disabledRuleIds: ['preset-sqli-classic-query'],
    });
    expect(rules.map((r) => r.id)).toEqual(['custom-block-admin']);
  });

  it('empty enabledRuleIds is a no-op', () => {
    const all = buildRuleList({ presets: ['sqli'], level: 'low' });
    const withEmpty = buildRuleList({
      presets: ['sqli'],
      level: 'low',
      enabledRuleIds: [],
    });
    expect(withEmpty.map((r) => r.id)).toEqual(all.map((r) => r.id));
  });

  it('pure helpers filter without mutating input', () => {
    const input: readonly WafRule[] = Object.freeze([
      customBlock,
      {
        id: 'other',
        action: 'block' as const,
        when: { field: 'path', equals: '/x' },
      },
    ]);
    const enabled = filterRulesByEnabledIds(input, ['custom-block-admin']);
    const disabled = filterRulesByDisabledIds(input, ['other']);
    expect(input).toHaveLength(2);
    expect(enabled.map((r) => r.id)).toEqual(['custom-block-admin']);
    expect(disabled.map((r) => r.id)).toEqual(['custom-block-admin']);
  });

  it('disabled preset rule no longer blocks matching traffic', async () => {
    const engine = createWafEngine({
      presets: ['sqli'],
      level: 'low',
      disabledRuleIds: [
        'preset-sqli-classic-query',
        'preset-sqli-classic-body',
        'preset-sqli-classic-path',
        'preset-sqli-classic-cookies',
      ],
    });
    const result = await engine.handle(
      createMockContext({
        query: { id: '1 UNION SELECT 1' },
      }).ctx,
    );
    expect(result.decision).toBe('allow');
  });
});
