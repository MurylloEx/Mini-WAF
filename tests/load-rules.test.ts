import { describe, expect, it } from 'vitest';
import {
  loadRules,
  parseRulesFromJson,
  RuleParseError,
  createWafEngine,
} from '@/engine';
import type { JsonValue } from '@/domain';
import { createMockContext } from './helpers/mock-context';

const sampleJson = `{
  "rules": [
    {
      "id": "json-block-sqli",
      "action": "block",
      "reason": "Possible SQL injection",
      "when": {
        "field": "query.id",
        "matches": { "pattern": "union\\\\s+select", "flags": "i" }
      }
    },
    {
      "id": "json-allow-health",
      "action": "allow",
      "priority": 1,
      "when": { "field": "path", "equals": "/health" }
    }
  ]
}`;

describe('parseRulesFromJson / loadRules', () => {
  it('parses a rules document into live WafRule values', () => {
    const rules = parseRulesFromJson(sampleJson);
    expect(rules).toHaveLength(2);
    expect(rules[0]?.id).toBe('json-block-sqli');
    expect(rules[0]?.when).toMatchObject({ field: 'query.id' });
    const matches = (rules[0]?.when as { matches?: RegExp }).matches;
    expect(matches).toBeInstanceOf(RegExp);
    expect(matches?.flags).toContain('i');
  });

  it('accepts a top-level array', () => {
    const rules = parseRulesFromJson(
      JSON.stringify([
        {
          id: 'exact-path',
          action: 'block',
          when: { field: 'path', equals: '/secret' },
        },
      ]),
    );
    expect(rules).toHaveLength(1);
    expect(rules[0]?.id).toBe('exact-path');
  });

  it('compiles string-list matches', () => {
    const value: JsonValue = [
      {
        id: 'block-methods',
        action: 'block',
        when: { field: 'method', matches: ['TRACE', 'TRACK'] },
      },
    ];
    const rules = loadRules(value);
    expect(rules[0]?.when).toMatchObject({
      field: 'method',
      matches: ['TRACE', 'TRACK'],
    });
  });

  it('rejects invalid shapes with path errors', () => {
    expect(() => parseRulesFromJson('{"rules":[{}]}')).toThrow(RuleParseError);
    expect(() => parseRulesFromJson('{"rules":[{}]}')).toThrow(/id/);
    expect(() =>
      parseRulesFromJson(
        JSON.stringify([
          {
            id: 'bad',
            action: 'explode',
            when: { field: 'path', equals: '/' },
          },
        ]),
      ),
    ).toThrow(/action/);
    expect(() =>
      loadRules({
        rules: [
          {
            id: 'bad-field',
            action: 'block',
            when: { field: 'unknown', equals: 'x' },
          },
        ],
      }),
    ).toThrow(/field/);
  });

  it('rejects invalid JSON text', () => {
    expect(() => parseRulesFromJson('{')).toThrow(RuleParseError);
  });

  it('works with createWafEngine after loading', async () => {
    const rules = parseRulesFromJson(sampleJson);
    const engine = createWafEngine({ rules });
    const blocked = await engine.handle(
      createMockContext({ query: { id: '1 UNION SELECT 1' } }).ctx,
    );
    expect(blocked.decision).toBe('block');
    expect(blocked.matchedRule?.id).toBe('json-block-sqli');

    const allowed = await engine.handle(
      createMockContext({
        path: '/health',
        query: { id: '1 UNION SELECT 1' },
      }).ctx,
    );
    expect(allowed.decision).toBe('allow');
  });

  it('supports nested anyOf / all conditions', () => {
    const rules = loadRules([
      {
        id: 'compound',
        action: 'block',
        when: {
          anyOf: [
            { field: 'path', equals: '/admin' },
            {
              all: [
                { field: 'method', equals: 'POST' },
                { field: 'path', includes: 'upload' },
              ],
            },
          ],
        },
      },
    ]);
    expect(rules).toHaveLength(1);
    expect(rules[0]?.when).toHaveProperty('anyOf');
  });
});

describe('requires in JSON rules', () => {
  it('parses a requires prefilter', () => {
    const rules = loadRules([
      {
        id: 'json-prefilter',
        action: 'block',
        when: { field: 'query', matches: 'danger', requires: ['danger'] },
      },
    ]);
    const condition = rules[0]?.when;
    expect(condition && 'requires' in condition ? condition.requires : undefined)
      .toEqual(['danger']);
  });

  it('rejects a non-string requires entry', () => {
    expect(() =>
      loadRules([
        {
          id: 'bad-prefilter',
          action: 'block',
          when: { field: 'query', matches: 'danger', requires: [1] },
        },
      ]),
    ).toThrow(RuleParseError);
  });
});
