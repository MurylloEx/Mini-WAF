import { readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';
import type { WafPresetName } from '@/domain/rules';
import { resolvePresets } from '@/presets/index';
import { isFieldCondition } from '@/domain/rules';

const REPO_ROOT = join(__dirname, '..');

const ALL_PRESETS: readonly WafPresetName[] = [
  'sqli',
  'xss',
  'scanners',
  'path-traversal',
  'rfi',
  'rce',
  'protocol',
  'default',
];

const ALL_RULES = resolvePresets(ALL_PRESETS);

/**
 * Every id the presets can produce. Several are built from a template
 * (`preset-sqli-${kind}-${field}`), so they never appear as a literal in
 * `src/` — resolving the presets is the only reliable source of truth, and
 * grepping for `id: '...'` silently misses them.
 */
const KNOWN_IDS: ReadonlySet<string> = new Set(ALL_RULES.map((rule) => rule.id));

/**
 * `preset-`-prefixed strings that are deliberately not rule ids. Each one is
 * asserted against the source below, so this stays an exemption with evidence
 * rather than a way to silence the scan.
 */
const RATE_LIMIT_KEY_PREFIX = 'preset-dos';

/** `preset-…` tokens as they appear in prose, code fences and tables. */
const PRESET_ID_PATTERN = /preset-[a-z0-9]+(?:-[a-z0-9]+)*(?:-\{[a-z0-9,]+\})?/g;

/** `preset-sqli-classic-{query,body}` → the two ids it stands for. */
function expandBraces(token: string): readonly string[] {
  const match = token.match(/^(.*)-\{([a-z0-9,]+)\}$/);
  return match === null
    ? [token]
    : match[2].split(',').map((suffix) => `${match[1]}-${suffix}`);
}

function markdownFiles(dir: string): readonly string[] {
  return readdirSync(dir).flatMap((entry) => {
    if (entry === 'node_modules' || entry === 'assets' || entry === '.vercel') {
      return [];
    }
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      return markdownFiles(full);
    }
    return full.endsWith('.md') ? [full] : [];
  });
}

const DOC_FILES: readonly string[] = [
  join(REPO_ROOT, 'README.md'),
  join(REPO_ROOT, 'BENCHMARKS.md'),
  ...markdownFiles(join(REPO_ROOT, 'docs')),
];

function documentedIds(file: string): readonly string[] {
  const tokens = readFileSync(file, 'utf8').match(PRESET_ID_PATTERN) ?? [];
  return [...new Set(tokens.flatMap(expandBraces))].filter(
    (token) => token !== RATE_LIMIT_KEY_PREFIX,
  );
}

describe('rule ids referenced in documentation', () => {
  it('backs every documented id with a real rule', () => {
    const unknown = DOC_FILES.flatMap((file) =>
      documentedIds(file)
        .filter((id) => !KNOWN_IDS.has(id))
        .map((id) => `${relative(REPO_ROOT, file)}: ${id}`),
    );

    expect(unknown).toEqual([]);
  });

  it('reads enough ids that the scan cannot silently pass', () => {
    const found = DOC_FILES.flatMap(documentedIds);

    expect(new Set(found).size).toBeGreaterThan(20);
  });

  it('keeps the rate-limit keyPrefix exemption backed by the source', () => {
    const prefixes = ALL_RULES.flatMap((rule) =>
      isFieldCondition(rule.when) && rule.when.rateLimit?.keyPrefix !== undefined
        ? [rule.when.rateLimit.keyPrefix]
        : [],
    );

    expect(prefixes).toContain(RATE_LIMIT_KEY_PREFIX);
  });
});
