#!/usr/bin/env node
/**
 * Engine-level A/B performance benches (mock context).
 *
 * Cases A0–A7 use the **same N** (and same warmup) for every pair.
 *
 * Usage:
 *   node benchmarks/run.mjs
 *   node benchmarks/run.mjs --iterations 20000 --warmup 1000
 *   npm run bench
 */

import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createMockContext } from './lib/mock-context.mjs';
import {
  benchAsync,
  fmtMs,
  fmtOps,
  fmtUs,
  printTable,
  readCpuNote,
} from './lib/stats.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');

const DOS_RULE_ID = 'preset-dos-rate-limit';

const CLEAN_HEADERS = {
  'user-agent': 'Mozilla/5.0 (compatible; BenchBot/1.0)',
  accept: 'application/json',
  host: 'localhost',
};

const SQLI_QUERY = { q: "1' OR 1=1 --" };

function parseArgs(argv) {
  const out = { iterations: 20_000, warmup: 1_000 };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--iterations' || a === '-n') out.iterations = Number(argv[++i]);
    else if (a === '--warmup') out.warmup = Number(argv[++i]);
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

function smallBody() {
  return '{"ok":true,"q":"hello"}';
}

function largeBody(bytes = 8_192) {
  return `{"note":"pad","data":"${'A'.repeat(Math.max(0, bytes - 40))}"}`;
}

async function loadEngine() {
  const distIndex = path.join(root, 'dist', 'esm', 'index.js');
  try {
    return await import(pathToFileURL(distIndex).href);
  } catch (err) {
    console.error(
      'Could not load dist/esm. Run `npm run build` first.\n',
      err.message,
    );
    process.exit(1);
  }
}

function noDosBalanced(extra = {}) {
  return {
    presets: ['default'],
    level: 'balanced',
    disabledRuleIds: [DOS_RULE_ID],
    ruleYieldEvery: 0,
    ...extra,
  };
}

async function runCase(id, name, engine, makeCtx, opts) {
  const result = await benchAsync(
    async (i) => engine.handle(makeCtx(i).ctx),
    opts,
  );
  return {
    id,
    name,
    rules: engine.rules.length,
    ...result,
  };
}

function toRow(c) {
  return {
    id: c.id,
    case: c.name,
    N: String(c.iterations),
    rules: String(c.rules),
    wall: fmtMs(c.wallMs),
    'ops/s': fmtOps(c.opsPerSec),
    p50: fmtUs(c.stats.p50Us),
    p95: fmtUs(c.stats.p95Us),
    p99: fmtUs(c.stats.p99Us),
    decision: c.lastResult?.decision ?? '',
  };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(
      'Usage: node benchmarks/run.mjs [--iterations N] [--warmup N]',
    );
    process.exit(0);
  }

  const mod = await loadEngine();
  const { iterations, warmup } = args;
  const cpu = await readCpuNote();

  console.log('mini-waf engine benches (A0–A7)');
  console.log(`  N=${iterations}  warmup=${warmup}  (same N for every case)`);
  console.log(`  node ${process.version}`);
  console.log(`  cpu ${cpu}`);
  console.log(`  cwd ${root}`);
  console.log(
    `  note: preset-dos-rate-limit disabled on A1–A7 so allow path stays allow\n`,
  );

  const opts = { iterations, warmup };
  const cases = [];

  // A0 — 0 rules (baseline handle/protect overhead)
  {
    const engine = mod.createWafEngine({
      rules: [],
      presets: [],
      ruleYieldEvery: 0,
    });
    cases.push(
      await runCase(
        'A0',
        '0 rules (baseline handle)',
        engine,
        () =>
          createMockContext({
            path: '/',
            headers: CLEAN_HEADERS,
            ip: '10.0.0.9',
          }),
        opts,
      ),
    );
  }

  // A1 — default+balanced WITHOUT rate-limit (clean allow)
  {
    const engine = mod.createWafEngine(noDosBalanced());
    cases.push(
      await runCase(
        'A1',
        'balanced no-dos clean allow',
        engine,
        () =>
          createMockContext({
            path: '/api/items',
            method: 'GET',
            query: { page: '1' },
            headers: CLEAN_HEADERS,
            body: '',
            ip: '10.0.0.1',
          }),
        opts,
      ),
    );
  }

  // A2 — A1 + decisionCache (same fingerprint → cache hits after warmup)
  {
    const engine = mod.createWafEngine(
      noDosBalanced({
        decisionCache: { max: 256, ttlMs: 60_000 },
      }),
    );
    cases.push(
      await runCase(
        'A2',
        'A1 + decisionCache (same fingerprint)',
        engine,
        () =>
          createMockContext({
            path: '/api/items',
            method: 'GET',
            query: { page: '1' },
            headers: CLEAN_HEADERS,
            body: '',
            ip: '10.0.0.1',
          }),
        opts,
      ),
    );
  }

  // A3 — A1 with 8KB body
  {
    const engine = mod.createWafEngine(
      noDosBalanced({ maxFieldLength: 8_192 }),
    );
    const body = largeBody(8_192);
    cases.push(
      await runCase(
        'A3',
        'A1 + 8KB body',
        engine,
        () =>
          createMockContext({
            path: '/echo',
            method: 'POST',
            headers: {
              ...CLEAN_HEADERS,
              'content-type': 'application/json',
            },
            body,
            ip: '10.0.0.3',
          }),
        opts,
      ),
    );
  }

  // A4 — A1 with small body
  {
    const engine = mod.createWafEngine(
      noDosBalanced({ maxFieldLength: 8_192 }),
    );
    cases.push(
      await runCase(
        'A4',
        'A1 + small body (~24B)',
        engine,
        () =>
          createMockContext({
            path: '/echo',
            method: 'POST',
            headers: {
              ...CLEAN_HEADERS,
              'content-type': 'application/json',
            },
            body: smallBody(),
            ip: '10.0.0.3',
          }),
        opts,
      ),
    );
  }

  // A5 — A1 SQLi block path
  {
    const engine = mod.createWafEngine(noDosBalanced());
    cases.push(
      await runCase(
        'A5',
        'A1 SQLi block path',
        engine,
        () =>
          createMockContext({
            path: '/search',
            method: 'GET',
            query: SQLI_QUERY,
            headers: CLEAN_HEADERS,
            ip: '10.0.0.2',
          }),
        opts,
      ),
    );
  }

  // A6 — level low vs balanced vs high vs paranoid (same N, clean)
  for (const level of ['low', 'balanced', 'high', 'paranoid']) {
    const engine = mod.createWafEngine({
      presets: ['default'],
      level,
      disabledRuleIds: [DOS_RULE_ID],
      ruleYieldEvery: 0,
    });
    cases.push(
      await runCase(
        `A6-${level}`,
        `level=${level} clean allow`,
        engine,
        () =>
          createMockContext({
            path: '/api/items',
            method: 'GET',
            query: { page: '1' },
            headers: CLEAN_HEADERS,
            body: '',
            ip: '10.0.0.1',
          }),
        opts,
      ),
    );
  }

  // A7 — paranoid yield=0 vs yield=32 (same N)
  for (const yieldEvery of [0, 32]) {
    const engine = mod.createWafEngine({
      presets: ['default'],
      level: 'paranoid',
      disabledRuleIds: [DOS_RULE_ID],
      ruleYieldEvery: yieldEvery,
    });
    cases.push(
      await runCase(
        `A7-y${yieldEvery}`,
        `paranoid yield=${yieldEvery}`,
        engine,
        () =>
          createMockContext({
            path: '/api/items',
            method: 'GET',
            query: { page: '1' },
            headers: CLEAN_HEADERS,
            body: '',
            ip: '10.0.0.1',
          }),
        opts,
      ),
    );
  }

  // Sanity: every case used exact N
  const nMismatch = cases.filter((c) => c.iterations !== iterations);
  if (nMismatch.length) {
    console.error('FATAL: N mismatch across cases', nMismatch.map((c) => c.id));
    process.exit(1);
  }

  const cols = [
    'id',
    'case',
    'N',
    'rules',
    'wall',
    'ops/s',
    'p50',
    'p95',
    'p99',
    'decision',
  ];
  printTable(cases.map(toRow), cols);

  // Pair deltas (apples-to-apples)
  console.log('\nPair deltas (same N):');
  const byId = Object.fromEntries(cases.map((c) => [c.id, c]));
  const pairs = [
    ['A0', 'A1', 'baseline → balanced allow'],
    ['A1', 'A2', 'decisionCache off → on'],
    ['A4', 'A3', 'small body → 8KB body'],
    ['A1', 'A5', 'clean allow → SQLi block'],
    ['A6-low', 'A6-paranoid', 'level low → paranoid'],
    ['A7-y0', 'A7-y32', 'paranoid yield 0 → 32'],
  ];
  for (const [a, b, label] of pairs) {
    const left = byId[a];
    const right = byId[b];
    if (!left || !right) continue;
    const ratio = right.opsPerSec / left.opsPerSec;
    const latDelta = right.stats.p50Us - left.stats.p50Us;
    console.log(
      `  ${a}→${b}  ${label.padEnd(36)}  ops ${fmtOps(left.opsPerSec)} → ${fmtOps(right.opsPerSec)}  (${(ratio * 100).toFixed(1)}%)  p50 Δ ${latDelta >= 0 ? '+' : ''}${fmtUs(latDelta)}`,
    );
  }

  const ranked = [...cases].sort((a, b) => b.stats.meanUs - a.stats.meanUs);
  console.log('\nRanked by mean latency (slowest first) — this run only:');
  ranked.forEach((c, i) => {
    console.log(
      `  ${String(i + 1).padStart(2)}. ${c.id.padEnd(12)} ${c.name.padEnd(40)}  mean=${fmtUs(c.stats.meanUs)}  ${fmtOps(c.opsPerSec)}`,
    );
  });

  const report = {
    meta: {
      kind: 'engine',
      iterations,
      warmup,
      node: process.version,
      cpu,
      timestamp: new Date().toISOString(),
      note: 'preset-dos-rate-limit disabled on A1–A7',
    },
    cases: cases.map((c) => ({
      id: c.id,
      name: c.name,
      rules: c.rules,
      iterations: c.iterations,
      opsPerSec: Math.round(c.opsPerSec),
      wallMs: Number(c.wallMs.toFixed(2)),
      p50Us: Number(c.stats.p50Us.toFixed(2)),
      p95Us: Number(c.stats.p95Us.toFixed(2)),
      p99Us: Number(c.stats.p99Us.toFixed(2)),
      meanUs: Number(c.stats.meanUs.toFixed(2)),
      decision: c.lastResult?.decision,
    })),
  };

  const fs = await import('node:fs/promises');
  const outPath = path.join(__dirname, 'last-run.json');
  await fs.writeFile(outPath, JSON.stringify(report, null, 2));
  console.log(`\nWrote ${outPath}`);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
