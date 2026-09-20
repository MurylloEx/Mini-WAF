#!/usr/bin/env node
/**
 * HTTP Express BEFORE vs AFTER WAF — fixed request count, keep-alive.
 *
 * Pairs:
 *   B0 / B1  — GET /health clean (no WAF vs WAF)
 *   C0 / C1  — GET /search?q=shoes clean
 *   C2 / C3  — GET /search?q=SQLi (app 200 without WAF; WAF expects 403)
 *
 * Methodology (default):
 *   - Fixed N requests per case (default 50_000) — same N for all pairs
 *   - Warmup 2_000 requests first
 *   - concurrency=32, http.Agent keepAlive
 *   - WAF: default balanced, preset-dos-rate-limit DISABLED (fair allow path)
 *
 * Usage:
 *   node benchmarks/http.mjs
 *   node benchmarks/http.mjs --requests 50000 --concurrency 32 --warmup 2000
 *   npm run bench:http
 */

import http from 'node:http';
import { pathToFileURL } from 'node:url';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import {
  fmtMs,
  fmtOps,
  fmtUs,
  percentile,
  printTable,
  readCpuNote,
} from './lib/stats.mjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, '..');
const require = createRequire(import.meta.url);

const DOS_RULE_ID = 'preset-dos-rate-limit';
const SQLI_Q = "1' OR 1=1 --";
const CLEAN_SEARCH = '/search?q=shoes';
const SQLI_SEARCH = `/search?q=${encodeURIComponent(SQLI_Q)}`;

function parseArgs(argv) {
  const out = {
    requests: 50_000,
    warmup: 2_000,
    concurrency: 32,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--requests' || a === '-n') out.requests = Number(argv[++i]);
    else if (a === '--warmup') out.warmup = Number(argv[++i]);
    else if (a === '--concurrency') out.concurrency = Number(argv[++i]);
    else if (a === '--help' || a === '-h') out.help = true;
  }
  return out;
}

async function loadExpressAndWaf() {
  let express;
  try {
    express = require('express');
  } catch {
    console.error(
      'express is required (devDependency). Run npm install at repo root.',
    );
    process.exit(1);
  }
  const wafMod = await import(
    pathToFileURL(path.join(root, 'dist', 'esm', 'express.js')).href
  );
  return { express, expressWaf: wafMod.expressWaf };
}

function listen(app) {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const { port } = server.address();
      resolve({ server, port });
    });
  });
}

function createAgent() {
  return new http.Agent({
    keepAlive: true,
    maxSockets: 256,
    maxFreeSockets: 64,
  });
}

function httpGet(port, pathName, agent) {
  return new Promise((resolve, reject) => {
    const req = http.request(
      {
        host: '127.0.0.1',
        port,
        path: pathName,
        method: 'GET',
        agent,
        headers: {
          connection: 'keep-alive',
          accept: 'application/json',
          'user-agent': 'mini-waf-bench/1.0',
        },
      },
      (res) => {
        res.resume();
        res.on('end', () => resolve(res.statusCode));
        res.on('error', reject);
      },
    );
    req.on('error', reject);
    req.end();
  });
}

/**
 * Fixed-count concurrent load with keep-alive.
 * Returns completed, errors, wallMs, latencies (ns), statusCodes map.
 */
async function loadFixed(port, pathName, { requests, concurrency, agent }) {
  let next = 0;
  let completed = 0;
  let errors = 0;
  const latencies = new Array(requests);
  const statusCodes = Object.create(null);

  async function worker() {
    for (;;) {
      const i = next++;
      if (i >= requests) return;
      const t0 = process.hrtime.bigint();
      try {
        const code = await httpGet(port, pathName, agent);
        latencies[i] = Number(process.hrtime.bigint() - t0);
        statusCodes[code] = (statusCodes[code] ?? 0) + 1;
        completed++;
      } catch {
        latencies[i] = Number(process.hrtime.bigint() - t0);
        statusCodes.error = (statusCodes.error ?? 0) + 1;
        errors++;
      }
    }
  }

  const wall0 = process.hrtime.bigint();
  await Promise.all(
    Array.from({ length: concurrency }, () => worker()),
  );
  const wallNs = Number(process.hrtime.bigint() - wall0);
  const wallMs = wallNs / 1e6;

  const valid = latencies.filter((v) => typeof v === 'number');
  const sorted = [...valid].sort((a, b) => a - b);
  const toUs = (ns) => ns / 1e3;

  return {
    requests,
    completed,
    errors,
    wallMs,
    opsPerSec: completed / (wallMs / 1000),
    errorRate: errors / requests,
    p50Us: toUs(percentile(sorted, 50)),
    p95Us: toUs(percentile(sorted, 95)),
    p99Us: toUs(percentile(sorted, 99)),
    statusCodes: { ...statusCodes },
  };
}

function buildApp(express, expressWaf, mountWaf) {
  const app = express();
  // No json parser on these GET routes — keep baseline lean / apples-to-apples.
  if (mountWaf) {
    app.use(
      expressWaf({
        presets: ['default'],
        level: 'balanced',
        disabledRuleIds: [DOS_RULE_ID],
        ruleYieldEvery: 0,
      }),
    );
  }
  app.get('/health', (_req, res) => {
    res.status(200).json({ ok: true });
  });
  app.get('/search', (req, res) => {
    res.status(200).json({ q: req.query.q ?? null });
  });
  return app;
}

function fmtStatus(map) {
  return Object.entries(map)
    .sort(([a], [b]) => String(a).localeCompare(String(b)))
    .map(([k, v]) => `${k}:${v}`)
    .join(',');
}

function toRow(c) {
  return {
    id: c.id,
    case: c.name,
    N: String(c.requests),
    done: String(c.completed),
    wall: fmtMs(c.wallMs),
    'req/s': fmtOps(c.opsPerSec),
    p50: fmtUs(c.p50Us),
    p95: fmtUs(c.p95Us),
    p99: fmtUs(c.p99Us),
    'err%': `${(c.errorRate * 100).toFixed(3)}%`,
    status: fmtStatus(c.statusCodes),
  };
}

export async function runHttpBench(opts = {}) {
  const args = { ...parseArgs(process.argv.slice(2)), ...opts };
  if (args.help) {
    console.log(
      'Usage: node benchmarks/http.mjs [--requests N] [--warmup N] [--concurrency N]',
    );
    process.exit(0);
  }

  const { express, expressWaf } = await loadExpressAndWaf();
  const cpu = await readCpuNote();
  const { requests, warmup, concurrency } = args;

  console.log('=== HTTP Express benches (B0/B1, C0–C3) ===');
  console.log(
    `  mode=fixed-request-count  N=${requests}  warmup=${warmup}  concurrency=${concurrency}`,
  );
  console.log(`  keep-alive=http.Agent  node=${process.version}`);
  console.log(`  cpu ${cpu}`);
  console.log(
    `  WAF: presets=default level=balanced disabledRuleIds=[${DOS_RULE_ID}] ruleYieldEvery=0\n`,
  );

  async function measureServer(mountWaf) {
    const app = buildApp(express, expressWaf, mountWaf);
    const { server, port } = await listen(app);
    const agent = createAgent();
    return { server, port, agent, mountWaf };
  }

  async function runCase(id, name, pathName, { server, port, agent }) {
    // Warmup (not counted)
    if (warmup > 0) {
      await loadFixed(port, pathName, {
        requests: warmup,
        concurrency,
        agent,
      });
    }
    const result = await loadFixed(port, pathName, {
      requests,
      concurrency,
      agent,
    });
    return { id, name, concurrency, ...result };
  }

  const cases = [];

  // --- B: /health clean ---
  {
    const noWaf = await measureServer(false);
    try {
      cases.push(
        await runCase('B0', 'Express NO WAF  GET /health', '/health', noWaf),
      );
    } finally {
      noWaf.agent.destroy();
      await new Promise((r) => noWaf.server.close(r));
    }
  }
  {
    const withWaf = await measureServer(true);
    try {
      cases.push(
        await runCase(
          'B1',
          'Express + WAF   GET /health',
          '/health',
          withWaf,
        ),
      );
    } finally {
      withWaf.agent.destroy();
      await new Promise((r) => withWaf.server.close(r));
    }
  }

  // --- C: /search clean & SQLi — separate servers so state is clean ---
  {
    const noWaf = await measureServer(false);
    try {
      cases.push(
        await runCase(
          'C0',
          'Express NO WAF  GET /search clean',
          CLEAN_SEARCH,
          noWaf,
        ),
      );
      cases.push(
        await runCase(
          'C2',
          'Express NO WAF  GET /search SQLi (expect 200)',
          SQLI_SEARCH,
          noWaf,
        ),
      );
    } finally {
      noWaf.agent.destroy();
      await new Promise((r) => noWaf.server.close(r));
    }
  }
  {
    const withWaf = await measureServer(true);
    try {
      cases.push(
        await runCase(
          'C1',
          'Express + WAF   GET /search clean',
          CLEAN_SEARCH,
          withWaf,
        ),
      );
      cases.push(
        await runCase(
          'C3',
          'Express + WAF   GET /search SQLi (expect 403)',
          SQLI_SEARCH,
          withWaf,
        ),
      );
    } finally {
      withWaf.agent.destroy();
      await new Promise((r) => withWaf.server.close(r));
    }
  }

  // Order for display: B0 B1 C0 C1 C2 C3
  const order = ['B0', 'B1', 'C0', 'C1', 'C2', 'C3'];
  cases.sort((a, b) => order.indexOf(a.id) - order.indexOf(b.id));

  const cols = [
    'id',
    'case',
    'N',
    'done',
    'wall',
    'req/s',
    'p50',
    'p95',
    'p99',
    'err%',
    'status',
  ];
  printTable(cases.map(toRow), cols);

  console.log('\nPair deltas (same N, same concurrency):');
  const byId = Object.fromEntries(cases.map((c) => [c.id, c]));
  const pairs = [
    ['B0', 'B1', '/health clean  no-WAF → +WAF'],
    ['C0', 'C1', '/search clean  no-WAF → +WAF'],
    ['C2', 'C3', '/search SQLi   no-WAF → +WAF'],
  ];
  for (const [a, b, label] of pairs) {
    const left = byId[a];
    const right = byId[b];
    const ratio = right.opsPerSec / left.opsPerSec;
    const drop = (1 - ratio) * 100;
    console.log(
      `  ${a}→${b}  ${label.padEnd(34)}  ${fmtOps(left.opsPerSec)} → ${fmtOps(right.opsPerSec)}  (${drop >= 0 ? '-' : '+'}${Math.abs(drop).toFixed(1)}% req/s)  p50 ${fmtUs(left.p50Us)} → ${fmtUs(right.p50Us)}`,
    );
  }

  // Expectation checks
  const c3 = byId.C3;
  const c2 = byId.C2;
  if (c2 && (c2.statusCodes[200] ?? 0) < c2.completed * 0.95) {
    console.warn(
      `\nWARN C2: expected mostly 200 without WAF, got ${fmtStatus(c2.statusCodes)}`,
    );
  }
  if (c3 && (c3.statusCodes[403] ?? 0) < c3.completed * 0.95) {
    console.warn(
      `\nWARN C3: expected mostly 403 with WAF on SQLi, got ${fmtStatus(c3.statusCodes)}`,
    );
  }

  const ranked = [...cases].sort((a, b) => b.p50Us - a.p50Us);
  console.log('\nRanked by p50 latency (slowest first) — this run only:');
  ranked.forEach((c, i) => {
    console.log(
      `  ${String(i + 1).padStart(2)}. ${c.id.padEnd(4)} ${c.name.padEnd(48)}  p50=${fmtUs(c.p50Us)}  ${fmtOps(c.opsPerSec)}`,
    );
  });

  const report = {
    meta: {
      kind: 'http',
      mode: 'fixed-request-count',
      requests,
      warmup,
      concurrency,
      keepAlive: true,
      node: process.version,
      cpu,
      timestamp: new Date().toISOString(),
      waf: {
        presets: ['default'],
        level: 'balanced',
        disabledRuleIds: [DOS_RULE_ID],
        ruleYieldEvery: 0,
        rationale:
          'Disable dos rate-limit so allow-path benches are not rate-limited / cache-disabled',
      },
    },
    cases: cases.map((c) => ({
      id: c.id,
      name: c.name,
      requests: c.requests,
      completed: c.completed,
      errors: c.errors,
      errorRate: Number(c.errorRate.toFixed(6)),
      wallMs: Number(c.wallMs.toFixed(2)),
      opsPerSec: Math.round(c.opsPerSec),
      p50Us: Number(c.p50Us.toFixed(2)),
      p95Us: Number(c.p95Us.toFixed(2)),
      p99Us: Number(c.p99Us.toFixed(2)),
      statusCodes: c.statusCodes,
      concurrency: c.concurrency,
    })),
  };

  const fs = await import('node:fs/promises');
  const outPath = path.join(__dirname, 'last-http-run.json');
  await fs.writeFile(outPath, JSON.stringify(report, null, 2));
  console.log(`\nWrote ${outPath}`);

  return report;
}

const isMain =
  process.argv[1] &&
  path.resolve(process.argv[1]) ===
    path.resolve(fileURLToPath(import.meta.url));

if (isMain) {
  runHttpBench().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
