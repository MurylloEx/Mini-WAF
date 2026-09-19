#!/usr/bin/env node
/**
 * Full A/B compare: engine (A0–A7) then HTTP Express (B/C).
 *
 *   npm run bench:compare
 *   node benchmarks/compare.mjs
 *   node benchmarks/compare.mjs --iterations 20000 --requests 50000
 */

import { spawn } from 'node:child_process';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

function parseArgs(argv) {
  const engine = [];
  const http = [];
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--iterations' || a === '-n') {
      engine.push('--iterations', argv[++i]);
    } else if (a === '--warmup') {
      // apply to engine; http has its own --warmup via --http-warmup
      engine.push('--warmup', argv[++i]);
    } else if (a === '--requests') {
      http.push('--requests', argv[++i]);
    } else if (a === '--concurrency') {
      http.push('--concurrency', argv[++i]);
    } else if (a === '--http-warmup') {
      http.push('--warmup', argv[++i]);
    } else if (a === '--help' || a === '-h') {
      return { help: true };
    }
  }
  return { engine, http };
}

function runNode(script, args) {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [script, ...args], {
      stdio: 'inherit',
      cwd: path.resolve(__dirname, '..'),
    });
    child.on('exit', (code) => {
      if (code === 0) resolve();
      else reject(new Error(`${script} exited ${code}`));
    });
    child.on('error', reject);
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    console.log(`Usage: node benchmarks/compare.mjs [options]
  --iterations N     engine N (default 20000)
  --warmup N         engine warmup (default 1000)
  --requests N       HTTP fixed request count (default 50000)
  --concurrency N    HTTP concurrency (default 32)
  --http-warmup N    HTTP warmup requests (default 2000)`);
    process.exit(0);
  }

  console.log('=== mini-waf bench:compare ===\n');
  await runNode(path.join(__dirname, 'run.mjs'), args.engine);
  console.log('\n');
  await runNode(path.join(__dirname, 'http.mjs'), args.http);
  console.log('\n=== compare complete ===');
  console.log('Artifacts: benchmarks/last-run.json  benchmarks/last-http-run.json');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
