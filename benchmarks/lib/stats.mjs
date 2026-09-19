/** Timing / percentile helpers for benches. */

export function percentile(sortedAsc, p) {
  if (sortedAsc.length === 0) return 0;
  const idx = Math.min(
    sortedAsc.length - 1,
    Math.max(0, Math.ceil((p / 100) * sortedAsc.length) - 1),
  );
  return sortedAsc[idx];
}

export function summarize(samplesNs) {
  const sorted = [...samplesNs].sort((a, b) => a - b);
  const sum = sorted.reduce((acc, v) => acc + v, 0);
  return {
    n: sorted.length,
    meanUs: sum / sorted.length / 1e3,
    p50Us: percentile(sorted, 50) / 1e3,
    p95Us: percentile(sorted, 95) / 1e3,
    p99Us: percentile(sorted, 99) / 1e3,
    minUs: sorted[0] / 1e3,
    maxUs: sorted[sorted.length - 1] / 1e3,
  };
}

/**
 * Run `fn` for `iterations` after `warmup`, sampling each call with hrtime.
 * Returns { iterations, opsPerSec, wallMs, stats, lastResult }.
 */
export async function benchAsync(fn, { iterations, warmup = 200 } = {}) {
  for (let i = 0; i < warmup; i++) {
    await fn(i);
  }

  const samples = new Array(iterations);
  const t0 = process.hrtime.bigint();
  let lastResult;
  for (let i = 0; i < iterations; i++) {
    const s = process.hrtime.bigint();
    lastResult = await fn(i);
    samples[i] = Number(process.hrtime.bigint() - s);
  }
  const wallNs = Number(process.hrtime.bigint() - t0);
  const wallMs = wallNs / 1e6;
  const opsPerSec = iterations / (wallNs / 1e9);

  return {
    iterations,
    opsPerSec,
    wallMs,
    stats: summarize(samples),
    lastResult,
  };
}

export function fmtUs(us) {
  if (us >= 1000) return `${(us / 1000).toFixed(2)} ms`;
  return `${us.toFixed(1)} µs`;
}

export function fmtOps(ops) {
  if (ops >= 1000) return `${(ops / 1000).toFixed(2)}k/s`;
  return `${ops.toFixed(0)}/s`;
}

export function fmtMs(ms) {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)} s`;
  return `${ms.toFixed(1)} ms`;
}

export function printTable(rows, cols) {
  const columns =
    cols ??
    Object.keys(rows[0] ?? {
      case: '',
    });
  const widths = columns.map((c) =>
    Math.max(c.length, ...rows.map((r) => String(r[c] ?? '').length)),
  );
  const line = (cells) =>
    cells.map((cell, i) => String(cell).padEnd(widths[i])).join('  ');
  console.log(line(columns));
  console.log(widths.map((w) => '-'.repeat(w)).join('  '));
  for (const row of rows) {
    console.log(line(columns.map((c) => row[c] ?? '')));
  }
}

export async function readCpuNote() {
  try {
    const os = await import('node:os');
    const cpus = os.cpus();
    if (!cpus?.length) return 'cpu=unknown';
    const model = cpus[0].model.replace(/\s+/g, ' ').trim();
    return `${cpus.length}× ${model}`;
  } catch {
    return 'cpu=unknown';
  }
}
