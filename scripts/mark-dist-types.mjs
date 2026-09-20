#!/usr/bin/env node
/**
 * Writes the `type` marker each dist folder needs so Node (and TypeScript)
 * interpret the emitted files correctly:
 *
 * - dist/cjs is CommonJS, even if the root package.json ever gains
 *   `"type": "module"`.
 * - dist/esm is ESM, which is what lets the `import` condition resolve to
 *   real ES modules rather than being re-interpreted as CJS.
 */

import { writeFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');

const MARKERS = [
  ['dist/cjs', 'commonjs'],
  ['dist/esm', 'module'],
];

await Promise.all(
  MARKERS.map(async ([dir, type]) => {
    const target = path.join(root, dir);
    await mkdir(target, { recursive: true });
    await writeFile(
      path.join(target, 'package.json'),
      `${JSON.stringify({ type }, null, 2)}\n`,
      'utf8',
    );
  }),
);
