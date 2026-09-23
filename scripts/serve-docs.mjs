#!/usr/bin/env node
/**
 * Serves docs/ locally, the same way the production host does: real files are
 * returned as-is, page paths (no file extension) fall back to index.html so
 * the page router can resolve them, and a missing file is a plain 404 — which
 * is how the router tells a missing page apart from an existing one. Mirrors
 * the rewrite in docs/vercel.json.
 *
 *   npm run docs:dev            # http://localhost:5173
 *   PORT=4000 npm run docs:dev
 */

import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'docs');
const port = Number(process.env.PORT ?? 5173);

const TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.md': 'text/markdown; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
};

async function resolveFile(urlPath) {
  const file = path.join(root, path.normalize(decodeURIComponent(urlPath)));
  if (!file.startsWith(root)) return undefined;
  const info = await stat(file).catch(() => undefined);
  return info?.isFile() ? file : undefined;
}

createServer(async (req, res) => {
  const { pathname } = new URL(req.url ?? '/', 'http://localhost');
  const isPage = path.extname(pathname) === '';
  const file = (await resolveFile(pathname)) ?? (isPage ? path.join(root, 'index.html') : undefined);
  if (file === undefined) {
    res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
    res.end('Not found');
    return;
  }
  const type = TYPES[path.extname(file)] ?? 'application/octet-stream';
  res.writeHead(200, { 'content-type': type, 'cache-control': 'no-cache' });
  res.end(await readFile(file));
}).listen(port, () => {
  console.log(`docs → http://localhost:${port}`);
});
