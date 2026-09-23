import { existsSync, readFileSync, readdirSync, statSync } from 'node:fs';
import { join, relative } from 'node:path';
import { describe, expect, it } from 'vitest';

/**
 * The docs site renders Markdown in the browser, so nothing validates links at
 * build time. This test is that check: every page in the sidebar exists, and
 * every internal link and `#anchor` in the docs resolves.
 */

const DOCS = join(__dirname, '..', 'docs');

/** Same page-to-file mapping as `canonical` + `fileFor` in docs/assets/app.js. */
function fileFor(path: string): string {
  const page = path.replace(/(.)\/+$/, '$1');
  return join(DOCS, `${page === '/' ? '/index' : page}.md`);
}

/**
 * Must stay identical to `slugify` in docs/assets/app.js: heading ids are
 * generated there at runtime, and this is how the test predicts them.
 */
function slugify(text: string): string {
  const slug = text
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '')
    .replace(/[\u0000-\u001f]/g, '')
    .replace(/[\s~`!@#$%^&*()\-_+=[\]{}|\\;:"'“”‘’<>,.?/]+/g, '-')
    .replace(/-{2,}/g, '-')
    .replace(/^-+|-+$/g, '')
    .toLowerCase();
  return /^\d/.test(slug) ? `_${slug}` : slug;
}

/** Drops fenced code blocks so their contents are neither headings nor links. */
function withoutFences(markdown: string): string {
  return markdown.replace(/^\s*(`{3,}|~{3,})[\s\S]*?^\s*\1\s*$/gm, '');
}

/** The text a heading renders to, which is what its id is derived from. */
function headingText(source: string): string {
  return source
    .replace(/\[([^\]]+)\]\([^)]*\)/g, '$1')
    .replace(/<[^>]+>/g, '')
    .replace(/`/g, '')
    .replace(/(\*\*|__)(.+?)\1/g, '$2')
    .replace(/\\(.)/g, '$1')
    .trim();
}

function anchorsOf(file: string): ReadonlySet<string> {
  const seen = new Map<string, number>();
  const ids = withoutFences(readFileSync(file, 'utf8'))
    .split('\n')
    .flatMap((line) => {
      const match = line.match(/^#{1,4}\s+(.+?)\s*#*\s*$/);
      if (match === null) {
        return [];
      }
      const base = slugify(headingText(match[1])) || 'section';
      const count = seen.get(base);
      seen.set(base, count === undefined ? 0 : count + 1);
      return [count === undefined ? base : `${base}-${count + 1}`];
    });
  return new Set(ids);
}

function markdownFiles(dir: string): readonly string[] {
  return readdirSync(dir).flatMap((entry) => {
    if (entry === 'assets' || entry === '.vercel' || entry === 'node_modules') {
      return [];
    }
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) {
      return markdownFiles(full);
    }
    return full.endsWith('.md') ? [full] : [];
  });
}

/** Internal targets of Markdown links and HTML `href`s, outside code. */
function linksIn(file: string): readonly string[] {
  const text = withoutFences(readFileSync(file, 'utf8')).replace(/`[^`\n]*`/g, '');
  const markdown = [...text.matchAll(/\]\(([^)\s]+)\)/g)].map((m) => m[1]);
  const html = [...text.matchAll(/href="([^"]+)"/g)].map((m) => m[1]);
  return [...markdown, ...html].filter(
    (href) => (href.startsWith('/') && !href.startsWith('//')) || href.startsWith('#'),
  );
}

function sidebarPaths(): readonly string[] {
  const sidebar = readFileSync(join(DOCS, '_sidebar.md'), 'utf8').replace(/<!--[\s\S]*?-->/g, '');
  return [...sidebar.matchAll(/^\s*-\s+\[.+?\]\((.+?)\)\s*$/gm)].map((m) => m[1]);
}

const PAGES = markdownFiles(DOCS);

describe('docs links', () => {
  it('lists only pages that exist in the sidebar', () => {
    const missing = sidebarPaths().filter((path) => !existsSync(fileFor(path)));

    expect(missing).toEqual([]);
  });

  it('resolves every internal link and anchor', () => {
    const broken = PAGES.flatMap((file) =>
      linksIn(file).flatMap((href) => {
        const hash = href.indexOf('#');
        const path = hash === -1 ? href : href.slice(0, hash);
        const anchor = hash === -1 ? '' : href.slice(hash + 1);
        const where = `${relative(DOCS, file)}: ${href}`;

        if (path.startsWith('/assets/')) {
          return existsSync(join(DOCS, path)) ? [] : [where];
        }
        const target = path === '' ? file : fileFor(path);
        if (!existsSync(target)) {
          return [where];
        }
        return anchor === '' || anchorsOf(target).has(anchor) ? [] : [where];
      }),
    );

    expect(broken).toEqual([]);
  });

  it('keeps section pages beside their folder, not inside it as index.md', () => {
    // Static hosts answer "/guide/x/" with guide/x/index.md itself, so a page
    // stored there would be served as raw Markdown instead of the site.
    const nested = PAGES.filter((file) => file.endsWith('index.md') && file !== join(DOCS, 'index.md'));

    expect(nested.map((file) => relative(DOCS, file))).toEqual([]);
  });

  it('shows the released version wherever the site prints one', () => {
    const { version } = JSON.parse(readFileSync(join(DOCS, '..', 'package.json'), 'utf8')) as {
      readonly version: string;
    };
    const shown = [join(DOCS, 'index.html'), join(DOCS, 'index.md')].flatMap((file) =>
      [...readFileSync(file, 'utf8').matchAll(/\bv(\d+\.\d+(?:\.\d+)?)\b/g)].map(
        (m) => `${relative(DOCS, file)}: v${m[1]}`,
      ),
    );

    expect(shown.length).toBeGreaterThan(0);
    expect(shown.filter((entry) => !entry.endsWith(`v${version}`))).toEqual([]);
  });

  it('checks enough links that the scan cannot silently pass', () => {
    const count = PAGES.reduce((total, file) => total + linksIn(file).length, 0);

    expect(count).toBeGreaterThan(100);
  });
});
