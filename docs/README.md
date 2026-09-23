# Mini-WAF docs

The documentation site, published at <https://mini-waf.vercel.app>. It is plain
Markdown rendered in the browser: one `index.html`, one stylesheet, one script,
and the pages. There is no build step and no dependency to install.

## Run it

```bash
npm run docs:dev    # http://localhost:5173
```

Any static server works as long as unknown paths fall back to `index.html`,
which is what `scripts/serve-docs.mjs` and `vercel.json` both do.

## Layout

```
index.html          page shell (top bar, sidebar, search palette)
index.md            landing page
_sidebar.md         navigation: its order drives the sidebar, pager and search
guide/**.md         every other page (a section's page sits beside its folder)
assets/style.css    the design system (light and dark tokens at the top)
assets/app.js       router, Markdown rendering, sidebar, TOC, search
assets/vendor/      marked + highlight.js, vendored so nothing loads from npm
assets/img/         site images; assets/img/fw/ holds framework logos from
                    Simple Icons and gilbarbara/logos (both CC0; the marks
                    belong to their respective projects)
vercel.json         serves index.html for page paths
```

## Writing pages

- **Add a page:** create `guide/<name>.md` and add one line to `_sidebar.md`.
  It is served at `/guide/<name>`.
- **Links** use site paths: `[Presets](/guide/presets)`,
  `[the prefilter](/guide/conditions#the-requires-prefilter)`.
- **Section pages** sit beside their folder, never inside it as `index.md`:
  `/guide/integrations` is `guide/integrations.md`. Static hosts answer a
  folder URL with any `index.*` file they find, which would serve raw Markdown.
  `tests/docs-links.test.ts` fails on any link or anchor that does not resolve.
- **Callouts:** `::: tip`, `::: info`, `::: warning`, `::: danger`, each with an
  optional title after the type, closed by `:::`.
- **Code file names:** when the first line of a code block is a comment holding
  a path (`// lib/waf.ts`, `// src/fastify.ts (excerpt)`), it becomes the title
  of the block.
- **Tables** follow GitHub Markdown; escape a literal pipe as `\|`.

## Deploying

Vercel deploys this folder straight from GitHub: every push to `master` that
touches `docs/` goes to production, and every pull request gets a preview URL.
Pushes that do not change `docs/` are skipped by the `ignoreCommand` in
`vercel.json`. The Vercel project uses `docs` as its root directory and has no
build command.

A manual deploy is still possible from the repository root:

```bash
npx vercel --prod
```
