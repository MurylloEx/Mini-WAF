# Deploy to GitHub Pages

This documentation is a **VitePress** static site under `docs/`. Build output goes to `docs/.vitepress/dist`.

The product site target is **`https://mini-waf.github.io`**.

## Local commands

From the repository root:

```bash
npm run docs:dev      # http://localhost:5173 (default VitePress port)
npm run docs:build    # writes docs/.vitepress/dist
npm run docs:preview  # serve the production build locally
```

## Option A — `mini-waf.github.io` (recommended for the custom domain / org site)

Use a dedicated GitHub repository named **`mini-waf.github.io`** (user or organization `mini-waf`).

1. Keep `base: '/'` (default). Do **not** set `DOCS_BASE`.
2. Build:

   ```bash
   npm run docs:build
   ```

3. Publish the contents of `docs/.vitepress/dist` to the `main` (or `gh-pages`) branch of the `mini-waf.github.io` repo — for example:

   ```bash
   # example: push dist into a sibling clone of mini-waf.github.io
   rsync -a --delete docs/.vitepress/dist/ ../mini-waf.github.io/
   cd ../mini-waf.github.io && git add -A && git commit -m "docs: publish" && git push
   ```

4. In the repo **Settings → Pages**, serve from the branch root.

Site URL: `https://mini-waf.github.io/`

## Option B — Project Pages on the library repo

If you publish from [MurylloEx/Mini-WAF](https://github.com/MurylloEx/Mini-WAF) as GitHub **project** pages, assets must live under `/Mini-WAF/`:

```bash
DOCS_BASE=/Mini-WAF/ npm run docs:build
```

Then deploy `docs/.vitepress/dist` via GitHub Actions (`peaceiris/actions-gh-pages`, `actions/upload-pages-artifact`, etc.) or the Pages UI.

Site URL: `https://murylloex.github.io/Mini-WAF/` (adjust user/org).

You can still attach a custom domain later; for a naked `mini-waf.github.io` host, **Option A** is the usual fit.

## Example GitHub Actions (Option A artifact → Pages)

If `mini-waf.github.io` is a separate repo that only hosts the static files, a simple push workflow is enough. If you build from this library repo and deploy to Pages in the same repo with `base: '/'`, ensure Pages is not expecting a project subpath.

Minimal build job fragment:

```yaml
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: 22
          cache: npm
      - run: npm ci
      - run: npm run docs:build
      # upload docs/.vitepress/dist to your Pages deploy action
```

## Logo & branding

The site logo is `docs/public/mini-waf-logo.png` (copied from the repo-root `mini-waf-logo.png`). Theme accents use the logo red (`#E60000`) on a dark background.
