# Deploy to GitHub Pages

This documentation is a **VitePress** static site under `docs/`. Build output goes to `docs/.vitepress/dist`.

The live site for this personal repository is **[https://murylloex.github.io/Mini-WAF/](https://murylloex.github.io/Mini-WAF/)** (GitHub **Project Pages** on [MurylloEx/Mini-WAF](https://github.com/MurylloEx/Mini-WAF)).

## Local commands

From the repository root:

```bash
npm run docs:dev      # http://localhost:5173 (default VitePress port)
npm run docs:build    # writes docs/.vitepress/dist
npm run docs:preview  # serve the production build locally
```

## Primary path — Project Pages on this repo

Assets must live under the `/Mini-WAF/` base path:

```bash
DOCS_BASE=/Mini-WAF/ npm run docs:build
```

CI does this automatically. The workflow [`.github/workflows/docs.yml`](../../.github/workflows/docs.yml) builds with `DOCS_BASE=/Mini-WAF/` and deploys via `actions/upload-pages-artifact` + `actions/deploy-pages`.

In the repo **Settings → Pages**, set the source to **GitHub Actions**.

Site URL: `https://murylloex.github.io/Mini-WAF/`

## Optional — dedicated user/org site (`*.github.io`)

A bare host like `https://mini-waf.github.io` needs a GitHub user or organization named `mini-waf` and a repo named `mini-waf.github.io`. That is a separate setup, not the default for this personal repo.

1. Keep `base: '/'` (default). Do **not** set `DOCS_BASE`.
2. Build with `npm run docs:build`.
3. Publish `docs/.vitepress/dist` to that dedicated Pages repo (or another host).

## Example GitHub Actions (this repo)

The maintained workflow already covers build + deploy. Minimal build fragment:

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
      - run: DOCS_BASE=/Mini-WAF/ npm run docs:build
      # then upload docs/.vitepress/dist via actions/upload-pages-artifact
```

## Logo & branding

The site logo is `docs/public/mini-waf-logo.png` (copied from the repo-root `mini-waf-logo.png`). Theme accents use the logo red (`#E60000`) on a dark background.
