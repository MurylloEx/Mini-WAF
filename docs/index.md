<!--
  Landing page. It is still Markdown: HTML blocks are passed through as-is,
  fenced code blocks are highlighted like any other page.
  Keep each HTML block free of blank lines (a blank line ends an HTML block
  in Markdown, and indented lines after it would turn into code).
-->

<section class="hero">
  <div class="hero-bricks" aria-hidden="true"></div>
  <div class="hero-copy">
    <span class="eyebrow"><span class="dot"></span> v1.2 · 94 rules · zero dependencies</span>
    <h1 class="hero-title">A firewall that lives <em>inside</em> your Node app.</h1>
    <p class="hero-lede">Mini-WAF inspects every request against typed, CRS-inspired rules — SQL &amp; NoSQL injection, XSS, Log4Shell, path traversal, RCE and protocol abuse — and blocks it before your route ever runs.</p>
    <div class="hero-actions">
      <a class="btn btn-primary" href="/guide/quick-start">Get started <span aria-hidden="true">→</span></a>
      <a class="btn btn-ghost" href="/guide/introduction">Read the guide</a>
    </div>
    <button class="install" data-copy="npm install mini-waf" type="button" aria-label="Copy install command">
      <span class="install-prompt">$</span><code>npm install mini-waf</code><span class="install-hint">copy</span>
    </button>
  </div>
  <div class="hero-art">
    <img src="/assets/img/mini-waf-mark.png" alt="Mini-WAF mark: a brick wall with a shield" width="340" height="340">
  </div>
</section>

<section class="flow" aria-label="Animated diagram: requests reaching the firewall">
  <div class="flow-head">
    <span class="flow-label">incoming</span>
    <span class="flow-label flow-label-mid">mini-waf</span>
    <span class="flow-label">your routes</span>
  </div>
  <div class="flow-track">
    <div class="flow-wall" aria-hidden="true"><span></span></div>
    <div class="packet ok" style="--lane:0;--delay:0s">GET /health</div>
    <div class="packet bad" style="--lane:1;--delay:.9s">?id=1' OR 1=1 --</div>
    <div class="packet ok" style="--lane:2;--delay:1.8s">POST /orders</div>
    <div class="packet bad" style="--lane:0;--delay:2.7s">&lt;script&gt;alert(1)&lt;/script&gt;</div>
    <div class="packet bad" style="--lane:1;--delay:3.6s">${jndi:ldap://x}</div>
    <div class="packet ok" style="--lane:2;--delay:4.5s">?q=running+shoes</div>
    <div class="packet bad" style="--lane:0;--delay:5.4s">../../etc/passwd</div>
    <div class="packet bad" style="--lane:2;--delay:6.3s">UA: sqlmap/1.7</div>
    <div class="packet ok" style="--lane:1;--delay:7.2s">GET /search</div>
    <div class="packet bad" style="--lane:1;--delay:8.1s">{"user":{"$ne":null}}</div>
  </div>
  <p class="flow-caption">Clean traffic passes untouched. Attacks get a <code>403</code> before a single line of your handler runs.</p>
</section>

<section class="stats">
  <div class="stat"><strong>94</strong><span>rules in the default pack</span></div>
  <div class="stat"><strong>7</strong><span>CRS-inspired categories</span></div>
  <div class="stat"><strong>~13&nbsp;µs</strong><span>per clean request at <code>balanced</code></span></div>
  <div class="stat"><strong>0</strong><span>runtime dependencies</span></div>
</section>

## One line to protect an app

Parse the body, mount the WAF, then your routes. That's the whole integration.

```ts
// server.ts
import express from 'express';
import { expressWaf } from 'mini-waf/express';

const app = express();
app.use(express.json());
app.use(expressWaf({ presets: ['default'], level: 'balanced' }));

app.get('/search', (req, res) => res.json({ q: req.query.q }));
app.listen(3000);
```

<section class="features">
  <article class="feature">
    <div class="feature-icon"><svg viewBox="0 0 24 24"><polygon points="12 2 2 7 12 12 22 7 12 2"/><polyline points="2 17 12 22 22 17"/><polyline points="2 12 12 17 22 12"/></svg></div>
    <h3>Framework-agnostic core</h3>
    <p>The engine only ever sees a <code>WafHttpContext</code>. Express, Fastify and NestJS ship built in — Koa, Hono, Hapi and Next.js are a dozen lines away.</p>
  </article>
  <article class="feature">
    <div class="feature-icon"><svg viewBox="0 0 24 24"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg></div>
    <h3>Typed presets</h3>
    <p>SQLi, NoSQL, XSS, RCE, RFI, path traversal, scanners and protocol abuse — every rule has a stable public id you can disable.</p>
  </article>
  <article class="feature">
    <div class="feature-icon"><svg viewBox="0 0 24 24"><line x1="4" y1="21" x2="4" y2="14"/><line x1="4" y1="10" x2="4" y2="3"/><line x1="12" y1="21" x2="12" y2="12"/><line x1="12" y1="8" x2="12" y2="3"/><line x1="20" y1="21" x2="20" y2="16"/><line x1="20" y1="12" x2="20" y2="3"/><line x1="1" y1="14" x2="7" y2="14"/><line x1="9" y1="8" x2="15" y2="8"/><line x1="17" y1="16" x2="23" y2="16"/></svg></div>
    <h3>Four protection levels</h3>
    <p>One dial from <code>low</code> to <code>paranoid</code> trades coverage against false positives — and doubles as your performance knob.</p>
  </article>
  <article class="feature">
    <div class="feature-icon"><svg viewBox="0 0 24 24"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg></div>
    <h3>Declarative rules</h3>
    <p>Compose <code>block</code>, <code>allow</code> and <code>log</code> rules from field matchers, <code>all</code> / <code>anyOf</code> / <code>not</code> and rate limits — or load them from JSON.</p>
  </article>
  <article class="feature">
    <div class="feature-icon"><svg viewBox="0 0 24 24"><polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2"/></svg></div>
    <h3>Built to be cheap</h3>
    <p>Literal prefilters skip regex passes, values are memoized per request, and an optional decision cache answers repeat traffic in ~2&nbsp;µs.</p>
  </article>
  <article class="feature">
    <div class="feature-icon"><svg viewBox="0 0 24 24"><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/><polyline points="3.27 6.96 12 12.01 20.73 6.96"/><line x1="12" y1="22.08" x2="12" y2="12"/></svg></div>
    <h3>Nothing to install twice</h3>
    <p>Zero runtime dependencies, dual CJS + ESM, tree-shakeable, fully typed. Framework peers are optional.</p>
  </article>
</section>

## Pick how strict you want to be

<section class="levels" data-levels>
  <div class="levels-tabs" role="tablist">
    <button role="tab" data-level="low" data-count="19" data-desc="High-confidence signatures only: scanners, classic SQLi, traversal, stream-wrapper RFI, shell & PHP RCE, Log4Shell, reverse shells. For APIs that cannot afford a false positive.">low</button>
    <button role="tab" data-level="balanced" data-count="51" data-desc="The default. Adds XSS, SQLi tautologies, NoSQL operators, SSTI, deserialization, protocol smuggling and per-IP DoS rate limiting. General production.">balanced</button>
    <button role="tab" data-level="high" data-count="81" data-desc="Adds blind & JSON SQLi, prototype pollution, XXE, LDAP and mail injection — and auto-enables Base64, URL and SQL-comment decoding. For when you are under attack.">high</button>
    <button role="tab" data-level="paranoid" data-count="94" data-desc="Every rule, including broad heuristics: generic HTML tags, oversized headers, internal-host SSRF, GraphQL introspection. Maximum coverage; expect to tune.">paranoid</button>
  </div>
  <div class="levels-body">
    <div class="levels-count"><strong data-out="count">51</strong><span>active rules</span></div>
    <div class="levels-meter"><div class="levels-fill" data-out="fill"></div></div>
    <p class="levels-desc" data-out="desc"></p>
    <a class="levels-link" href="/guide/protection-levels">How levels work →</a>
  </div>
</section>

## Works with your framework

<section class="frameworks">
  <a class="fw" href="/guide/integrations/express"><span class="fw-mono"><img src="/assets/img/fw/express.svg" alt=""></span><span class="fw-name">Express</span><span class="fw-tag">built-in</span></a>
  <a class="fw" href="/guide/integrations/fastify"><span class="fw-mono"><img src="/assets/img/fw/fastify.svg" alt=""></span><span class="fw-name">Fastify</span><span class="fw-tag">built-in</span></a>
  <a class="fw" href="/guide/integrations/nestjs"><span class="fw-mono"><img src="/assets/img/fw/nestjs.svg" alt=""></span><span class="fw-name">NestJS</span><span class="fw-tag">built-in</span></a>
  <a class="fw" href="/guide/integrations/koa"><span class="fw-mono"><img class="wide" src="/assets/img/fw/koa.svg" alt=""></span><span class="fw-name">Koa</span><span class="fw-tag">adapter</span></a>
  <a class="fw" href="/guide/integrations/hono"><span class="fw-mono"><img src="/assets/img/fw/hono.svg" alt=""></span><span class="fw-name">Hono</span><span class="fw-tag">adapter</span></a>
  <a class="fw" href="/guide/integrations/hapi"><span class="fw-mono"><img class="wide" src="/assets/img/fw/hapi.svg" alt=""></span><span class="fw-name">Hapi</span><span class="fw-tag">adapter</span></a>
  <a class="fw" href="/guide/integrations/nextjs"><span class="fw-mono"><img src="/assets/img/fw/nextdotjs.svg" alt=""></span><span class="fw-name">Next.js</span><span class="fw-tag">adapter</span></a>
  <a class="fw" href="/guide/integrations/custom-adapters"><span class="fw-mono"><svg viewBox="0 0 24 24"><path d="M12 22v-5"/><path d="M9 8V2"/><path d="M15 8V2"/><path d="M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z"/></svg></span><span class="fw-name">Anything else</span><span class="fw-tag">createAdapter</span></a>
</section>

<section class="cta">
  <h2>Ready when your traffic is.</h2>
  <p>Start with <code>balanced</code>, watch the logs, raise the level when you need it.</p>
  <div class="hero-actions">
    <a class="btn btn-primary" href="/guide/quick-start">Quick start <span aria-hidden="true">→</span></a>
    <a class="btn btn-ghost" href="/guide/presets">Browse the rules</a>
  </div>
</section>
