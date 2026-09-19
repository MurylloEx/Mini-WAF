import Koa from 'koa';
import Router from '@koa/router';
import bodyParser from 'koa-bodyparser';
import { createAdapter, createMiniWaf } from 'mini-waf';

const PORT = Number(process.env.PORT || 3104);

const waf = createMiniWaf({
  presets: ['default'],
  level: 'balanced',
});

/** Custom adapter path (no built-in Koa integration). */
const koaAdapter = createAdapter({
  name: 'koa',
  getMethod: (ctx) => ctx.method,
  getUrl: (ctx) => ctx.url,
  getPath: (ctx) => ctx.path,
  getIp: (ctx) => ctx.ip,
  getHeader: (ctx, name) => ctx.get(name) || undefined,
  getHeaders: (ctx) => ctx.headers,
  getQuery: (ctx) => ctx.query,
  getRawBody: (ctx) => ctx.request.body ?? '',
  setResponseHeader: (ctx, name, value) => ctx.set(name, String(value)),
  drop: (ctx, _res, status, body) => {
    ctx.status = status;
    ctx.body = body;
  },
});

const app = new Koa();
const router = new Router();

// Body parser MUST run before the WAF so body rules can fire.
app.use(bodyParser({ enableTypes: ['json', 'form'] }));

app.use(async (ctx, next) => {
  const result = await waf.protect(koaAdapter, ctx, ctx);
  if (result.decision === 'allow') {
    await next();
  }
});

router.get('/', (ctx) => {
  ctx.body = { app: 'koa', ok: true };
});

router.get('/health', (ctx) => {
  ctx.body = { status: 'ok' };
});

router.get('/search', (ctx) => {
  ctx.body = { q: ctx.query.q ?? null };
});

router.post('/echo', (ctx) => {
  ctx.body = { body: ctx.request.body };
});

app.use(router.routes());
app.use(router.allowedMethods());

app.listen(PORT, '127.0.0.1', () => {
  console.log(`[koa] listening on http://127.0.0.1:${PORT}`);
});
