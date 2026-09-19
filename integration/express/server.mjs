import express from 'express';
import { expressWaf } from 'mini-waf/express';

const PORT = Number(process.env.PORT || 3101);

const app = express();

// Body parsers MUST run before the WAF so body rules can fire.
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

app.use(
  expressWaf({
    presets: ['default'],
    level: 'balanced',
  }),
);

app.get('/', (_req, res) => {
  res.json({ app: 'express', ok: true });
});

app.get('/health', (_req, res) => {
  res.json({ status: 'ok' });
});

app.get('/search', (req, res) => {
  res.json({ q: req.query.q ?? null });
});

app.post('/echo', (req, res) => {
  res.json({ body: req.body });
});

app.listen(PORT, '127.0.0.1', () => {
  console.log(`[express] listening on http://127.0.0.1:${PORT}`);
});
