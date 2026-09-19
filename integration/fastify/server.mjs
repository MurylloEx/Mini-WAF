import Fastify from 'fastify';
import { fastifyWaf } from 'mini-waf/fastify';

const PORT = Number(process.env.PORT || 3102);

const app = Fastify({ logger: false });

// Fastify parses JSON by default before preHandler (where fastifyWaf hooks).
await app.register(fastifyWaf, {
  config: {
    presets: ['default'],
    level: 'balanced',
  },
});

app.get('/', async () => ({ app: 'fastify', ok: true }));

app.get('/health', async () => ({ status: 'ok' }));

app.get('/search', async (request) => ({
  q: request.query?.q ?? null,
}));

app.post('/echo', async (request) => ({
  body: request.body,
}));

await app.listen({ port: PORT, host: '127.0.0.1' });
console.log(`[fastify] listening on http://127.0.0.1:${PORT}`);
