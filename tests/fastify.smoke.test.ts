import { describe, expect, it } from 'vitest';
import Fastify from 'fastify';
import { fastifyWaf } from '@/fastify';

describe('fastify smoke', () => {
  it('blocks scanner UA and allows clean GET', async () => {
    const app = Fastify();
    await app.register(fastifyWaf, {
      config: { presets: ['scanners'] },
    });
    app.get('/ping', async () => 'pong');

    const clean = await app.inject({
      method: 'GET',
      url: '/ping',
      headers: { 'user-agent': 'Mozilla/5.0' },
    });
    expect(clean.statusCode).toBe(200);
    expect(clean.body).toBe('pong');

    const evil = await app.inject({
      method: 'GET',
      url: '/ping',
      headers: { 'user-agent': 'nikto/2.1' },
    });
    expect(evil.statusCode).toBe(403);

    await app.close();
  });
});
