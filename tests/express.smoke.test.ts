import { describe, expect, it } from 'vitest';
import express from 'express';
import { expressWaf } from '@/express';
import type { Server } from 'http';

async function listen(app: express.Express): Promise<{
  readonly server: Server;
  readonly port: number;
}> {
  return new Promise((resolve) => {
    const server = app.listen(0, '127.0.0.1', () => {
      const address = server.address();
      if (address && typeof address === 'object') {
        resolve({ server, port: address.port });
      }
    });
  });
}

describe('express smoke', () => {
  it('blocks SQLi and allows clean GET', async () => {
    const app = express();
    app.use(
      expressWaf(
        { presets: ['sqli'] },
      ),
    );
    app.get('/items', (_req, res) => {
      res.status(200).send('ok');
    });

    const { server, port } = await listen(app);
    try {
      const clean = await fetch(`http://127.0.0.1:${port}/items?id=1`);
      expect(clean.status).toBe(200);
      expect(await clean.text()).toBe('ok');

      const evil = await fetch(
        `http://127.0.0.1:${port}/items?id=1%20UNION%20SELECT%201`,
      );
      expect(evil.status).toBe(403);
    } finally {
      await new Promise<void>((resolve, reject) => {
        server.close((err) => (err ? reject(err) : resolve()));
      });
    }
  });
});
