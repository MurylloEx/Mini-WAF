import { describe, expect, it } from 'vitest';
import { createAdapter } from '@/adapters/create-adapter';
import { createMiniWaf } from '@/engine';
import type { WafRule } from '@/domain/rules';

interface FakeRequest {
  readonly method: string;
  readonly url: string;
  readonly ip: string;
  readonly headers: Readonly<Record<string, string>>;
  readonly query: Readonly<Record<string, string>>;
  readonly body: string;
}

interface FakeResponse {
  statusCode: number;
  body: string;
  readonly headers: Map<string, string>;
}

describe('createAdapter', () => {
  it('maps a custom framework onto the engine', async () => {
    const rule: WafRule = {
      id: 'block-path',
      action: 'block',
      when: { field: 'path', includes: 'admin' },
    };

    const adapter = createAdapter<FakeRequest, FakeResponse>({
      name: 'fake',
      getMethod: (req) => req.method,
      getUrl: (req) => req.url,
      getIp: (req) => req.ip,
      getHeader: (req, name) => req.headers[name.toLowerCase()],
      getHeaders: (req) => req.headers,
      getQuery: (req) => req.query,
      getRawBody: (req) => req.body,
      setResponseHeader: (res, name, value) => {
        res.headers.set(name, String(value));
      },
      drop: (_req, res, status, body) => {
        res.statusCode = status;
        res.body = body;
      },
    });

    const waf = createMiniWaf(
      { rules: [rule] },
    );

    const request: FakeRequest = {
      method: 'GET',
      url: '/admin/users',
      ip: '1.2.3.4',
      headers: { 'user-agent': 'test' },
      query: {},
      body: '',
    };
    const response: FakeResponse = {
      statusCode: 200,
      body: '',
      headers: new Map(),
    };

    const result = await waf.protect(adapter, request, response);
    expect(result.decision).toBe('block');
    expect(response.statusCode).toBe(403);
    expect(response.body).toBe('Forbidden');
  });
});
