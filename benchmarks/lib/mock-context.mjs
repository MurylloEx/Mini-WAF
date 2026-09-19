/**
 * Lightweight mock WafHttpContext for engine-only benches (mirrors tests helper).
 */

export function createMockContext(input = {}) {
  let blocked = false;
  let dropStatus;
  let dropBody;
  let responseHeaders = new Map();

  const headers = input.headers ?? {};
  const query = input.query ?? {};
  const cookies = input.cookies ?? {};
  const files = input.files ?? [];
  const url = input.url ?? input.path ?? '/';
  const path = input.path ?? (url.match(/^[^?]*/)?.[0] ?? '/');
  const ip = input.ip ?? '127.0.0.1';

  const ctx = {
    framework: 'mock',
    getMethod: () => input.method ?? 'GET',
    getUrl: () => url,
    getPath: () => path,
    getIp: () => ip,
    getProtocol: () => input.protocol ?? 'http',
    getLocalPort: () => input.port ?? 3000,
    getHeader: (name) => {
      const value = headers[name.toLowerCase()] ?? headers[name];
      return Array.isArray(value) ? value[0] : value;
    },
    getHeaders: () => headers,
    getQuery: () => query,
    getCookies: () => cookies,
    getRawBody: () => input.body ?? '',
    getFiles: () => files,
    setResponseHeader: (name, value) => {
      responseHeaders = new Map(responseHeaders).set(name, String(value));
    },
    removeResponseHeader: (name) => {
      const next = new Map(responseHeaders);
      next.delete(name);
      responseHeaders = next;
    },
    isBlocked: () => blocked,
    drop: (statusCode = 403, body = 'Forbidden') => {
      blocked = true;
      dropStatus = statusCode;
      dropBody = body;
    },
  };

  return {
    ctx,
    get dropped() {
      return { statusCode: dropStatus, body: dropBody };
    },
  };
}
