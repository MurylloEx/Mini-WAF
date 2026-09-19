import type { WafHttpContext } from '@/domain/context';
import type { CookieMap, HeaderMap, QueryMap, UploadedFile } from '@/domain/values';
import { normalizeClientIp } from '@/utils/ip';

export interface MockRequestInput {
  readonly method?: string;
  readonly url?: string;
  readonly path?: string;
  readonly ip?: string;
  readonly protocol?: string;
  readonly port?: number;
  readonly headers?: HeaderMap;
  readonly query?: QueryMap;
  readonly cookies?: CookieMap;
  readonly body?: string;
  readonly files?: readonly UploadedFile[];
}

export interface MockContextHandle {
  readonly ctx: WafHttpContext;
  readonly dropped: {
    statusCode: number | undefined;
    body: string | undefined;
  };
  readonly responseHeaders: ReadonlyMap<string, string>;
}

/**
 * Build an immutable-friendly mock context for unit tests.
 * Internal blocked/drop state is encapsulated; domain view stays read-oriented.
 */
export function createMockContext(input: MockRequestInput = {}): MockContextHandle {
  let blocked = false;
  let dropStatus: number | undefined;
  let dropBody: string | undefined;
  let responseHeaders = new Map<string, string>();

  const headers: HeaderMap = input.headers ?? {};
  const query: QueryMap = input.query ?? {};
  const cookies: CookieMap = input.cookies ?? {};
  const files = input.files ?? [];
  const url = input.url ?? input.path ?? '/';
  const path = input.path ?? url.match(/^[^?]*/)?.[0] ?? '/';
  const ip = normalizeClientIp(input.ip ?? '127.0.0.1');

  const ctx: WafHttpContext = {
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
    get responseHeaders() {
      return responseHeaders;
    },
  };
}
