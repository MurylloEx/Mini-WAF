import type { IncomingHttpHeaders } from 'http';
import type { WafAdapter, WafHttpContext } from '@/domain/context';
import type {
  FilesBag,
  HeaderMap,
  HeaderValue,
  JsonValue,
  QueryMap,
  UploadedFile,
} from '@/domain/values';
import {
  lazyBodyToString,
  normalizeFiles,
  scalarToString,
} from '@/domain/values';
import { parseCookies } from '@/utils/cookies';
import { normalizeClientIp, pickClientIpFromXff } from '@/utils/ip';

/** Minimal Express-like shapes (compatible with Express 4/5). */
export interface ExpressLikeRequest {
  // Optional because Node's own `IncomingMessage` types them as
  // `string | undefined`; the adapter already falls back to 'GET' and '/'.
  // Keeping them required would reject Next.js' `NextApiRequest`.
  readonly method?: string | undefined;
  readonly url?: string | undefined;
  readonly originalUrl?: string;
  readonly protocol?: string;
  readonly ip?: string;
  readonly query?: QueryMap;
  readonly headers: IncomingHttpHeaders;
  readonly body?: string | Buffer | JsonValue;
  readonly rawBody?: string | Buffer;
  readonly files?: FilesBag;
  readonly socket?: { readonly remoteAddress?: string; readonly localPort?: number };
  readonly connection?: {
    readonly remoteAddress?: string;
    readonly localPort?: number;
  };
  readonly get?: (name: string) => string | undefined;
}

export interface ExpressLikeResponse {
  statusCode?: number;
  readonly headersSent?: boolean;
  readonly writableEnded?: boolean;
  // These three are declared as returning void because the adapter ignores
  // their result. TypeScript lets a function returning a value satisfy a
  // void-returning signature, so Express (returns the response) and
  // Next.js' NextApiResponse (returns void) both fit.
  readonly send?: (body?: string) => void;
  readonly end?: (body?: string) => void;
  readonly set?: (name: string, value: string) => void;
  readonly header?: (name: string, value: string) => void;
  // `status` is the exception: the adapter chains `.end()` off its result.
  readonly status?: (code: number) => ExpressLikeResponse;
  readonly setHeader?: (
    name: string,
    value: string | number | readonly string[],
  ) => void;
  readonly removeHeader?: (name: string) => void;
}

export type ExpressNext = (err?: Error) => void;

function headerMapFromIncoming(headers: IncomingHttpHeaders): HeaderMap {
  const out: Record<string, HeaderValue> = {};
  for (const key of Object.keys(headers)) {
    const value = headers[key];
    if (typeof value === 'string' || Array.isArray(value) || value === undefined) {
      out[key] = value;
    } else {
      out[key] = String(value);
    }
  }
  return out;
}

function resolveIp(req: ExpressLikeRequest): string {
  if (req.ip) {
    return normalizeClientIp(req.ip);
  }
  const fromXff = pickClientIpFromXff(req.headers['x-forwarded-for']);
  if (fromXff.length > 0) {
    return fromXff;
  }
  return normalizeClientIp(
    req.connection?.remoteAddress || req.socket?.remoteAddress || '',
  );
}

/**
 * Adapter mapping Express `req`/`res` onto a {@link WafHttpContext}.
 *
 * Use it with `createMiniWaf(...).protect(...)` when you need the WAF outside
 * the `expressWaf` middleware — otherwise prefer that helper.
 *
 * The body is read lazily, so a request that never reaches a `body`-scoped
 * rule pays nothing, and the client IP is resolved from `req.ip`, the first
 * `X-Forwarded-For` hop, then the socket address.
 */
export function createExpressAdapter(): WafAdapter<
  ExpressLikeRequest,
  ExpressLikeResponse,
  ExpressNext
> {
  return {
    name: 'express',
    createContext(req, res): WafHttpContext {
      let blocked = false;
      const ip = resolveIp(req);
      // Deferred: only pays JSON.stringify (parsed body) / Buffer decode
      // cost the first time a rule actually inspects the `body` field.
      const getRawBody = lazyBodyToString(() => req.rawBody ?? req.body);
      const url = req.originalUrl || req.url || '/';
      const path = url.match(/^[^?]*/)?.[0] || '/';

      const getHeader = (name: string): string | undefined => {
        if (typeof req.get === 'function') {
          return req.get(name);
        }
        const value = req.headers[name.toLowerCase()];
        return Array.isArray(value) ? value[0] : value;
      };

      const files: readonly UploadedFile[] = normalizeFiles(req.files);

      return {
        framework: 'express',
        getMethod: () => req.method || 'GET',
        getUrl: () => url,
        getPath: () => path,
        getIp: () => ip,
        getProtocol: () => req.protocol || 'http',
        getLocalPort: () =>
          Number(req.socket?.localPort || req.connection?.localPort || 0),
        getHeader,
        getHeaders: () => headerMapFromIncoming(req.headers),
        getQuery: () => req.query ?? {},
        getCookies: () => parseCookies(getHeader('cookie')),
        getRawBody,
        getFiles: () => files,
        setResponseHeader: (name, value) => {
          if (typeof res.set === 'function') {
            res.set(name, String(value));
          } else if (typeof res.setHeader === 'function') {
            res.setHeader(name, String(value));
          }
        },
        removeResponseHeader: (name) => {
          res.removeHeader?.(name);
        },
        isBlocked: () => blocked,
        drop: (statusCode = 403, body = 'Forbidden') => {
          blocked = true;
          if (res.headersSent || res.writableEnded) {
            return;
          }
          if (typeof res.status === 'function' && typeof res.end === 'function') {
            res.status(statusCode).end?.(body);
          } else {
            res.statusCode = statusCode;
            res.end?.(body);
          }
        },
      };
    },
  };
}

export { scalarToString };
