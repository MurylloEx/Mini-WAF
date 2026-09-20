import type { WafAdapter, WafHttpContext } from '@/domain/context';
import type {
  HeaderMap,
  JsonValue,
  QueryMap,
  UploadedFile,
} from '@/domain/values';
import { lazyBodyToString } from '@/domain/values';
import { parseCookies } from '@/utils/cookies';
import { normalizeClientIp, pickClientIpFromXff } from '@/utils/ip';

/** Minimal Fastify-like shapes. */
export interface FastifyLikeRequest {
  // Optional for the same reason as ExpressLikeRequest: the underlying Node
  // request types them as `string | undefined` and the adapter already falls
  // back to 'GET' and '/'.
  readonly method?: string | undefined;
  readonly url?: string | undefined;
  readonly routerPath?: string;
  readonly protocol?: string;
  readonly ip?: string;
  readonly ips?: readonly string[];
  readonly hostname?: string;
  readonly query?: QueryMap;
  readonly headers: HeaderMap;
  readonly body?: string | Buffer | JsonValue;
  readonly rawBody?: string | Buffer;
  readonly files?: readonly UploadedFile[];
  readonly raw?: {
    readonly socket?: {
      readonly remoteAddress?: string;
      readonly localPort?: number;
    };
  };
  readonly server?: object;
}

export interface FastifyLikeReply {
  readonly sent?: boolean;
  readonly raw?: {
    readonly headersSent?: boolean;
    readonly writableEnded?: boolean;
  };
  readonly code: (statusCode: number) => FastifyLikeReply;
  readonly status?: (statusCode: number) => FastifyLikeReply;
  readonly header: (name: string, value: string | number) => FastifyLikeReply;
  readonly removeHeader?: (name: string) => void;
  readonly send: (payload?: string) => FastifyLikeReply;
  readonly hijack?: () => void;
}

function resolveIp(req: FastifyLikeRequest): string {
  if (req.ip) {
    return normalizeClientIp(req.ip);
  }
  if (req.ips && req.ips.length > 0) {
    return normalizeClientIp(req.ips[0] ?? '');
  }
  const fromXff = pickClientIpFromXff(req.headers['x-forwarded-for']);
  if (fromXff.length > 0) {
    return fromXff;
  }
  return normalizeClientIp(req.raw?.socket?.remoteAddress ?? '');
}

/**
 * Adapter mapping a Fastify request/reply pair onto a {@link WafHttpContext}.
 *
 * Use it with `createMiniWaf(...).protect(...)` when you need the WAF outside
 * the `fastifyWaf` plugin — otherwise prefer that helper.
 */
export function createFastifyAdapter(): WafAdapter<
  FastifyLikeRequest,
  FastifyLikeReply
> {
  return {
    name: 'fastify',
    createContext(req, reply): WafHttpContext {
      let blocked = false;
      const ip = resolveIp(req);
      // Deferred: only pays JSON.stringify (parsed body) / Buffer decode
      // cost the first time a rule actually inspects the `body` field.
      const getRawBody = lazyBodyToString(() => req.rawBody ?? req.body);
      const url = req.url || '/';
      const path = req.routerPath || url.match(/^[^?]*/)?.[0] || '/';
      const files = req.files ? [...req.files] : [];

      const getHeader = (name: string): string | undefined => {
        const value = req.headers[name.toLowerCase()];
        if (Array.isArray(value)) {
          return value[0];
        }
        if (typeof value === 'string') {
          return value;
        }
        return undefined;
      };

      return {
        framework: 'fastify',
        getMethod: () => req.method || 'GET',
        getUrl: () => url,
        getPath: () => path,
        getIp: () => ip,
        getProtocol: () => req.protocol || 'http',
        getLocalPort: () => Number(req.raw?.socket?.localPort || 0),
        getHeader,
        getHeaders: () => req.headers,
        getQuery: () => req.query ?? {},
        getCookies: () => parseCookies(getHeader('cookie')),
        getRawBody,
        getFiles: () => files,
        setResponseHeader: (name, value) => {
          reply.header(name, value);
        },
        removeResponseHeader: (name) => {
          reply.removeHeader?.(name);
        },
        isBlocked: () => blocked,
        drop: (statusCode = 403, body = 'Forbidden') => {
          blocked = true;
          if (reply.sent || reply.raw?.headersSent) {
            return;
          }
          reply.code(statusCode).send(body);
        },
      };
    },
  };
}
