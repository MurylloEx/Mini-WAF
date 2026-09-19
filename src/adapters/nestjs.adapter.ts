import {
  createExpressAdapter,
  type ExpressLikeRequest,
  type ExpressLikeResponse,
  type ExpressNext,
} from '@/adapters/express.adapter';
import {
  createFastifyAdapter,
  type FastifyLikeRequest,
  type FastifyLikeReply,
} from '@/adapters/fastify.adapter';
import type { WafAdapter, WafHttpContext } from '@/domain/context';
import type { HeaderMap, JsonValue, QueryMap, UploadedFile } from '@/domain/values';

export type NestPlatform = 'express' | 'fastify' | 'auto';

export type NestRequest = ExpressLikeRequest | FastifyLikeRequest;
export type NestResponse = ExpressLikeResponse | FastifyLikeReply;

function isFastifyReply(res: NestResponse): res is FastifyLikeReply {
  return (
    'code' in res &&
    typeof res.code === 'function' &&
    'send' in res &&
    typeof res.send === 'function' &&
    'header' in res &&
    typeof res.header === 'function'
  );
}

function isExpressResponse(res: NestResponse): res is ExpressLikeResponse {
  return !isFastifyReply(res);
}

function looksLikeFastifyRequest(req: NestRequest): boolean {
  return 'server' in req || ('ips' in req && Array.isArray(req.ips));
}

function toFastifyRequest(req: NestRequest): FastifyLikeRequest {
  const headers: HeaderMap = req.headers;
  const query: QueryMap | undefined =
    'query' in req && req.query && !Array.isArray(req.query)
      ? req.query
      : undefined;

  const files: readonly UploadedFile[] | undefined =
    'files' in req && Array.isArray(req.files) ? req.files : undefined;

  const body: string | Buffer | JsonValue | undefined =
    'body' in req ? req.body : undefined;

  const rawBody: string | Buffer | undefined =
    'rawBody' in req ? req.rawBody : undefined;

  const routerPath =
    'routerPath' in req && typeof req.routerPath === 'string'
      ? req.routerPath
      : undefined;
  const ips =
    'ips' in req && Array.isArray(req.ips) ? req.ips : undefined;
  const raw =
    'raw' in req && req.raw !== undefined ? req.raw : undefined;
  const server =
    'server' in req && req.server !== undefined ? req.server : undefined;

  return {
    method: req.method,
    url: req.url,
    headers,
    ...(routerPath !== undefined ? { routerPath } : {}),
    ...(req.protocol !== undefined ? { protocol: req.protocol } : {}),
    ...(req.ip !== undefined ? { ip: req.ip } : {}),
    ...(ips !== undefined ? { ips } : {}),
    ...(query !== undefined ? { query } : {}),
    ...(body !== undefined ? { body } : {}),
    ...(rawBody !== undefined ? { rawBody } : {}),
    ...(files !== undefined ? { files } : {}),
    ...(raw !== undefined ? { raw } : {}),
    ...(server !== undefined ? { server } : {}),
  };
}

function toIncomingHeaders(headers: HeaderMap): ExpressLikeRequest['headers'] {
  const out: Record<string, string | string[] | undefined> = {};
  for (const key of Object.keys(headers)) {
    out[key] = headers[key];
  }
  return out;
}

function toExpressRequest(req: NestRequest): ExpressLikeRequest {
  const originalUrl =
    'originalUrl' in req && typeof req.originalUrl === 'string'
      ? req.originalUrl
      : undefined;
  const query = 'query' in req ? req.query : undefined;
  const body = 'body' in req ? req.body : undefined;
  const rawBody = 'rawBody' in req ? req.rawBody : undefined;
  const files =
    'files' in req && req.files !== undefined && !Array.isArray(req.files)
      ? req.files
      : undefined;
  const socket =
    'socket' in req && req.socket !== undefined ? req.socket : undefined;
  const connection =
    'connection' in req && req.connection !== undefined
      ? req.connection
      : undefined;
  const get =
    'get' in req && typeof req.get === 'function' ? req.get : undefined;

  return {
    method: req.method,
    url: req.url,
    headers: toIncomingHeaders(req.headers),
    ...(originalUrl !== undefined ? { originalUrl } : {}),
    ...(req.protocol !== undefined ? { protocol: req.protocol } : {}),
    ...(req.ip !== undefined ? { ip: req.ip } : {}),
    ...(query !== undefined ? { query } : {}),
    ...(body !== undefined ? { body } : {}),
    ...(rawBody !== undefined ? { rawBody } : {}),
    ...(files !== undefined ? { files } : {}),
    ...(socket !== undefined ? { socket } : {}),
    ...(connection !== undefined ? { connection } : {}),
    ...(get !== undefined ? { get } : {}),
  };
}

/**
 * NestJS adapter that delegates to Express or Fastify adapters.
 * Detection uses type guards + explicit mapping (no unsafe casts).
 */
export function createNestAdapter(
  platform: NestPlatform = 'auto',
): WafAdapter<NestRequest, NestResponse, ExpressNext> {
  const expressAdapter = createExpressAdapter();
  const fastifyAdapter = createFastifyAdapter();

  return {
    name: 'nestjs',
    async createContext(req, res, next): Promise<WafHttpContext> {
      const useFastify =
        platform === 'fastify' ||
        (platform === 'auto' &&
          (isFastifyReply(res) || looksLikeFastifyRequest(req)));

      if (useFastify && isFastifyReply(res)) {
        return fastifyAdapter.createContext(toFastifyRequest(req), res);
      }

      if (isExpressResponse(res)) {
        return expressAdapter.createContext(toExpressRequest(req), res, next);
      }

      // Fallback: treat as Express-shaped response surface.
      return expressAdapter.createContext(
        toExpressRequest(req),
        {
          end: () => undefined,
        },
        next,
      );
    },
  };
}
