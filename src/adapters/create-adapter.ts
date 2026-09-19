import type {
  CookieMap,
  FilesBag,
  HeaderMap,
  HeaderValue,
  JsonValue,
  QueryMap,
  UploadedFile,
} from '@/domain/values';
import { bodyToString, normalizeFiles } from '@/domain/values';
import type { WafAdapter, WafHttpContext } from '@/domain/context';
import { parseCookies } from '@/utils/cookies';
import { normalizeClientIp } from '@/utils/ip';

export interface CustomAdapterHandlers<TRequest, TResponse> {
  readonly name: string;
  readonly getMethod: (request: TRequest) => string;
  readonly getUrl: (request: TRequest) => string;
  readonly getPath?: (request: TRequest) => string;
  readonly getIp: (request: TRequest) => string;
  readonly getProtocol?: (request: TRequest) => string;
  readonly getLocalPort?: (request: TRequest, response: TResponse) => number;
  readonly getHeader: (request: TRequest, name: string) => string | undefined;
  readonly getHeaders: (request: TRequest) => HeaderMap;
  readonly getQuery: (request: TRequest) => QueryMap;
  readonly getCookies?: (request: TRequest) => CookieMap;
  readonly getRawBody: (
    request: TRequest,
  ) => string | Buffer | JsonValue | undefined | Promise<string | Buffer | JsonValue | undefined>;
  readonly getFiles?: (request: TRequest) => FilesBag | readonly UploadedFile[];
  readonly setResponseHeader: (
    response: TResponse,
    name: string,
    value: string | number,
  ) => void;
  readonly removeResponseHeader?: (response: TResponse, name: string) => void;
  readonly drop: (
    request: TRequest,
    response: TResponse,
    statusCode: number,
    body: string,
  ) => void;
}

/**
 * Build a WAF adapter for any framework by supplying typed request/response mappers.
 */
export function createAdapter<TRequest, TResponse>(
  handlers: CustomAdapterHandlers<TRequest, TResponse>,
): WafAdapter<TRequest, TResponse> {
  return {
    name: handlers.name,
    async createContext(request, response): Promise<WafHttpContext> {
      let blocked = false;
      const rawBody = bodyToString(
        await Promise.resolve(handlers.getRawBody(request)),
      );

      const url = handlers.getUrl(request);
      const path =
        handlers.getPath?.(request) ??
        (url.match(/^[^?]*/)?.[0] || url);

      const getHeader = (name: string): string | undefined =>
        handlers.getHeader(request, name);

      const ctx: WafHttpContext = {
        framework: handlers.name,
        getMethod: () => handlers.getMethod(request),
        getUrl: () => url,
        getPath: () => path,
        getIp: () => normalizeClientIp(handlers.getIp(request)),
        getProtocol: () => handlers.getProtocol?.(request) ?? 'http',
        getLocalPort: () =>
          handlers.getLocalPort?.(request, response) ?? 0,
        getHeader,
        getHeaders: () => handlers.getHeaders(request),
        getQuery: () => handlers.getQuery(request),
        getCookies: () =>
          handlers.getCookies?.(request) ??
          parseCookies(getHeader('cookie')),
        getRawBody: () => rawBody,
        getFiles: () => {
          const files = handlers.getFiles?.(request);
          if (!files) {
            return [];
          }
          if (Array.isArray(files)) {
            return files;
          }
          return normalizeFiles(files);
        },
        setResponseHeader: (name, value) =>
          handlers.setResponseHeader(response, name, value),
        removeResponseHeader: (name) =>
          handlers.removeResponseHeader?.(response, name),
        isBlocked: () => blocked,
        drop: (statusCode = 403, body = 'Forbidden') => {
          blocked = true;
          handlers.drop(request, response, statusCode, body);
        },
      };

      return ctx;
    },
  };
}

export type { HeaderValue };
