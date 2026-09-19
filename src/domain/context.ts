import type {
  CookieMap,
  HeaderMap,
  HeaderValue,
  QueryMap,
  UploadedFile,
} from '@/domain/values';

/**
 * Framework-agnostic HTTP view consumed by the WAF engine.
 * Adapters map Express / Fastify / Nest / custom runtimes onto this shape.
 */
export interface WafHttpContext {
  readonly framework: string;

  getMethod(): string;
  getUrl(): string;
  getPath(): string;
  getIp(): string;
  getProtocol(): string;
  getLocalPort(): number;

  getHeader(name: string): string | undefined;
  getHeaders(): HeaderMap;
  getQuery(): QueryMap;
  getCookies(): CookieMap;
  getRawBody(): string;
  getFiles(): readonly UploadedFile[];

  setResponseHeader(name: string, value: string | number): void;
  removeResponseHeader(name: string): void;

  isBlocked(): boolean;
  /** Ends the request with a block response (typically 403). */
  drop(statusCode?: number, body?: string): void;
}

/**
 * Maps a framework's request/response pair into a WafHttpContext.
 */
export interface WafAdapter<TRequest, TResponse, TNext = void> {
  readonly name: string;

  createContext(
    request: TRequest,
    response: TResponse,
    next?: TNext,
  ): WafHttpContext | Promise<WafHttpContext>;
}

export type { HeaderValue };
