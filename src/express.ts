import {
  createExpressAdapter,
  type ExpressLikeRequest,
  type ExpressLikeResponse,
  type ExpressNext,
} from '@/adapters/express.adapter';
import { createMiniWaf, runWithAdapter } from '@/engine';
import type { WafEngineOptions } from '@/engine';
import type { WafConfig } from '@/domain/rules';

/**
 * Express 4/5 middleware factory (parallel to `fastifyWaf`).
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { expressWaf } from 'mini-waf/express';
 *
 * const app = express();
 * app.use(expressWaf({ presets: ['default'] }));
 * ```
 */
export function expressWaf(
  config: WafConfig = { presets: ['default'] },
  options?: WafEngineOptions,
) {
  const waf = createMiniWaf(config, options);
  const adapter = createExpressAdapter();

  return (
    req: ExpressLikeRequest,
    res: ExpressLikeResponse,
    next: ExpressNext,
  ): void => {
    runWithAdapter(waf, adapter, req, res, next)
      .then(({ result, ctx }) => {
        if (result.decision === 'allow' && !ctx.isBlocked()) {
          next();
        }
      })
      .catch((err: Error) => next(err));
  };
}

/** Secure browser headers middleware (Express). */
export function expressSecurityPolicy() {
  return (
    req: ExpressLikeRequest,
    res: ExpressLikeResponse,
    next: ExpressNext,
  ): void => {
    const set = (name: string, value: string) => {
      if (typeof res.set === 'function') {
        res.set(name, value);
      } else {
        res.setHeader?.(name, value);
      }
    };
    const get = (name: string): string | undefined => {
      if (typeof req.get === 'function') {
        return req.get(name);
      }
      const value = req.headers[name.toLowerCase()];
      return Array.isArray(value) ? value[0] : value;
    };

    set('X-Frame-Options', 'sameorigin');
    set('X-XSS-Protection', '1');
    set('X-Content-Type-Options', 'nosniff');
    res.removeHeader?.('X-Powered-By');
    res.removeHeader?.('Server');

    if (String(req.method || '').toUpperCase() === 'OPTIONS') {
      const origin = get('Origin');
      if (origin) {
        set('Access-Control-Allow-Origin', origin);
      }
      if (get('Access-Control-Request-Method')) {
        set(
          'Access-Control-Allow-Methods',
          'GET, POST, PUT, PATCH, DELETE, COPY, HEAD, OPTIONS',
        );
      }
      const reqHeaders = get('Access-Control-Request-Headers');
      if (reqHeaders) {
        set('Access-Control-Allow-Headers', reqHeaders);
      }
      set('Access-Control-Max-Age', '86400');
      set('Access-Control-Allow-Credentials', 'true');
    }

    const origin = get('Origin');
    if (origin) {
      set('Access-Control-Allow-Origin', origin);
    }
    next();
  };
}

export {
  createExpressAdapter,
  type ExpressLikeRequest,
  type ExpressLikeResponse,
  type ExpressNext,
} from '@/adapters/express.adapter';
