import type { WafConfig } from '@/domain/rules';
import type { WafEngineOptions } from '@/engine';
import { createMiniWaf, runWithAdapter } from '@/engine';
import {
  createFastifyAdapter,
  type FastifyLikeRequest,
  type FastifyLikeReply,
} from '@/adapters/fastify.adapter';

export interface FastifyPluginOptions extends WafEngineOptions {
  readonly settings?: WafConfig;
  readonly config?: WafConfig;
}

interface FastifyLikeInstance {
  /**
   * Structural subset of Fastify's `addHook`.
   * Wider than a single overload so real `FastifyInstance` remains assignable.
   */
  readonly addHook: (
    name: string,
    handler: (
      request: FastifyLikeRequest,
      reply: FastifyLikeReply,
    ) => void | Promise<void>,
  ) => unknown;
}

/**
 * Fastify plugin (register with `app.register(fastifyWaf, { config })`).
 * Marked with skip-override so hooks apply to parent routes.
 *
 * Declared `async` deliberately: Fastify 4's avvio treats a synchronous plugin
 * whose arity is 2 (no `done` callback) and which returns `undefined` as never
 * signalling completion, so the boot sequence (`listen`/`ready`/`inject`) hangs
 * forever. Returning a resolved promise is what makes the advertised
 * `fastify >= 4` peer range genuinely work; Fastify 5 is unaffected either way.
 */
export async function fastifyWaf(
  instance: FastifyLikeInstance,
  opts: FastifyPluginOptions,
): Promise<void> {
  const config = opts.config ?? opts.settings ?? { presets: ['default'] };
  const waf = createMiniWaf(config, opts);
  const adapter = createFastifyAdapter();

  instance.addHook('preHandler', async (request, reply) => {
    const { result } = await runWithAdapter(waf, adapter, request, reply);
    if (result.decision === 'block' && !reply.sent) {
      reply.code(403).send('Forbidden');
    }
  });
}

Object.assign(fastifyWaf, { [Symbol.for('skip-override')]: true });

/** Standalone Fastify preHandler for manual registration. */
export function fastifyPreHandler(
  config: WafConfig = { presets: ['default'] },
  options?: WafEngineOptions,
) {
  const waf = createMiniWaf(config, options);
  const adapter = createFastifyAdapter();

  return async (
    request: FastifyLikeRequest,
    reply: FastifyLikeReply,
  ): Promise<void> => {
    await runWithAdapter(waf, adapter, request, reply);
  };
}

/** Secure browser headers as a Fastify onRequest hook. */
export function fastifySecurityPolicy() {
  return async (
    request: FastifyLikeRequest,
    reply: FastifyLikeReply,
  ): Promise<void> => {
    reply.header('X-Frame-Options', 'sameorigin');
    reply.header('X-XSS-Protection', '1');
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.removeHeader?.('X-Powered-By');
    reply.removeHeader?.('Server');

    const origin = request.headers.origin;
    if (origin) {
      reply.header(
        'Access-Control-Allow-Origin',
        Array.isArray(origin) ? (origin[0] ?? '') : origin,
      );
    }
  };
}

export {
  createFastifyAdapter,
  type FastifyLikeRequest,
  type FastifyLikeReply,
} from '@/adapters/fastify.adapter';
