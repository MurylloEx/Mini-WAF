import type { WafConfig } from '@/domain/rules';
import type { WafEngineOptions } from '@/engine';
import { createMiniWaf, runWithAdapter } from '@/engine';
import {
  createNestAdapter,
  type NestPlatform,
  type NestRequest,
  type NestResponse,
} from '@/adapters/nestjs.adapter';
import type { ExpressNext } from '@/adapters/express.adapter';

export const MINI_WAF_OPTIONS = 'MINI_WAF_OPTIONS';

export interface NestMiniWafOptions extends WafEngineOptions {
  readonly settings?: WafConfig;
  readonly config?: WafConfig;
  /** Underlying Nest HTTP platform. Default: auto-detect. */
  readonly platform?: NestPlatform;
}

function resolveConfig(options: NestMiniWafOptions): WafConfig {
  return options.config ?? options.settings ?? { presets: ['default'] };
}

/**
 * NestJS middleware class (works with Express or Fastify platforms).
 */
export class MiniWafMiddleware {
  private readonly waf;
  private readonly adapter;

  constructor(options: NestMiniWafOptions) {
    this.waf = createMiniWaf(resolveConfig(options), options);
    this.adapter = createNestAdapter(options.platform ?? 'auto');
  }

  use(req: NestRequest, res: NestResponse, next: ExpressNext): void {
    runWithAdapter(this.waf, this.adapter, req, res, next)
      .then(({ result, ctx }) => {
        if (result.decision === 'allow' && !ctx.isBlocked()) {
          next();
        }
      })
      .catch((err: Error) => next(err));
  }
}

export interface MiniWafDynamicModule {
  readonly module: typeof MiniWafModule;
  readonly providers: readonly [
    { readonly provide: typeof MINI_WAF_OPTIONS; readonly useValue: NestMiniWafOptions },
    {
      readonly provide: typeof MiniWafMiddleware;
      readonly useFactory: (opts: NestMiniWafOptions) => MiniWafMiddleware;
      readonly inject: readonly [typeof MINI_WAF_OPTIONS];
    },
  ];
  readonly exports: readonly [
    typeof MiniWafMiddleware,
    typeof MINI_WAF_OPTIONS,
  ];
  readonly global: true;
}

/**
 * Lightweight Nest-style dynamic module descriptor.
 * Does not import `@nestjs/common` so the peer stays optional at compile time.
 */
export const MiniWafModule = {
  forRoot(options: NestMiniWafOptions): MiniWafDynamicModule {
    return {
      module: MiniWafModule,
      global: true,
      providers: [
        { provide: MINI_WAF_OPTIONS, useValue: options },
        {
          provide: MiniWafMiddleware,
          useFactory: (opts: NestMiniWafOptions) =>
            new MiniWafMiddleware(opts),
          inject: [MINI_WAF_OPTIONS],
        },
      ],
      exports: [MiniWafMiddleware, MINI_WAF_OPTIONS],
    };
  },
};

/** Functional Nest middleware factory. */
export function nestMiddleware(
  config: WafConfig = { presets: ['default'] },
  options?: Omit<NestMiniWafOptions, 'settings' | 'config'>,
) {
  const middleware = new MiniWafMiddleware({
    config,
    ...options,
  });
  return (req: NestRequest, res: NestResponse, next: ExpressNext) =>
    middleware.use(req, res, next);
}

export {
  createNestAdapter,
  type NestPlatform,
  type NestRequest,
  type NestResponse,
} from '@/adapters/nestjs.adapter';
