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
 *
 * Nest resolves middleware classes via `new MiniWafMiddleware(...)` and cannot
 * inject options without `@Inject` from `@nestjs/common`. `MiniWafModule.forRoot`
 * therefore binds options onto the class before Nest instantiates the middleware.
 */
export class MiniWafMiddleware {
  private static boundOptions: NestMiniWafOptions | undefined;

  /** Used by {@link MiniWafModule.forRoot}. */
  static bindOptions(options: NestMiniWafOptions): void {
    MiniWafMiddleware.boundOptions = options;
  }

  private readonly waf;
  private readonly adapter;

  constructor(options?: NestMiniWafOptions) {
    const resolved = options ?? MiniWafMiddleware.boundOptions;
    if (resolved === undefined) {
      throw new Error(
        'MiniWafMiddleware requires options: use MiniWafModule.forRoot({ config }) before consumer.apply(MiniWafMiddleware), or pass options to the constructor / nestMiddleware().',
      );
    }
    this.waf = createMiniWaf(resolveConfig(resolved), resolved);
    this.adapter = createNestAdapter(resolved.platform ?? 'auto');
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

/**
 * Nest-compatible DynamicModule shape (no `@nestjs/common` import).
 * Arrays are mutable so they assign to Nest's `Provider[]` / `exports`.
 */
export interface MiniWafDynamicModule {
  module: typeof MiniWafModule;
  providers: Array<
    | { provide: typeof MINI_WAF_OPTIONS; useValue: NestMiniWafOptions }
    | {
        provide: typeof MiniWafMiddleware;
        useFactory: (opts: NestMiniWafOptions) => MiniWafMiddleware;
        inject: [typeof MINI_WAF_OPTIONS];
      }
  >;
  exports: Array<typeof MiniWafMiddleware | typeof MINI_WAF_OPTIONS>;
  global: true;
}

/**
 * Nest-compatible dynamic module (plain class — no `@nestjs/common` import).
 * Nest requires `DynamicModule.module` to be a constructor; a plain object
 * causes `TypeError: metatype is not a constructor` at bootstrap.
 */
export class MiniWafModule {
  static forRoot(options: NestMiniWafOptions): MiniWafDynamicModule {
    MiniWafMiddleware.bindOptions(options);
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
  }
}

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
