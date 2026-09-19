export { createAdapter, type CustomAdapterHandlers } from '@/adapters/create-adapter';
export {
  createExpressAdapter,
  type ExpressLikeRequest,
  type ExpressLikeResponse,
  type ExpressNext,
} from '@/adapters/express.adapter';
export {
  createFastifyAdapter,
  type FastifyLikeRequest,
  type FastifyLikeReply,
} from '@/adapters/fastify.adapter';
export {
  createNestAdapter,
  type NestPlatform,
  type NestRequest,
  type NestResponse,
} from '@/adapters/nestjs.adapter';
