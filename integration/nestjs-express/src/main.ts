import 'reflect-metadata';
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module.js';

const PORT = Number(process.env.PORT || 3103);

async function bootstrap() {
  const app = await NestFactory.create(AppModule, {
    logger: ['error', 'warn'],
  });
  await app.listen(PORT, '127.0.0.1');
  console.log(`[nestjs-express] listening on http://127.0.0.1:${PORT}`);
}

bootstrap().catch((err) => {
  console.error('[nestjs-express] bootstrap failed:', err);
  process.exit(1);
});
