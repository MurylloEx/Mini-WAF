import {
  Module,
  NestModule,
  MiddlewareConsumer,
  RequestMethod,
} from '@nestjs/common';
import { MiniWafModule, MiniWafMiddleware } from 'mini-waf/nestjs';
import { AppController } from './app.controller.js';

@Module({
  imports: [
    MiniWafModule.forRoot({
      config: {
        presets: ['default'],
        level: 'balanced',
      },
      platform: 'express',
    }),
  ],
  controllers: [AppController],
})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    // Nest/Express body parser runs before middleware; WAF sees JSON bodies.
    consumer
      .apply(MiniWafMiddleware)
      .forRoutes({ path: '{*path}', method: RequestMethod.ALL });
  }
}
