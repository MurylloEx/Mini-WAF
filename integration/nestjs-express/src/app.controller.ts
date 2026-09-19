import { Controller, Get, Post, Body, Query } from '@nestjs/common';

@Controller()
export class AppController {
  @Get()
  root() {
    return { app: 'nestjs-express', ok: true };
  }

  @Get('health')
  health() {
    return { status: 'ok' };
  }

  @Get('search')
  search(@Query('q') q?: string) {
    return { q: q ?? null };
  }

  @Post('echo')
  echo(@Body() body: unknown) {
    return { body };
  }
}
