# Mini-WAF integration harness

Minimal apps exercise the local `mini-waf` package against real frameworks.

| App | Port | Entry |
|-----|------|--------|
| Express 5 | `3101` | `express/server.mjs` |
| Fastify 5 | `3102` | `fastify/server.mjs` |
| NestJS (Express) | `3103` | `nestjs-express/src/main.ts` |
| Koa (custom adapter) | `3104` | `koa/server.mjs` |

Shared WAF config: `{ presets: ['default'], level: 'balanced' }`.

## Setup

From the library root:

```bash
npm run build
cd integration
npm install
```

`npm install` in `integration/` installs deps for all apps (and links `mini-waf` via `file:../..`).

## Run one app manually

```bash
cd express && npm start          # :3101
cd fastify && npm start          # :3102
cd nestjs-express && npm start   # :3103
cd koa && npm start              # :3104
```

Routes on each app: `GET /`, `GET /health`, `GET /search?q=`, `POST /echo`.

## Run the scenario suite

Starts all servers, runs attacks, then tears them down:

```bash
# from integration/
npm run integration

# or from library root
npm run integration
```

Scenarios only (servers already running):

```bash
node scenarios/run.mjs --no-start
```

See [scenarios.md](./scenarios.md) for the full checklist, expected status codes, and framework notes.

## Order note

Body inspection requires a parser **before** the WAF (Express/Nest/Koa) or Fastify’s built-in parser before `preHandler`. These apps follow that order on purpose.
