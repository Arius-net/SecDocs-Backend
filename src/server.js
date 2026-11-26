import { config } from './config/env.js';
import { pool } from './db/pool.js';
import { runMigrations } from './db/migrate.js';
import { createApp } from './app.js';
import { startJobs, stopJobs } from './jobs/index.js';

async function main() {
  const applied = await runMigrations();
  console.log(applied.length ? `[db] migraciones aplicadas: ${applied.join(', ')}` : '[db] esquema al día');

  const app = createApp();
  const server = app.listen(config.port, '0.0.0.0', () => {
    console.log(`[api] SecDocs v2 escuchando en 0.0.0.0:${config.port} (${config.nodeEnv})`);
  });
  const jobs = startJobs(); // no programa nada con NODE_ENV=test

  const shutdown = (signal) => {
    console.log(`[api] ${signal} recibido, cerrando...`);
    stopJobs(jobs);
    server.close(async () => {
      await pool.end().catch(() => {});
      process.exit(0);
    });
    setTimeout(() => process.exit(1), 10_000).unref();
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

main().catch((err) => {
  console.error('[fatal]', err.message);
  process.exit(1);
});
