import './helpers/env.js';
import test, { after } from 'node:test';
import assert from 'node:assert/strict';

// El límite se fija ANTES de cargar la app (configuración leída al importar).
process.env.AUTH_RATE_LIMIT_MAX = '5';
const { startServer, createClient, uniqueEmail } = await import('./helpers/http.js');
const { pool } = await import('../src/db/pool.js');
const { runMigrations } = await import('../src/db/migrate.js');

await runMigrations();
const srv = await startServer();
after(async () => {
  await srv.close();
  await pool.end();
});

test('rate limiter estricto en /auth/login y /auth/register (429 al exceder, compartido por IP)', async () => {
  const c = createClient(srv.base);
  const statuses = [];
  for (let i = 0; i < 5; i++) statuses.push((await c.post('/auth/login', { email: uniqueEmail(), password: 'x'.repeat(10) })).status);
  assert.deepEqual(statuses, [401, 401, 401, 401, 401]);
  const blocked = await c.post('/auth/login', { email: uniqueEmail(), password: 'x'.repeat(10) });
  assert.equal(blocked.status, 429);
  assert.match(blocked.json.error, /Demasiados intentos/);
  // register comparte el mismo limitador de autenticación
  assert.equal((await c.post('/auth/register', { email: uniqueEmail(), password: 'x'.repeat(10) })).status, 429);
  // /auth/me no está limitado por este limitador
  assert.equal((await c.get('/auth/me')).status, 401);
});
