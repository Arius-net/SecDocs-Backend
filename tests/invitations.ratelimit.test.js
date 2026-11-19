import './helpers/env.js';
import test, { after } from 'node:test';
import assert from 'node:assert/strict';

// El límite se fija ANTES de cargar la app (configuración leída al importar).
process.env.INVITATION_RATE_LIMIT_MAX = '3';
const { startServer, createClient } = await import('./helpers/http.js');
const { pool } = await import('../src/db/pool.js');
const { runMigrations } = await import('../src/db/migrate.js');

await runMigrations();
const srv = await startServer();
after(async () => {
  await srv.close();
  await pool.end();
});

test('rate limiter específico en /invitations/* y /shared/*: 429 con cabeceras estrictas', async () => {
  const c = createClient(srv.base);
  for (let i = 0; i < 3; i++) assert.equal((await c.get('/invitations/' + 'a'.repeat(32))).status, 404);
  const blocked = await c.get('/invitations/' + 'a'.repeat(32));
  assert.equal(blocked.status, 429);
  assert.match(blocked.json.error, /Demasiadas solicitudes/);
  assert.equal(blocked.headers.get('x-robots-tag'), 'noindex, nofollow, noarchive');
  assert.equal(blocked.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(blocked.headers.get('cache-control'), 'no-store');
  // Comparte el límite con /shared (por IP) y no afecta a otras rutas
  assert.equal((await c.get('/shared')).status, 429);
  assert.equal((await c.get('/health')).status, 200);
});
