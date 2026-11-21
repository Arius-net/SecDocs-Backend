import './helpers/env.js';
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import { pool, query } from '../src/db/pool.js';
import { runMigrations } from '../src/db/migrate.js';
import { startServer, createClient, uniqueEmail } from './helpers/http.js';

let srv;
const createdEmails = [];

before(async () => {
  await runMigrations();
  srv = await startServer();
});

after(async () => {
  await query('DELETE FROM users WHERE lower(email) = ANY($1)', [createdEmails.map((e) => e.toLowerCase())]);
  await srv.close();
  await pool.end();
});

async function registerUser(tag) {
  const email = uniqueEmail(tag);
  createdEmails.push(email);
  const c = createClient(srv.base);
  const r = await c.post('/auth/register', { email, password: 'Contraseña-Segura-123' });
  assert.equal(r.status, 201);
  return { c, id: r.json.user.id };
}

const ownCount = async (id, extra = '', params = []) =>
  (await query(`SELECT count(*)::int AS n FROM access_logs WHERE owner_id = $1 ${extra}`, [id, ...params])).rows[0].n;

// ------------------------------- /audit/logs -------------------------------

test('GET /audit/logs: paginación, orden DESC, límite máximo y retentionPolicy', async () => {
  const A = await registerUser('audita');
  await query(
    `INSERT INTO access_logs (owner_id, event, ip, created_at)
     SELECT $1, CASE WHEN i % 3 = 0 THEN 'TEST_B' ELSE 'TEST_A' END, '10.0.0.1', now() - (i || ' minutes')::interval
       FROM generate_series(1, 45) AS i`,
    [A.id],
  );
  const total = await ownCount(A.id);
  assert.equal(total, 46); // 45 + USER_REGISTERED

  const p1 = await A.c.get('/audit/logs');
  assert.equal(p1.status, 200);
  assert.equal(p1.json.retentionPolicy, '6 months (LFPDPPP)');
  assert.deepEqual(p1.json.pagination, { page: 1, limit: 20, total, totalPages: 3 });
  assert.equal(p1.json.logs.length, 20);
  const dates = p1.json.logs.map((l) => new Date(l.created_at).getTime());
  assert.deepEqual([...dates].sort((a, b) => b - a), dates, 'orden created_at DESC');
  assert.deepEqual(Object.keys(p1.json.logs[0]).sort(), ['created_at', 'detail', 'event', 'file_id', 'id', 'ip', 'member_id', 'user_agent', 'vault_id']);

  const p3 = await A.c.get('/audit/logs?page=3&limit=20');
  assert.equal(p3.json.logs.length, 6);
  const ids = new Set([...p1.json.logs, ...(await A.c.get('/audit/logs?page=2')).json.logs, ...p3.json.logs].map((l) => l.id));
  assert.equal(ids.size, total, 'sin duplicados ni huecos entre páginas');
  assert.equal((await A.c.get('/audit/logs?page=9')).json.logs.length, 0);

  const big = await A.c.get('/audit/logs?limit=500');
  assert.equal(big.json.pagination.limit, 100);
  assert.equal(big.json.logs.length, total);
  assert.deepEqual((await A.c.get('/audit/logs?limit=10')).json.pagination, { page: 1, limit: 10, total, totalPages: 5 });
});

test('GET /audit/logs: filtros por event y por fechas (from/to)', async () => {
  const A = await registerUser('filtros');
  await query(
    `INSERT INTO access_logs (owner_id, event, created_at) VALUES
       ($1, 'TEST_B', now()), ($1, 'TEST_B', now()), ($1, 'TEST_A', now()),
       ($1, 'TEST_DATE', '2026-01-10T12:00:00Z'), ($1, 'TEST_DATE', '2026-01-15T12:00:00Z'), ($1, 'TEST_DATE', '2026-01-20T12:00:00Z')`,
    [A.id],
  );
  assert.equal((await A.c.get('/audit/logs?event=TEST_B')).json.pagination.total, 2);
  assert.equal((await A.c.get('/audit/logs?event=NO_EXISTE')).json.pagination.total, 0);
  assert.equal((await A.c.get('/audit/logs?event=USER_REGISTERED')).json.pagination.total, 1);

  const d = (qs) => A.c.get(`/audit/logs?event=TEST_DATE&${qs}`).then((r) => r.json.pagination.total);
  assert.equal(await d('from=2026-01-15&to=2026-01-15'), 1); // fecha sola = día completo, inclusivo
  assert.equal(await d('from=2026-01-12T00:00:00Z'), 2);
  assert.equal(await d('to=2026-01-12'), 1);
  assert.equal(await d('from=2026-01-10&to=2026-01-20'), 3);
  assert.equal(await d('from=2026-01-10T12:00:00Z&to=2026-01-10T12:00:00Z'), 1); // instante exacto inclusivo
  assert.equal(await d('from=2027-01-01'), 0);
  const combo = await A.c.get('/audit/logs?event=TEST_DATE&from=2026-01-12&limit=1&page=2');
  assert.equal(combo.json.pagination.total, 2);
  assert.equal(combo.json.logs.length, 1);
  assert.equal(combo.json.logs[0].event, 'TEST_DATE');
});

test('GET /audit/logs: parámetros inválidos -> 400 y sin sesión -> 401', async () => {
  const A = await registerUser('invalidos');
  for (const qs of ['page=0', 'page=-1', 'page=abc', 'page=1.5', 'limit=0', 'limit=abc', 'from=basura', 'to=basura',
    'from=2026-02-01&to=2026-01-01', `event=${'x'.repeat(51)}`, 'event=', 'page=1&page=2', 'event[a]=1']) {
    assert.equal((await A.c.get(`/audit/logs?${qs}`)).status, 400, qs);
  }
  assert.equal((await createClient(srv.base).get('/audit/logs')).status, 401);
  assert.equal((await createClient(srv.base).get('/audit/stats')).status, 401);
});

test('anti-IDOR: cada usuario solo ve su propia bitácora (owner_id nunca viene de la query)', async () => {
  const A = await registerUser('duenoA');
  const B = await registerUser('duenoB');
  await query(`INSERT INTO access_logs (owner_id, event) VALUES ($1, 'SECRETO_DE_A'), ($2, 'SECRETO_DE_B')`, [A.id, B.id]);

  const a = await A.c.get('/audit/logs?limit=100');
  const b = await B.c.get('/audit/logs?limit=100');
  assert.ok(a.json.logs.some((l) => l.event === 'SECRETO_DE_A') && !a.json.logs.some((l) => l.event === 'SECRETO_DE_B'));
  assert.ok(b.json.logs.some((l) => l.event === 'SECRETO_DE_B') && !b.json.logs.some((l) => l.event === 'SECRETO_DE_A'));

  // Intentos de suplantar el filtro
  const spoof = await B.c.get(`/audit/logs?owner_id=${A.id}&event=SECRETO_DE_A`);
  assert.equal(spoof.status, 200);
  assert.equal(spoof.json.pagination.total, 0);
  assert.equal((await B.c.get(`/audit/logs?event=${encodeURIComponent("' OR 1=1 --")}`)).json.pagination.total, 0);
});

// ------------------------------- /audit/stats -------------------------------

test('GET /audit/stats: 7 y 30 días, serie cronológica continua y totales', async () => {
  const A = await registerUser('stats');
  const B = await registerUser('statsb');
  await query(
    `INSERT INTO daily_stats_rollup (owner_id, stat_date, total_downloads, total_failed_attempts, unique_visitors) VALUES
       ($1, CURRENT_DATE,      5, 1, 2),
       ($1, CURRENT_DATE - 3,  2, 4, 1),
       ($1, CURRENT_DATE - 6,  1, 0, 1),
       ($1, CURRENT_DATE - 7,  10, 10, 10),
       ($1, CURRENT_DATE - 20, 7, 2, 3),
       ($1, CURRENT_DATE - 29, 3, 3, 3),
       ($1, CURRENT_DATE - 30, 100, 100, 100),
       ($2, CURRENT_DATE,      99, 99, 99)`,
    [A.id, B.id],
  );

  const d7 = await A.c.get('/audit/stats?days=7');
  assert.equal(d7.status, 200);
  assert.equal(d7.json.days, 7);
  assert.equal(d7.json.series.length, 7);
  assert.deepEqual(d7.json.totals, { downloads: 8, failedAttempts: 5, uniqueVisitors: 4 });
  const dates7 = d7.json.series.map((s) => s.date);
  assert.deepEqual([...dates7].sort(), dates7, 'orden cronológico ascendente');
  assert.equal(new Set(dates7).size, 7);
  assert.deepEqual(Object.keys(d7.json.series[0]).sort(), ['date', 'downloads', 'failedAttempts', 'uniqueVisitors']);
  assert.equal(d7.json.series.at(-1).downloads, 5); // hoy al final
  assert.equal(d7.json.series[0].downloads, 1); // hace 6 días al inicio
  assert.equal(d7.json.series.find((s) => s.downloads === 0 && s.failedAttempts === 0) !== undefined, true, 'días sin actividad en 0');

  const d30 = await A.c.get('/audit/stats?days=30');
  assert.equal(d30.json.days, 30);
  assert.equal(d30.json.series.length, 30);
  assert.deepEqual(d30.json.totals, { downloads: 5 + 2 + 1 + 10 + 7 + 3, failedAttempts: 1 + 4 + 0 + 10 + 2 + 3, uniqueVisitors: 2 + 1 + 1 + 10 + 3 + 3 });

  assert.equal((await A.c.get('/audit/stats')).json.days, 30); // default
  for (const bad of ['days=5', 'days=0', 'days=abc', 'days=90', 'days=7&days=30']) {
    assert.equal((await A.c.get(`/audit/stats?${bad}`)).status, 400, bad);
  }

  // Aislamiento entre usuarios
  const b = await B.c.get('/audit/stats?days=7');
  assert.deepEqual(b.json.totals, { downloads: 99, failedAttempts: 99, uniqueVisitors: 99 });
  const none = await (await registerUser('vacio')).c.get('/audit/stats?days=30');
  assert.deepEqual(none.json.totals, { downloads: 0, failedAttempts: 0, uniqueVisitors: 0 });
  assert.equal(none.json.series.length, 30);
});
