import './helpers/env.js';
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import { pool, query } from '../src/db/pool.js';
import { runMigrations } from '../src/db/migrate.js';
import * as audit from '../src/services/audit.service.js';

let ownerId;

before(async () => {
  await runMigrations();
  const email = `audit-${crypto.randomUUID()}@test.local`;
  const r = await query(`INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id`, [email, 'x'.repeat(60)]);
  ownerId = r.rows[0].id;
});

after(async () => {
  await query('DELETE FROM users WHERE id = $1', [ownerId]); // cascada
  await pool.end();
});

test('sanitizeDetail elimina contraseñas, tokens, tickets y llaves (recursivo)', () => {
  const out = audit.sanitizeDetail({
    reason: 'bad_password',
    attemptsLeft: 3,
    active: true,
    password: 'p', newPassword: 'p', token: 't', inviteToken: 't', ticket: 'x', ticket_hash: 'h',
    authorization: 'Bearer z', wrappedDek: 'w', wrapped_kek: 'w', iv: 'i', authTag: 'a', apiKey: 'k', secret: 's',
    nested: { cookie: 'c', ok: 1, deep: [{ jwt: 'j', fine: 'v' }] },
  });
  assert.deepEqual(out, { reason: 'bad_password', attemptsLeft: 3, active: true, nested: { ok: 1, deep: [{ fine: 'v' }] } });
});

test('logEvent inserta en access_logs sin secretos y con recorte de ip/user-agent', async () => {
  await audit.logEvent({
    ownerId,
    event: 'ACCESS_DENIED',
    ip: '1.2.3.4',
    userAgent: 'U'.repeat(500),
    detail: { reason: 'email_mismatch', password: 'SECRETO-XYZ', ticket: 'TICKET-XYZ', token: 'TOKEN-XYZ' },
  });
  const { rows } = await query('SELECT * FROM access_logs WHERE owner_id = $1', [ownerId]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].event, 'ACCESS_DENIED');
  assert.equal(rows[0].user_agent.length, 300);
  assert.deepEqual(rows[0].detail, { reason: 'email_mismatch' });
  assert.ok(!JSON.stringify(rows[0]).match(/SECRETO-XYZ|TICKET-XYZ|TOKEN-XYZ/));
  await assert.rejects(() => audit.logEvent({ ownerId }), /event/);
});

test('logEvent usa parámetros: un evento con SQL malicioso se guarda como dato', async () => {
  const evil = "x'); DROP TABLE access_logs; --";
  await audit.logEvent({ ownerId, event: 'TEST_SQLI', detail: { note: evil } });
  const { rows } = await query(`SELECT detail FROM access_logs WHERE owner_id = $1 AND event = 'TEST_SQLI'`, [ownerId]);
  assert.equal(rows[0].detail.note, evil);
});

test('incrementDailyStats: upsert atómico bajo concurrencia (50 llamadas en paralelo)', async () => {
  await Promise.all(
    Array.from({ length: 50 }, (_, i) =>
      audit.incrementDailyStats(ownerId, { downloads: 1, failedAttempts: i % 2, uniqueVisitors: 0 }),
    ),
  );
  await audit.incrementDailyStats(ownerId, { uniqueVisitors: 2 });
  const { rows } = await query('SELECT * FROM daily_stats_rollup WHERE owner_id = $1', [ownerId]);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].total_downloads, 50);
  assert.equal(rows[0].total_failed_attempts, 25);
  assert.equal(rows[0].unique_visitors, 2);
});

test('user_metrics: incrementa, decrementa y nunca baja de 0', async () => {
  await audit.metricsVaultAdded(ownerId);
  await audit.metricsFileAdded(ownerId, 1000);
  await audit.metricsFileAdded(ownerId, 500);
  let m = (await query('SELECT * FROM user_metrics WHERE owner_id = $1', [ownerId])).rows[0];
  assert.equal(m.total_vaults_active, 1);
  assert.equal(m.total_files_active, 2);
  assert.equal(m.total_storage_bytes, 1500);

  await audit.metricsFileRemoved(ownerId, 1000);
  m = (await query('SELECT * FROM user_metrics WHERE owner_id = $1', [ownerId])).rows[0];
  assert.equal(m.total_files_active, 1);
  assert.equal(m.total_storage_bytes, 500);

  await audit.metricsFileRemoved(ownerId, 99999);
  await audit.metricsVaultRemoved(ownerId);
  await audit.metricsVaultRemoved(ownerId);
  m = (await query('SELECT * FROM user_metrics WHERE owner_id = $1', [ownerId])).rows[0];
  assert.equal(m.total_files_active, 0);
  assert.equal(m.total_storage_bytes, 0);
  assert.equal(m.total_vaults_active, 0);
});

test('adjustUserMetrics concurrente es consistente y funciona dentro de una transacción', async () => {
  await Promise.all(Array.from({ length: 20 }, () => audit.metricsFileAdded(ownerId, 10)));
  let m = (await query('SELECT * FROM user_metrics WHERE owner_id = $1', [ownerId])).rows[0];
  assert.equal(m.total_files_active, 20);
  assert.equal(m.total_storage_bytes, 200);

  const { withTransaction } = await import('../src/db/pool.js');
  await assert.rejects(() =>
    withTransaction(async (client) => {
      await audit.metricsFileAdded(ownerId, 1000, client);
      await audit.logEvent({ ownerId, event: 'TX_TEST' }, client);
      throw new Error('rollback');
    }),
  );
  m = (await query('SELECT * FROM user_metrics WHERE owner_id = $1', [ownerId])).rows[0];
  assert.equal(m.total_storage_bytes, 200);
  const n = (await query(`SELECT count(*)::int AS n FROM access_logs WHERE owner_id = $1 AND event = 'TX_TEST'`, [ownerId])).rows[0].n;
  assert.equal(n, 0);
});
