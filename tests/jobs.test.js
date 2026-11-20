import './helpers/env.js';
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import cron from 'node-cron';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { config } from '../src/config/env.js';
import { pool, query } from '../src/db/pool.js';
import { runMigrations } from '../src/db/migrate.js';
import { purgeOldAuditLogs, expireVaults, cleanupExpiredTokens, startJobs, JOBS } from '../src/jobs/index.js';
import { startServer, createClient, uniqueEmail } from './helpers/http.js';

const future = (days = 30) => new Date(Date.now() + days * 86_400_000).toISOString();
const pdf = (m = crypto.randomUUID()) => Buffer.from(`%PDF-1.4\n% ${m}\ntrailer\n<< >>\n%%EOF\n`);

let srv;
let localDir;
const createdEmails = [];
const storedFiles = () => fs.readdirSync(localDir);

before(async () => {
  localDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secdocs-jobs-'));
  config.storage.driver = 'local';
  config.storage.localDir = localDir;
  await runMigrations();
  srv = await startServer();
});

after(async () => {
  await query('DELETE FROM users WHERE lower(email) = ANY($1)', [createdEmails.map((e) => e.toLowerCase())]);
  await srv.close();
  await pool.end();
  fs.rmSync(localDir, { recursive: true, force: true });
});

async function registerUser(tag) {
  const email = uniqueEmail(tag);
  createdEmails.push(email);
  const c = createClient(srv.base);
  const r = await c.post('/auth/register', { email, password: 'Contraseña-Segura-123' });
  assert.equal(r.status, 201);
  return { c, id: r.json.user.id, email: email.toLowerCase() };
}

test('startJobs no programa nada con NODE_ENV=test; las expresiones cron son válidas', () => {
  assert.equal(config.nodeEnv, 'test');
  assert.deepEqual(startJobs(), []);
  for (const [name, { schedule, run }] of Object.entries(JOBS)) {
    assert.ok(cron.validate(schedule), `cron inválido para ${name}`);
    assert.equal(typeof run, 'function');
  }
});

test('purgeOldAuditLogs: borra solo logs > 6 meses y no toca daily_stats_rollup', async () => {
  const U = await registerUser('retencion');
  await query(
    `INSERT INTO access_logs (owner_id, event, created_at) VALUES
       ($1, 'LOG_7_MESES', now() - interval '7 months'),
       ($1, 'LOG_MUY_VIEJO', now() - interval '3 years'),
       ($1, 'LOG_5_MESES', now() - interval '5 months'),
       ($1, 'LOG_HOY', now())`,
    [U.id],
  );
  await query(
    `INSERT INTO daily_stats_rollup (owner_id, stat_date, total_downloads, total_failed_attempts, unique_visitors) VALUES
       ($1, CURRENT_DATE - 400, 9, 8, 7), ($1, CURRENT_DATE, 1, 1, 1)`,
    [U.id],
  );

  const r = await purgeOldAuditLogs();
  assert.ok(r.deleted >= 2);
  const left = (await query('SELECT event FROM access_logs WHERE owner_id = $1', [U.id])).rows.map((x) => x.event).sort();
  assert.deepEqual(left, ['LOG_5_MESES', 'LOG_HOY', 'USER_REGISTERED']);
  const rollup = (await query('SELECT total_downloads FROM daily_stats_rollup WHERE owner_id = $1 ORDER BY stat_date', [U.id])).rows;
  assert.deepEqual(rollup.map((x) => x.total_downloads), [9, 1], 'el rollup anónimo se conserva indefinidamente');
  assert.equal((await purgeOldAuditLogs()).deleted >= 0, true); // idempotente
});

test('expireVaults: crypto-shredding de bóvedas vencidas (ACTIVE y LOCKED), storage, métricas y VAULT_EXPIRED', async () => {
  const A = await registerUser('expira');
  const mk = async (name) => (await A.c.post('/vaults', { name, expires_at: future() })).json.vault;
  const vActive = await mk('Vencida ACTIVE');
  const vLocked = await mk('Vencida LOCKED');
  const vOk = await mk('Vigente');

  const keys = {};
  for (const [label, v] of [['active', vActive], ['locked', vLocked], ['ok', vOk]]) {
    const r = await A.c.upload(`/vaults/${v.id}/files`, pdf(), `${label}.pdf`, 'application/pdf');
    assert.equal(r.status, 201);
    keys[label] = (await query('SELECT storage_key FROM vault_files WHERE id = $1', [r.json.file.id])).rows[0].storage_key;
  }
  const extra = await A.c.upload(`/vaults/${vActive.id}/files`, pdf(), 'otro.pdf', 'application/pdf'); // 2 archivos en la bóveda ACTIVE
  assert.equal(extra.status, 201);
  const extraKey = (await query('SELECT storage_key FROM vault_files WHERE id = $1', [extra.json.file.id])).rows[0].storage_key;

  // Miembro con ticket vivo en la bóveda que va a vencer
  const mem = await query(
    `INSERT INTO workspace_members (vault_id, recipient_email, token_hash, password_hash, expires_at, status, ticket_hash, ticket_expires_at)
     VALUES ($1, 'inv@example.com', $2, 'h', now() + interval '1 day', 'ACCEPTED', $3, now() + interval '1 minute') RETURNING id`,
    [vActive.id, crypto.randomBytes(32).toString('hex'), crypto.randomBytes(32).toString('hex')],
  );
  assert.equal((await A.c.patch(`/vaults/${vLocked.id}/status`, { status: 'LOCKED' })).status, 200);
  const before = (await query('SELECT * FROM user_metrics WHERE owner_id = $1', [A.id])).rows[0];
  assert.equal(before.total_vaults_active, 3);
  assert.equal(before.total_files_active, 4);

  await query(`UPDATE vaults SET expires_at = now() - interval '1 minute' WHERE id = ANY($1)`, [[vActive.id, vLocked.id]]);
  const res = await expireVaults();
  assert.ok(res.vaults >= 2 && res.files >= 3);

  for (const v of [vActive, vLocked]) {
    const row = (await query('SELECT status, wrapped_kek, purged_at FROM vaults WHERE id = $1', [v.id])).rows[0];
    assert.equal(row.status, 'EXPIRED');
    assert.equal(row.wrapped_kek, null);
    assert.ok(row.purged_at);
    const files = (await query('SELECT status, wrapped_dek, iv, auth_tag, purged_at FROM vault_files WHERE vault_id = $1', [v.id])).rows;
    assert.ok(files.length >= 1 && files.every((f) => f.status === 'PURGED' && f.wrapped_dek === null && f.iv === null && f.auth_tag === null && f.purged_at));
    assert.equal((await query(`SELECT count(*)::int AS n FROM access_logs WHERE vault_id = $1 AND event = 'VAULT_EXPIRED' AND owner_id = $2`, [v.id, A.id])).rows[0].n, 1);
  }
  const member = (await query('SELECT status, ticket_hash, ticket_expires_at FROM workspace_members WHERE id = $1', [mem.rows[0].id])).rows[0];
  assert.deepEqual(member, { status: 'EXPIRED', ticket_hash: null, ticket_expires_at: null });

  // storage: solo sobrevive el .enc de la bóveda vigente
  assert.ok(!fs.existsSync(path.join(localDir, keys.active)));
  assert.ok(!fs.existsSync(path.join(localDir, extraKey)));
  assert.ok(!fs.existsSync(path.join(localDir, keys.locked)));
  assert.ok(fs.existsSync(path.join(localDir, keys.ok)));

  // métricas: solo queda la bóveda vigente con su archivo
  const m = (await query('SELECT * FROM user_metrics WHERE owner_id = $1', [A.id])).rows[0];
  assert.equal(m.total_vaults_active, 1);
  assert.equal(m.total_files_active, 1);
  assert.ok(m.total_storage_bytes > 0);

  // La bóveda vigente no se tocó; las vencidas ya no aceptan nada
  const ok = (await query('SELECT status, wrapped_kek FROM vaults WHERE id = $1', [vOk.id])).rows[0];
  assert.equal(ok.status, 'ACTIVE');
  assert.ok(ok.wrapped_kek);
  assert.equal((await A.c.upload(`/vaults/${vActive.id}/files`, pdf(), 'x.pdf')).status, 409);
  assert.equal((await A.c.get(`/vaults/${vActive.id}`)).json.vault.keys.kekStatus, 'PURGED');
  assert.equal((await A.c.patch(`/vaults/${vActive.id}/status`, { status: 'ACTIVE' })).status, 409);

  // Idempotente: una segunda ejecución no vuelve a procesar ni a descontar métricas
  const again = await expireVaults();
  assert.equal(again.vaults, 0);
  assert.equal((await query('SELECT total_vaults_active FROM user_metrics WHERE owner_id = $1', [A.id])).rows[0].total_vaults_active, 1);

  // Al borrar la última bóveda, las métricas quedan en 0
  await query(`UPDATE vaults SET expires_at = now() - interval '1 second' WHERE id = $1`, [vOk.id]);
  await expireVaults();
  assert.deepEqual(
    (await query('SELECT total_storage_bytes, total_files_active, total_vaults_active FROM user_metrics WHERE owner_id = $1', [A.id])).rows[0],
    { total_storage_bytes: 0, total_files_active: 0, total_vaults_active: 0 },
  );
  assert.equal(storedFiles().length, 0);
  void before;
});

test('expireVaults: invitación de una bóveda vencida deja de estar disponible y miembros vencidos pasan a EXPIRED', async () => {
  const A = await registerUser('expira2');
  const v = (await A.c.post('/vaults', { name: 'V', expires_at: future() })).json.vault;
  const inv = await A.c.post(`/vaults/${v.id}/members`, { recipient_email: uniqueEmail('inv') });
  assert.equal(inv.status, 201);
  const token = inv.json.invitationPath.split('/').pop();
  const anon = createClient(srv.base);
  assert.equal((await anon.get(`/invitations/${token}`)).status, 200);

  // Miembro vencido en bóveda vigente -> EXPIRED
  await query(`UPDATE workspace_members SET expires_at = now() - interval '1 second' WHERE id = $1`, [inv.json.member.id]);
  const r = await expireVaults();
  assert.ok(r.membersExpired >= 1);
  assert.equal((await query('SELECT status FROM workspace_members WHERE id = $1', [inv.json.member.id])).rows[0].status, 'EXPIRED');
  assert.equal((await anon.get(`/invitations/${token}`)).status, 410);
  assert.equal((await query('SELECT status FROM vaults WHERE id = $1', [v.id])).rows[0].status, 'ACTIVE');
});

test('cleanupExpiredTokens: purga solo registros expirados de revoked_tokens y user_sessions', async () => {
  const U = await registerUser('limpieza');
  const tag = crypto.randomUUID();
  const j = (n) => `${tag}-${n}`;
  await query(
    `INSERT INTO revoked_tokens (jti, expires_at) VALUES
       ($1, now() - interval '1 hour'), ($2, now() - interval '1 second'), ($3, now() + interval '1 hour'), ($4, now() + interval '7 days')`,
    [j('rev-old1'), j('rev-old2'), j('rev-new1'), j('rev-new2')],
  );
  await query(
    `INSERT INTO user_sessions (jti, user_id, expires_at) VALUES
       ($1, $5, now() - interval '1 day'), ($2, $5, now() - interval '1 second'), ($3, $5, now() + interval '1 hour'), ($4, $5, now() + interval '1 day')`,
    [j('ses-old1'), j('ses-old2'), j('ses-new1'), j('ses-new2'), U.id],
  );

  const r = await cleanupExpiredTokens();
  assert.ok(r.revokedTokens >= 2 && r.sessions >= 2);
  const rev = (await query('SELECT jti FROM revoked_tokens WHERE jti LIKE $1 ORDER BY jti', [`${tag}%`])).rows.map((x) => x.jti);
  assert.deepEqual(rev, [j('rev-new1'), j('rev-new2')]);
  const ses = (await query('SELECT jti FROM user_sessions WHERE jti LIKE $1 ORDER BY jti', [`${tag}%`])).rows.map((x) => x.jti);
  assert.deepEqual(ses, [j('ses-new1'), j('ses-new2')]);
  // la sesión real del usuario sigue viva
  assert.equal((await U.c.get('/auth/me')).status, 200);
  // idempotente
  const again = await cleanupExpiredTokens();
  assert.equal(again.sessions >= 0, true);
  assert.equal((await query('SELECT count(*)::int AS n FROM revoked_tokens WHERE jti LIKE $1', [`${tag}%`])).rows[0].n, 2);
});
