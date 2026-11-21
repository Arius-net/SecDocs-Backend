import './helpers/env.js';
import test, { before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { config } from '../src/config/env.js';
import { pool, query } from '../src/db/pool.js';
import { runMigrations } from '../src/db/migrate.js';
import { startServer, createClient, uniqueEmail } from './helpers/http.js';

const PASSWORD = 'Contraseña-Segura-123';
let srv;
let localDir;
let mailLines = [];
const createdEmails = [];

before(async () => {
  localDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secdocs-e2e-'));
  config.storage.driver = 'local';
  config.storage.localDir = localDir;
  mock.method(console, 'log', (...a) => mailLines.push(a.join(' ')));
  await runMigrations();
  srv = await startServer();
});

after(async () => {
  mock.restoreAll();
  await query('DELETE FROM users WHERE lower(email) = ANY($1)', [createdEmails.map((e) => e.toLowerCase())]);
  await srv.close();
  await pool.end();
  fs.rmSync(localDir, { recursive: true, force: true });
});

test('E2E: registro -> bóveda -> archivo -> invitación -> Canal 2 -> unlock -> descarga -> auditoría -> kill-switch', async () => {
  const emailA = uniqueEmail('dueno');
  const emailB = uniqueEmail('invitado');
  createdEmails.push(emailA, emailB);

  // 1. Registro de A (dueño, dos dispositivos) y B (invitado)
  const A = createClient(srv.base, 'A-laptop');
  const rA = await A.post('/auth/register', { email: emailA, password: PASSWORD });
  assert.equal(rA.status, 201);
  const A2 = createClient(srv.base, 'A-phone');
  assert.equal((await A2.post('/auth/login', { email: emailA, password: PASSWORD })).status, 200);
  const B = createClient(srv.base, 'B-browser');
  assert.equal((await B.post('/auth/register', { email: emailB, password: PASSWORD })).status, 201);
  assert.equal((await A.get('/auth/me')).json.user.email, emailA.toLowerCase());

  // 2. Crear bóveda
  const vr = await A.post('/vaults', { name: 'Expediente E2E', expires_at: new Date(Date.now() + 14 * 86_400_000).toISOString() });
  assert.equal(vr.status, 201);
  const vault = vr.json.vault;

  // 3. Subir archivo (binario con bytes arbitrarios dentro de un PDF válido por magic bytes)
  const original = Buffer.concat([Buffer.from('%PDF-1.7\n'), crypto.randomBytes(200_000), Buffer.from('\n%%EOF\n')]);
  const up = await A.upload(`/vaults/${vault.id}/files`, original, 'Expediente confidencial.pdf', 'application/pdf');
  assert.equal(up.status, 201, JSON.stringify(up.json));
  const file = up.json.file;
  const stored = fs.readFileSync(path.join(localDir, (await query('SELECT storage_key FROM vault_files WHERE id = $1', [file.id])).rows[0].storage_key));
  assert.notDeepEqual(stored, original);

  // 4. Invitar a B
  const inv = await A.post(`/vaults/${vault.id}/members`, { recipient_email: emailB, recipient_label: 'Invitado B', max_downloads: 2 });
  assert.equal(inv.status, 201);
  const token = inv.json.invitationPath.split('/').pop();

  // 5. Consultar la invitación (pública, correo enmascarado)
  const info = await createClient(srv.base).get(`/invitations/${token}`);
  assert.equal(info.status, 200);
  assert.match(info.json.invitation.maskedEmail, /^.\*\*\*@/);
  assert.equal(info.json.invitation.vaultName, 'Expediente E2E');

  // 6. Verificar identidad (Canal 2: la clave llega por correo, capturada de la consola de dev)
  mailLines = [];
  assert.equal((await B.post(`/invitations/${token}/verify-identity`)).status, 200);
  const password = [...mailLines.join('\n').matchAll(/^│ {5}(\S+)$/gm)].pop()?.[1];
  assert.ok(password, 'la clave del Canal 2 debe llegar por correo');

  // 7. Desbloquear (ticket de un solo uso)
  const unlock = await B.post(`/invitations/${token}/unlock`, { password });
  assert.equal(unlock.status, 200);
  assert.equal(unlock.json.files.length, 1);
  assert.equal(unlock.json.files[0].id, file.id);

  // 8. Descargar y verificar integridad byte a byte
  const dl = await fetch(`${srv.base}/shared/${vault.id}/files/${file.id}/download`, {
    headers: { Cookie: B.cookie, 'X-Download-Ticket': unlock.json.ticket },
  });
  assert.equal(dl.status, 200);
  const downloaded = Buffer.from(await dl.arrayBuffer());
  assert.equal(downloaded.length, original.length);
  assert.ok(downloaded.equals(original), 'el archivo descargado debe ser idéntico al original');
  assert.equal(dl.headers.get('cache-control'), 'no-store');
  assert.equal(dl.headers.get('x-robots-tag'), 'noindex, nofollow, noarchive');
  assert.equal(dl.headers.get('referrer-policy'), 'no-referrer');
  // el ticket ya no sirve
  const replay = await fetch(`${srv.base}/shared/${vault.id}/files/${file.id}/download`, {
    headers: { Cookie: B.cookie, 'X-Download-Ticket': unlock.json.ticket },
  });
  assert.equal(replay.status, 401);

  // 9. Auditoría del dueño: eventos del ciclo completo + estadísticas
  const logs = await A.get('/audit/logs?limit=100');
  assert.equal(logs.status, 200);
  assert.equal(logs.json.retentionPolicy, '6 months (LFPDPPP)');
  const events = new Set(logs.json.logs.map((l) => l.event));
  for (const ev of ['USER_REGISTERED', 'LOGIN_SUCCESS', 'VAULT_CREATED', 'FILE_UPLOADED', 'MEMBER_INVITED', 'IDENTITY_VERIFIED',
    'PASSWORD_SENT', 'VAULT_UNLOCKED_BY_MEMBER', 'FILE_DOWNLOADED', 'DOWNLOAD_DENIED']) {
    assert.ok(events.has(ev), `falta el evento ${ev}`);
  }
  const blob = JSON.stringify(logs.json);
  for (const secret of [password, token, unlock.json.ticket]) assert.ok(!blob.includes(secret), 'la bitácora no debe contener secretos');
  assert.equal((await A.get('/audit/logs?event=FILE_DOWNLOADED')).json.pagination.total, 1);
  assert.equal((await B.get('/audit/logs')).json.pagination.total, 1 + 0, 'B no ve la bitácora del dueño (solo su propio registro)');

  const stats = await A.get('/audit/stats?days=7');
  assert.equal(stats.status, 200);
  assert.deepEqual(stats.json.totals, { downloads: 1, failedAttempts: 0, uniqueVisitors: 1 });
  assert.equal(stats.json.series.at(-1).downloads, 1);
  const list = await A.get('/vaults');
  assert.equal(list.json.metrics.total_files_active, 1);
  assert.equal(list.json.vaults[0].members_count, 1);

  // 10. Kill-switch: todas las sesiones de A quedan revocadas; B no se ve afectado
  assert.equal((await A.get('/security/sessions')).json.sessions.length, 2);
  const cookies = { laptop: A.cookie, phone: A2.cookie };
  const ks = await A.post('/security/kill-switch');
  assert.equal(ks.status, 200);
  assert.equal(ks.json.revoked, 2);
  for (const [name, cookie] of Object.entries(cookies)) {
    const c = createClient(srv.base);
    c.cookie = cookie;
    assert.equal((await c.get('/auth/me')).status, 401, `la sesión ${name} debe quedar revocada`);
    assert.equal((await c.get('/vaults')).status, 401);
  }
  assert.equal((await B.get('/auth/me')).status, 200);
  const A3 = createClient(srv.base);
  assert.equal((await A3.post('/auth/login', { email: emailA, password: PASSWORD })).status, 200);
  assert.equal((await A3.get('/audit/logs?event=SESSION_REVOKED')).json.pagination.total, 1);
  assert.equal((await query('SELECT count(*)::int AS n FROM user_sessions WHERE user_id = $1', [rA.json.user.id])).rows[0].n, 1);
});
