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
import { sha256Hex } from '../src/services/crypto.service.js';
import { startServer, createClient, uniqueEmail } from './helpers/http.js';

const PASSWORD = 'Contraseña-Segura-123';
const future = (days = 30) => new Date(Date.now() + days * 86_400_000).toISOString();
const pdf = (marker = crypto.randomUUID()) =>
  Buffer.from(`%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n% ${marker}\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n`);

let srv;
let localDir;
let mailLines = [];
const createdEmails = [];
const secrets = []; // tokens, tickets y claves de Canal 2 generados en las pruebas
const ownerIds = [];

before(async () => {
  localDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secdocs-inv-'));
  config.storage.driver = 'local';
  config.storage.localDir = localDir;
  config.invitation.resendCooldownSeconds = 60;
  mock.method(console, 'log', (...a) => mailLines.push(a.join(' '))); // captura el "correo" de Canal 2
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

async function registerUser(tag) {
  const email = uniqueEmail(tag);
  createdEmails.push(email);
  const c = createClient(srv.base);
  const r = await c.post('/auth/register', { email, password: PASSWORD });
  assert.equal(r.status, 201);
  return { c, id: r.json.user.id, email: email.toLowerCase() };
}

/** Dueño A con bóveda y 1 archivo + invitado B con invitación. */
async function setup({ maxDownloads = 3, files = 1 } = {}) {
  const A = await registerUser('owner');
  ownerIds.push(A.id);
  const B = await registerUser('guest');
  const v = (await A.c.post('/vaults', { name: 'Compartida', expires_at: future() })).json.vault;
  const plains = [];
  const uploaded = [];
  for (let i = 0; i < files; i++) {
    const plain = pdf();
    const r = await A.c.upload(`/vaults/${v.id}/files`, plain, `Informe ${i}.pdf`, 'application/pdf');
    assert.equal(r.status, 201);
    plains.push(plain);
    uploaded.push(r.json.file);
  }
  const inv = await A.c.post(`/vaults/${v.id}/members`, { recipient_email: B.email.toUpperCase(), recipient_label: 'Cliente B', max_downloads: maxDownloads });
  assert.equal(inv.status, 201, JSON.stringify(inv.json));
  const token = inv.json.invitationPath.split('/').pop();
  secrets.push(token);
  return { A, B, vault: v, files: uploaded, plains, member: inv.json.member, token, inv };
}

/** verify-identity como B y devuelve la clave capturada del "correo". */
async function sendPassword(s, who = s.B) {
  mailLines = [];
  const r = await who.c.post(`/invitations/${s.token}/verify-identity`);
  assert.equal(r.status, 200, JSON.stringify(r.json));
  const m = [...mailLines.join('\n').matchAll(/^│ {5}(\S+)$/gm)].pop();
  assert.ok(m, 'no se capturó la clave del correo: ' + mailLines.join('\n'));
  secrets.push(m[1]);
  return m[1];
}

async function unlockOk(s) {
  const pw = await sendPasswordForce(s); // sin cooldown: algunos tests desbloquean varias veces al mismo miembro
  const r = await s.B.c.post(`/invitations/${s.token}/unlock`, { password: pw });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  secrets.push(r.json.ticket);
  return { pw, ...r.json };
}

const download = (s, ticket, fileId = s.files[0].id, who = s.B, via = 'header') => {
  if (via === 'query') return rawDownload(who, `/shared/${s.vault.id}/files/${fileId}/download?ticket=${encodeURIComponent(ticket)}`, {});
  const headers = { 'X-Download-Ticket': ticket };
  return rawDownload(who, `/shared/${s.vault.id}/files/${fileId}/download`, headers);
};

/** GET binario con cabecera personalizada (el cliente JSON no devuelve el cuerpo crudo). */
async function rawDownload(who, p, headers) {
  const res = await fetch(srv.base + p, { headers: { Cookie: who.c.cookie ?? '', ...headers } });
  const body = Buffer.from(await res.arrayBuffer());
  return { status: res.status, headers: res.headers, body };
}

const memberRow = async (id) => (await query('SELECT * FROM workspace_members WHERE id = $1', [id])).rows[0];
const expireLock = (id) => query(`UPDATE workspace_members SET locked_until = now() - interval '1 second' WHERE id = $1`, [id]);

// --------------------------------------------------------------------------

test('FLUJO FELIZ: invitar -> enlace enmascarado -> verify-identity -> unlock -> descarga byte a byte', async () => {
  const s = await setup();

  // El enlace se devuelve una vez; BD solo tiene SHA-256 y bcrypt costo 12
  assert.match(s.inv.json.invitationPath, /^\/invitacion\/[A-Za-z0-9_-]{32}$/);
  assert.ok(s.inv.json.invitationUrl.endsWith(s.inv.json.invitationPath));
  assert.ok(!('token_hash' in s.inv.json.member) && !('password_hash' in s.inv.json.member));
  const row = await memberRow(s.member.id);
  assert.equal(row.token_hash, sha256Hex(s.token));
  assert.match(row.password_hash, /^\$2[aby]\$12\$/);
  assert.equal(row.recipient_email, s.B.email);
  assert.equal(row.status, 'PENDING');
  assert.ok(!JSON.stringify(row).includes(s.token));

  // GET /invitations/:token (sin sesión): info mínima, correo enmascarado, cabeceras estrictas
  const anon = createClient(srv.base);
  const info = await anon.get(`/invitations/${s.token}`);
  assert.equal(info.status, 200);
  assert.equal(info.json.invitation.vaultName, 'Compartida');
  assert.equal(info.json.invitation.maskedEmail, `${s.B.email[0]}***@${s.B.email.split('@')[1]}`);
  assert.ok(!JSON.stringify(info.json).includes(s.B.email));
  assert.ok(!JSON.stringify(info.json).includes(s.A.email), 'el correo del dueño va enmascarado');
  assert.deepEqual(Object.keys(info.json.invitation).sort(), ['expires_at', 'maskedEmail', 'ownerEmail', 'status', 'vaultName']);
  assert.equal(info.headers.get('x-robots-tag'), 'noindex, nofollow, noarchive');
  assert.equal(info.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(info.headers.get('cache-control'), 'no-store');

  // verify-identity: B recibe la clave por "correo" (consola dev), nunca en la respuesta
  mailLines = [];
  const v = await s.B.c.post(`/invitations/${s.token}/verify-identity`);
  assert.equal(v.status, 200);
  const mail = mailLines.join('\n');
  assert.match(mail, new RegExp(s.B.email.replace(/[.+]/g, '\\$&')));
  const pw = [...mail.matchAll(/^│ {5}(\S+)$/gm)].pop()[1];
  secrets.push(pw);
  assert.equal(pw.length, 14);
  assert.ok(!JSON.stringify(v.json).includes(pw));
  const row2 = await memberRow(s.member.id);
  assert.match(row2.password_hash, /^\$2[aby]\$12\$/);
  assert.notEqual(row2.password_hash, row.password_hash);
  assert.ok(await (await import('bcrypt')).default.compare(pw, row2.password_hash));
  for (const ev of ['IDENTITY_VERIFIED', 'PASSWORD_SENT']) {
    assert.equal((await query('SELECT 1 FROM access_logs WHERE member_id = $1 AND event = $2 AND owner_id = $3', [s.member.id, ev, s.A.id])).rowCount, 1, ev);
  }

  // unlock: ticket + lista de archivos (metadatos seguros)
  const u = await s.B.c.post(`/invitations/${s.token}/unlock`, { password: pw });
  assert.equal(u.status, 200);
  secrets.push(u.json.ticket);
  assert.ok(u.json.ticket.length >= 40);
  assert.ok(new Date(u.json.ticketExpiresAt) > new Date());
  assert.ok(new Date(u.json.ticketExpiresAt) <= new Date(Date.now() + 61_000));
  assert.equal(u.json.files.length, 1);
  assert.deepEqual(Object.keys(u.json.files[0]).sort(), ['created_at', 'id', 'mime_type', 'original_filename', 'size_bytes', 'status']);
  assert.equal(u.json.vault.name, 'Compartida');
  const row3 = await memberRow(s.member.id);
  assert.equal(row3.status, 'ACCEPTED');
  assert.equal(row3.failed_attempts, 0);
  assert.equal(row3.locked_until, null);
  assert.equal(row3.ticket_hash, sha256Hex(u.json.ticket));
  assert.ok(!JSON.stringify(row3).includes(u.json.ticket), 'solo se guarda el hash del ticket');
  assert.ok(row3.last_access_at);

  // GET /shared lista la bóveda
  const shared = await s.B.c.get('/shared');
  assert.equal(shared.status, 200);
  assert.equal(shared.json.shared.length, 1);
  assert.equal(shared.json.shared[0].files_count, 1);
  assert.equal(shared.json.shared[0].downloads_remaining, 3);
  assert.equal(shared.headers.get('x-robots-tag'), 'noindex, nofollow, noarchive');

  // Descarga: archivo original byte a byte + cabeceras estrictas
  const d = await download(s, u.json.ticket);
  assert.equal(d.status, 200);
  assert.deepEqual(d.body, s.plains[0]);
  assert.equal(d.headers.get('content-type'), 'application/pdf');
  assert.equal(d.headers.get('cache-control'), 'no-store');
  assert.equal(d.headers.get('x-robots-tag'), 'noindex, nofollow, noarchive');
  assert.equal(d.headers.get('referrer-policy'), 'no-referrer');
  assert.equal(d.headers.get('x-content-type-options'), 'nosniff');
  assert.match(d.headers.get('content-disposition'), /^attachment; filename="Informe 0\.pdf"/);

  const after = await memberRow(s.member.id);
  assert.equal(after.download_count, 1);
  assert.equal(after.ticket_hash, null);
  const stats = (await query('SELECT * FROM daily_stats_rollup WHERE owner_id = $1', [s.A.id])).rows[0];
  assert.equal(stats.total_downloads, 1);
  assert.equal(stats.unique_visitors, 1);
  assert.equal((await query(`SELECT 1 FROM access_logs WHERE member_id = $1 AND event = 'FILE_DOWNLOADED' AND file_id = $2`, [s.member.id, s.files[0].id])).rowCount, 1);
  assert.equal((await query(`SELECT 1 FROM access_logs WHERE member_id = $1 AND event = 'VAULT_UNLOCKED_BY_MEMBER'`, [s.member.id])).rowCount, 1);

  // La descarga es visible para el dueño y descargas restantes baja
  assert.equal((await s.B.c.get('/shared')).json.shared[0].downloads_remaining, 2);
});

test('ticket de un solo uso: reutilizarlo falla; dos descargas concurrentes -> solo una cuenta', async () => {
  const s = await setup();
  const { ticket } = await unlockOk(s);

  const [r1, r2] = await Promise.all([download(s, ticket), download(s, ticket)]);
  const statuses = [r1.status, r2.status].sort();
  assert.deepEqual(statuses, [200, 401]);
  const ok = r1.status === 200 ? r1 : r2;
  assert.deepEqual(ok.body, s.plains[0]);
  assert.equal((await memberRow(s.member.id)).download_count, 1);

  assert.equal((await download(s, ticket)).status, 401); // tercera vez, secuencial
  assert.equal((await memberRow(s.member.id)).download_count, 1);

  // 20 concurrentes con un ticket nuevo: exactamente 1
  const t2 = await unlockOk(s);
  const many = await Promise.all(Array.from({ length: 20 }, () => download(s, t2.ticket)));
  assert.equal(many.filter((r) => r.status === 200).length, 1);
  assert.equal(many.filter((r) => r.status === 401).length, 19);
  assert.equal((await memberRow(s.member.id)).download_count, 2);
  assert.equal((await query(`SELECT count(*)::int AS n FROM access_logs WHERE member_id = $1 AND event = 'FILE_DOWNLOADED'`, [s.member.id])).rows[0].n, 2);
});

test('ticket: inválido, ausente, expirado, por query y de otro usuario/archivo', async () => {
  const s = await setup({ files: 2 });
  const C = await registerUser('intruder');
  const t = await unlockOk(s);

  assert.equal((await download(s, 'a'.repeat(43))).status, 401);
  assert.equal((await rawDownload(s.B, `/shared/${s.vault.id}/files/${s.files[0].id}/download`, {})).status, 401);
  // archivo inexistente / de otra bóveda: 404 sin consumir el ticket
  assert.equal((await download(s, t.ticket, crypto.randomUUID())).status, 404);
  assert.equal((await download(s, t.ticket, 'no-uuid')).status, 404);
  assert.ok((await memberRow(s.member.id)).ticket_hash, 'el ticket sigue vivo');
  // otro usuario con el ticket de B: 403 (+ACCESS_DENIED) y no se consume
  assert.equal((await download(s, t.ticket, s.files[0].id, C)).status, 403);
  assert.equal((await query(`SELECT 1 FROM access_logs WHERE vault_id = $1 AND event = 'ACCESS_DENIED' AND owner_id = $2`, [s.vault.id, s.A.id])).rowCount, 1);
  assert.ok((await memberRow(s.member.id)).ticket_hash);
  // sin sesión
  assert.equal((await fetch(`${srv.base}/shared/${s.vault.id}/files/${s.files[0].id}/download`, { headers: { 'X-Download-Ticket': t.ticket } })).status, 401);

  // expirado (60 s simulados por SQL)
  await query(`UPDATE workspace_members SET ticket_expires_at = now() - interval '1 second' WHERE id = $1`, [s.member.id]);
  assert.equal((await download(s, t.ticket)).status, 401);
  assert.equal((await memberRow(s.member.id)).download_count, 0);

  // nuevo ticket aceptado por query string
  const t2 = await unlockOk(s);
  const q = await download(s, t2.ticket, s.files[1].id, s.B, 'query');
  assert.equal(q.status, 200);
  assert.deepEqual(q.body, s.plains[1]);
  assert.equal(q.headers.get('cache-control'), 'no-store');
});

test('usuario C (otro correo): verify-identity y unlock -> 403 con ACCESS_DENIED; sin sesión -> 401', async () => {
  const s = await setup();
  const C = await registerUser('otro');
  mailLines = [];
  const v = await C.c.post(`/invitations/${s.token}/verify-identity`);
  assert.equal(v.status, 403);
  assert.deepEqual(v.json, { error: 'Acceso denegado' });
  assert.equal(mailLines.length, 0, 'no se envía correo a quien no es el destinatario');
  const u = await C.c.post(`/invitations/${s.token}/unlock`, { password: 'cualquiera1234' });
  assert.equal(u.status, 403);

  const logs = await query(`SELECT owner_id, vault_id, member_id, detail FROM access_logs WHERE event = 'ACCESS_DENIED' AND vault_id = $1 ORDER BY id`, [s.vault.id]);
  assert.equal(logs.rowCount, 2);
  assert.ok(logs.rows.every((r) => r.owner_id === s.A.id && r.member_id === s.member.id));
  assert.deepEqual(logs.rows.map((r) => r.detail.action), ['verify_identity', 'unlock']);
  const m = await memberRow(s.member.id);
  assert.equal(m.failed_attempts, 0);
  assert.equal(m.password_hash.length > 0, true);
  assert.equal((await query(`SELECT 1 FROM access_logs WHERE member_id = $1 AND event = 'PASSWORD_SENT'`, [s.member.id])).rowCount, 0);

  const anon = createClient(srv.base);
  assert.equal((await anon.post(`/invitations/${s.token}/verify-identity`)).status, 401);
  assert.equal((await anon.post(`/invitations/${s.token}/unlock`, { password: 'x' })).status, 401);
  // El dueño tampoco puede usar la invitación como invitado
  assert.equal((await s.A.c.post(`/invitations/${s.token}/verify-identity`)).status, 403);
});

test('fuerza bruta en unlock: failed_attempts, retardo exponencial, 429 con clave correcta mientras dure y TEMP_LOCKED al 5.º', async () => {
  const s = await setup();
  const pw = await sendPassword(s);
  const unlock = (password) => s.B.c.post(`/invitations/${s.token}/unlock`, { password });

  const expected = [2, 4, 8, 16];
  for (let i = 0; i < 4; i++) {
    const r = await unlock('incorrecta-' + i);
    assert.equal(r.status, 401, JSON.stringify(r.json));
    assert.equal(r.json.attemptsUsed, i + 1);
    assert.equal(r.json.maxAttempts, 5);
    assert.equal(r.json.retryAfterSeconds, expected[i]);
    const m = await memberRow(s.member.id);
    assert.equal(m.failed_attempts, i + 1);
    assert.ok(new Date(m.locked_until) > new Date());
    assert.equal(m.status, 'PENDING');

    // Mientras dure el bloqueo: 429 incluso con la clave CORRECTA y sin tocar el contador
    const blocked = await unlock(pw);
    assert.equal(blocked.status, 429);
    assert.ok(blocked.json.retryAfterSeconds >= 1 && blocked.json.retryAfterSeconds <= expected[i]);
    assert.equal(blocked.json.failedAttempts, i + 1);
    assert.ok(blocked.headers.get('retry-after'));
    assert.equal((await memberRow(s.member.id)).failed_attempts, i + 1);
    await expireLock(s.member.id);
  }

  // 5.º fallo: bloqueo de 15 min + TEMP_LOCKED + 429
  const fifth = await unlock('incorrecta-5');
  assert.equal(fifth.status, 429);
  assert.equal(fifth.json.attemptsUsed, 5);
  assert.equal(fifth.json.retryAfterSeconds, 900);
  let m = await memberRow(s.member.id);
  assert.equal(m.status, 'TEMP_LOCKED');
  assert.equal(m.failed_attempts, 5);
  const secs = (new Date(m.locked_until) - new Date()) / 1000;
  assert.ok(secs > 890 && secs <= 900, `bloqueo ${secs}s`);
  assert.equal((await unlock(pw)).status, 429); // clave correcta, bloqueada
  assert.equal((await memberRow(s.member.id)).status, 'TEMP_LOCKED');

  // estadísticas y auditoría de los fallos (sin la clave probada)
  assert.equal((await query('SELECT total_failed_attempts FROM daily_stats_rollup WHERE owner_id = $1', [s.A.id])).rows[0].total_failed_attempts, 5);
  const fails = await query(`SELECT detail::text AS d FROM access_logs WHERE member_id = $1 AND event = 'UNLOCK_FAILED'`, [s.member.id]);
  assert.equal(fails.rowCount, 5);
  assert.ok(fails.rows.every((r) => !/incorrecta/.test(r.d) && !r.d.includes(pw)));

  // Pasado el bloqueo, la clave correcta restablece todo
  await expireLock(s.member.id);
  const ok = await unlock(pw);
  assert.equal(ok.status, 200);
  secrets.push(ok.json.ticket);
  m = await memberRow(s.member.id);
  assert.equal(m.status, 'ACCEPTED');
  assert.equal(m.failed_attempts, 0);
  assert.equal(m.locked_until, null);

  // Entradas inválidas no cuentan como intento
  assert.equal((await unlock(undefined)).status, 400);
  assert.equal((await unlock('')).status, 400);
  assert.equal((await unlock(12345678)).status, 400);
  assert.equal((await memberRow(s.member.id)).failed_attempts, 0);
});

test('un fallo invalida el ticket vigente', async () => {
  const s = await setup();
  const t = await unlockOk(s);
  await expireLock(s.member.id);
  assert.equal((await s.B.c.post(`/invitations/${s.token}/unlock`, { password: 'mala-clave-123' })).status, 401);
  assert.equal((await download(s, t.ticket)).status, 401);
});

test('cooldown de reenvío del Canal 2 y la clave anterior deja de servir', async () => {
  const s = await setup();
  const first = await sendPassword(s);
  mailLines = [];
  const again = await s.B.c.post(`/invitations/${s.token}/verify-identity`);
  assert.equal(again.status, 429);
  assert.ok(again.json.retryAfterSeconds > 0 && again.json.retryAfterSeconds <= 60);
  assert.equal(mailLines.length, 0, 'no se reenvía durante el cooldown');
  assert.equal((await query(`SELECT count(*)::int AS n FROM access_logs WHERE member_id = $1 AND event = 'PASSWORD_SENT'`, [s.member.id])).rows[0].n, 1);

  config.invitation.resendCooldownSeconds = 0;
  try {
    const second = await sendPassword(s);
    assert.notEqual(second, first);
    const old = await s.B.c.post(`/invitations/${s.token}/unlock`, { password: first });
    assert.equal(old.status, 401);
    await expireLock(s.member.id);
    assert.equal((await s.B.c.post(`/invitations/${s.token}/unlock`, { password: second })).status, 200);
  } finally {
    config.invitation.resendCooldownSeconds = 60;
  }
});

test('max_downloads: al agotarse, unlock y descarga fallan', async () => {
  const s = await setup({ maxDownloads: 1 });
  const t = await unlockOk(s);
  assert.equal((await download(s, t.ticket)).status, 200);
  assert.equal((await memberRow(s.member.id)).download_count, 1);

  await expireLock(s.member.id);
  const pw = await sendPasswordForce(s);
  const u = await s.B.c.post(`/invitations/${s.token}/unlock`, { password: pw });
  assert.equal(u.status, 403);
  assert.match(u.json.error, /límite de descargas/i);

  // Aun con un ticket "vivo" inyectado a mano, la descarga se rechaza por el límite
  const forged = crypto.randomBytes(32).toString('base64url');
  secrets.push(forged);
  await query(`UPDATE workspace_members SET ticket_hash = $2, ticket_expires_at = now() + interval '60 seconds' WHERE id = $1`, [s.member.id, sha256Hex(forged)]);
  assert.equal((await download(s, forged)).status, 401);
  assert.equal((await memberRow(s.member.id)).download_count, 1);
  assert.equal((await s.B.c.get('/shared')).json.shared[0].downloads_remaining, 0);
});

async function sendPasswordForce(s) {
  config.invitation.resendCooldownSeconds = 0;
  try {
    return await sendPassword(s);
  } finally {
    config.invitation.resendCooldownSeconds = 60;
  }
}

test('revocar al miembro: unlock, verify-identity, info y descarga fallan; ticket limpiado', async () => {
  const s = await setup();
  const t = await unlockOk(s);
  assert.ok((await memberRow(s.member.id)).ticket_hash);

  const other = await registerUser('noowner');
  assert.equal((await other.c.del(`/vaults/${s.vault.id}/members/${s.member.id}`)).status, 404); // anti-IDOR
  assert.equal((await memberRow(s.member.id)).status, 'ACCEPTED');

  assert.equal((await s.A.c.del(`/vaults/${s.vault.id}/members/${s.member.id}`)).status, 200);
  const m = await memberRow(s.member.id);
  assert.equal(m.status, 'REVOKED');
  assert.equal(m.ticket_hash, null);
  assert.equal(m.ticket_expires_at, null);
  assert.equal((await query(`SELECT 1 FROM access_logs WHERE member_id = $1 AND event = 'MEMBER_REVOKED' AND owner_id = $2`, [s.member.id, s.A.id])).rowCount, 1);

  assert.equal((await download(s, t.ticket)).status, 403); // ya no es miembro vigente
  assert.equal((await s.B.c.post(`/invitations/${s.token}/unlock`, { password: t.pw })).status, 410);
  assert.equal((await s.B.c.post(`/invitations/${s.token}/verify-identity`)).status, 410);
  assert.equal((await createClient(srv.base).get(`/invitations/${s.token}`)).status, 410);
  assert.equal((await s.B.c.get('/shared')).json.shared.length, 0);
  assert.equal((await s.A.c.del(`/vaults/${s.vault.id}/members/${s.member.id}`)).status, 404); // ya revocado
});

test('invitaciones no disponibles: desconocida/mal formada 404; expirada, bóveda bloqueada o purgada 410', async () => {
  const anon = createClient(srv.base);
  for (const bad of ['x', 'a'.repeat(32), "' OR 1=1 --", '../etc/passwd', 'a'.repeat(300)]) {
    assert.equal((await anon.get(`/invitations/${encodeURIComponent(bad)}`)).status, 404, bad.slice(0, 20));
  }

  const s = await setup();
  assert.equal((await anon.get(`/invitations/${s.token}`)).status, 200);
  await query(`UPDATE workspace_members SET expires_at = now() - interval '1 second' WHERE id = $1`, [s.member.id]);
  assert.equal((await anon.get(`/invitations/${s.token}`)).status, 410);
  await query(`UPDATE workspace_members SET expires_at = now() + interval '1 day' WHERE id = $1`, [s.member.id]);
  assert.equal((await anon.get(`/invitations/${s.token}`)).status, 200);

  assert.equal((await s.A.c.patch(`/vaults/${s.vault.id}/status`, { status: 'LOCKED' })).status, 200);
  const g = await anon.get(`/invitations/${s.token}`);
  assert.equal(g.status, 410);
  assert.deepEqual(g.json, { error: 'Invitación no disponible' });
  assert.equal((await s.B.c.post(`/invitations/${s.token}/verify-identity`)).status, 410);
  assert.equal((await s.A.c.patch(`/vaults/${s.vault.id}/status`, { status: 'ACTIVE' })).status, 200);
  assert.equal((await anon.get(`/invitations/${s.token}`)).status, 200);

  const t = await unlockOk(s);
  assert.equal((await s.A.c.del(`/vaults/${s.vault.id}`)).status, 200); // purga total
  assert.equal((await anon.get(`/invitations/${s.token}`)).status, 410);
  assert.equal((await download(s, t.ticket)).status, 403); // miembro revocado por la purga
  assert.equal((await s.B.c.get('/shared')).json.shared.length, 0);
});

test('bóveda bloqueada tras desbloquear: la descarga se rechaza (410) sin consumir el ticket', async () => {
  const s = await setup();
  const t = await unlockOk(s);
  await s.A.c.patch(`/vaults/${s.vault.id}/status`, { status: 'LOCKED' });
  assert.equal((await download(s, t.ticket)).status, 410);
  const m = await memberRow(s.member.id);
  assert.equal(m.download_count, 0);
  assert.ok(m.ticket_hash);
});

test('alta de miembros: validaciones, anti-IDOR, duplicados y estado de la bóveda', async () => {
  const A = await registerUser('own');
  const X = await registerUser('ajeno');
  const v = (await A.c.post('/vaults', { name: 'V', expires_at: future(10) })).json.vault;
  const url = `/vaults/${v.id}/members`;
  const target = uniqueEmail('inv').toLowerCase();
  createdEmails.push(target);

  assert.equal((await A.c.post(url, { recipient_email: A.email })).status, 400); // a sí mismo
  assert.equal((await A.c.post(url, { recipient_email: A.email.toUpperCase() })).status, 400);
  for (const body of [
    {}, { recipient_email: 'no-correo' }, { recipient_email: 5 },
    { recipient_email: target, max_downloads: 0 }, { recipient_email: target, max_downloads: 11 },
    { recipient_email: target, max_downloads: '3' }, { recipient_email: target, max_downloads: 2.5 },
    { recipient_email: target, recipient_label: 'x'.repeat(121) }, { recipient_email: target, recipient_label: 7 },
    { recipient_email: target, expires_at: 'basura' },
    { recipient_email: target, expires_at: new Date(Date.now() - 1000).toISOString() },
    { recipient_email: target, expires_at: future(11) }, // mayor que la bóveda (10 días)
  ]) {
    assert.equal((await A.c.post(url, body)).status, 400, JSON.stringify(body));
  }
  const ok = await A.c.post(url, { recipient_email: `  ${target.toUpperCase()}  `, expires_at: future(5) });
  assert.equal(ok.status, 201);
  secrets.push(ok.json.invitationPath.split('/').pop());
  assert.equal(ok.json.member.recipient_email, target);
  assert.equal(ok.json.member.max_downloads, 3); // default
  assert.equal((await A.c.post(url, { recipient_email: target })).status, 409); // duplicado vigente
  assert.equal((await query(`SELECT 1 FROM access_logs WHERE vault_id = $1 AND event = 'MEMBER_INVITED'`, [v.id])).rowCount, 1);

  // Revocada -> se puede volver a invitar
  assert.equal((await A.c.del(`${url}/${ok.json.member.id}`)).status, 200);
  assert.equal((await A.c.post(url, { recipient_email: target })).status, 201);

  // Otro usuario / sin sesión / ids inválidos
  assert.equal((await X.c.post(url, { recipient_email: target })).status, 404);
  assert.equal((await createClient(srv.base).post(url, { recipient_email: target })).status, 401);
  assert.equal((await A.c.del(`${url}/no-uuid`)).status, 404);
  assert.equal((await A.c.post(`/vaults/no-uuid/members`, { recipient_email: target })).status, 404);

  // Bóveda bloqueada -> 409
  await A.c.patch(`/vaults/${v.id}/status`, { status: 'LOCKED' });
  assert.equal((await A.c.post(url, { recipient_email: uniqueEmail('z') })).status, 409);
});

test('GET /shared: solo muestra al destinatario con miembro ACCEPTED; PENDING y otros usuarios no', async () => {
  const s = await setup();
  const C = await registerUser('c');
  assert.equal((await s.B.c.get('/shared')).json.shared.length, 0); // PENDING
  await unlockOk(s);
  const b = (await s.B.c.get('/shared')).json.shared;
  assert.equal(b.length, 1);
  assert.equal(b[0].vault_id, s.vault.id);
  assert.equal(b[0].member_status, 'ACCEPTED');
  assert.equal((await C.c.get('/shared')).json.shared.length, 0);
  assert.equal((await createClient(srv.base).get('/shared')).status, 401);
});

test('SECRETOS: ni claves de Canal 2, ni tokens, ni tickets aparecen en access_logs ni en respuestas de metadatos', async () => {
  assert.ok(secrets.length >= 10, 'se esperaban secretos acumulados en las pruebas anteriores');
  const logs = await query(
    `SELECT event, ip, user_agent, detail::text AS d, owner_id::text AS o FROM access_logs WHERE owner_id = ANY($1::uuid[])`,
    [ownerIds],
  );
  assert.ok(logs.rowCount > 30);
  const blob = logs.rows.map((r) => `${r.event} ${r.ip} ${r.user_agent} ${r.d}`).join('\n');
  for (const secret of secrets) assert.ok(!blob.includes(secret), 'un secreto apareció en access_logs');
  for (const h of secrets.map(sha256Hex)) assert.ok(!blob.includes(h), 'un hash de secreto apareció en access_logs');

  // Metadatos del dueño: detalle de bóveda con miembros
  const s = await setup();
  const t = await unlockOk(s);
  const detail = JSON.stringify((await s.A.c.get(`/vaults/${s.vault.id}`)).json);
  const shared = JSON.stringify((await s.B.c.get('/shared')).json);
  const list = JSON.stringify((await s.A.c.get('/vaults')).json);
  for (const body of [detail, shared, list]) {
    for (const secret of [...secrets, t.ticket, s.token]) assert.ok(!body.includes(secret));
    for (const key of ['token_hash', 'password_hash', 'ticket_hash', 'ticket_expires_at', 'wrapped_kek', 'wrapped_dek']) {
      assert.ok(!body.includes(`"${key}"`), `expone ${key}`);
    }
  }
  // La invitación no se puede recuperar tras la creación
  assert.ok(!detail.includes('invitationPath') && !detail.includes('/invitacion/'));
});
