'use strict';

/**
 * Prueba de integración de la lógica de negocio contra PostgreSQL real.
 * Uso: PGHOST=/tmp/pg PGPORT=5544 node --test test/integration/vault.itest.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Writable } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const { createPsqlDb } = require('./psqlDb');
const { localDisk } = require('../../src/storage');
const { createVault } = require('../../src/services/vault');
const { migrate } = require('../../src/db');

const db = createPsqlDb({
  host: process.env.PGHOST || '/tmp/pg', port: process.env.PGPORT || 5544, user: 'postgres', database: 'secdocs_test',
});
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-'));
const storage = localDisk(dir);
const hasher = {
  hash: async (pw) => `stub$${crypto.createHash('sha256').update(pw).digest('hex')}`,
  compare: async (pw, h) => h === `stub$${crypto.createHash('sha256').update(pw).digest('hex')}`,
};
const config = {
  masterKeys: { keys: new Map([[1, crypto.randomBytes(32)]]), current: 1 },
  publicBaseUrl: 'http://localhost:3000',
};
const vault = createVault({ db, storage, hasher, config, log: { error() {} } });
const ctx = { ip: '203.0.113.7', userAgent: 'test' };
const tokenOf = (url) => url.split('/s/')[1];
const SECRET = Buffer.from('%PDF-1.7\nCURP=ABCD010101HCSXXX09; password=Sup3rS3creta!\n' + 'x'.repeat(200_000));

async function download(ticket) {
  const r = await vault.redeemTicket(ticket, ctx);
  const { source, decrypt } = await vault.openDownload(r, ctx);
  const out = [];
  await pipeline(source, decrypt, new Writable({ write(c, _e, cb) { out.push(c); cb(); } }));
  await vault.finishDownload(r, true, ctx);
  return Buffer.concat(out);
}
const fileRow = async (id) => (await db.query(`SELECT * FROM vault_files WHERE id = $1`, [id])).rows[0];
const linkRow = async (id) => (await db.query(`SELECT * FROM share_links WHERE id = $1`, [id])).rows[0];
const unlock = (id) => db.query(`UPDATE share_links SET locked_until = NULL WHERE id = $1 RETURNING id`, [id]);

let user;

test.before(async () => {
  await db.raw('DROP TABLE IF EXISTS access_logs, share_links, vault_files, users CASCADE');
  await migrate(db);
});

test('registro, login y correo duplicado', async () => {
  user = await vault.register({ email: 'Alex@Example.com', password: 'una-clave-larga-123' }, ctx);
  assert.equal(user.email, 'alex@example.com');
  await assert.rejects(vault.register({ email: 'alex@example.com', password: 'otra-clave-larga-1' }, ctx), { status: 409 });
  await assert.rejects(vault.register({ email: 'x@y.com', password: 'corta' }, ctx), { status: 400 });
  assert.equal((await vault.login({ email: 'ALEX@example.com', password: 'una-clave-larga-123' }, ctx)).id, user.id);
  await assert.rejects(vault.login({ email: 'alex@example.com', password: 'mala' }, ctx), { status: 401 });
  await assert.rejects(vault.login({ email: 'nadie@example.com', password: 'mala' }, ctx), { status: 401 });
});

test('subida: el disco sólo tiene datos cifrados y la BD sólo la DEK envuelta', async () => {
  const f = await vault.uploadFile(user.id, { originalname: 'ine.pdf', buffer: Buffer.from(SECRET) }, { expiresInHours: 24 }, ctx);
  const row = await fileRow(f.id);
  const enc = fs.readFileSync(path.join(dir, row.storage_key));
  assert.equal(enc.includes(Buffer.from('Sup3rS3creta')), false);
  assert.equal(enc.includes(Buffer.from('%PDF')), false);
  assert.match(row.storage_key, /^[0-9a-f-]{36}\.enc$/);
  assert.match(row.wrapped_dek, /^v1\./);
  await assert.rejects(
    vault.uploadFile(user.id, { originalname: 'falso.pdf', buffer: Buffer.from('MZ\x90\x00binario') }, {}, ctx),
    { status: 415 },
  );
});

test('flujo completo de un receptor: clave errónea, retardo, descarga única y autodestrucción', async () => {
  const f = await vault.uploadFile(user.id, { originalname: 'contrato.pdf', buffer: Buffer.from(SECRET) }, { expiresInHours: 24 }, ctx);
  const link = await vault.createLink(user.id, f.id, { recipientLabel: 'Notaría', password: 'clave-fuera-de-banda', expiresInMinutes: 30 }, ctx);
  const token = tokenOf(link.url);

  // El token nunca se guarda en claro
  const lr = await linkRow(link.id);
  assert.notEqual(lr.token_hash, token);
  assert.equal(lr.token_hash, crypto.createHash('sha256').update(token).digest('hex'));

  assert.deepEqual(Object.keys(await vault.publicLinkInfo(token)).sort(), ['expiresAt', 'requiresPassword']);

  await assert.rejects(vault.verifyLinkPassword(token, 'incorrecta', ctx), (e) => e.status === 401 && e.extra.remainingAttempts === 4);
  // Retardo progresivo: reintentar de inmediato devuelve 429
  await assert.rejects(vault.verifyLinkPassword(token, 'clave-fuera-de-banda', ctx), { status: 429 });
  await unlock(link.id);

  const { ticket } = await vault.verifyLinkPassword(token, 'clave-fuera-de-banda', ctx);
  assert.deepEqual(await download(ticket), SECRET);

  // El ticket es de un solo uso y el enlace quedó consumido
  await assert.rejects(vault.redeemTicket(ticket, ctx), { status: 404 });
  await assert.rejects(vault.publicLinkInfo(token), { status: 404 });
  assert.equal((await linkRow(link.id)).status, 'CONSUMED');

  // Era el único enlace → crypto-shredding del archivo
  const row = await fileRow(f.id);
  assert.equal(row.status, 'PURGED');
  assert.equal(row.wrapped_dek, null);
  assert.equal(fs.existsSync(path.join(dir, row.storage_key)), false);
});

test('un enlace por receptor: el archivo sobrevive hasta que el último enlace termina; bloqueo tras 5 fallos', async () => {
  const f = await vault.uploadFile(user.id, { originalname: 'llaves.env', buffer: Buffer.from('DB_PASS=s3creto\n') }, { expiresInHours: 2 }, ctx);
  const a = await vault.createLink(user.id, f.id, { recipientLabel: 'Ana', password: 'clave-de-ana-01' }, ctx);
  const b = await vault.createLink(user.id, f.id, { recipientLabel: 'Beto', password: 'clave-de-beto-02' }, ctx);

  // La clave de Ana NO abre el enlace de Beto
  await assert.rejects(vault.verifyLinkPassword(tokenOf(b.url), 'clave-de-ana-01', ctx), { status: 401 });
  await unlock(b.id);

  const { ticket } = await vault.verifyLinkPassword(tokenOf(a.url), 'clave-de-ana-01', ctx);
  assert.equal((await download(ticket)).toString(), 'DB_PASS=s3creto\n');
  assert.equal((await fileRow(f.id)).status, 'ACTIVE', 'el enlace de Beto sigue activo');

  // Ataque de diccionario contra el enlace de Beto (ya lleva 1 fallo)
  for (let i = 2; i <= 4; i++) {
    await assert.rejects(vault.verifyLinkPassword(tokenOf(b.url), `intento-${i}`, ctx), { status: 401 });
    await unlock(b.id);
  }
  await assert.rejects(vault.verifyLinkPassword(tokenOf(b.url), 'intento-5', ctx), { status: 404 });
  assert.equal((await linkRow(b.id)).status, 'LOCKED');
  // Incluso con la clave correcta ya no abre
  await assert.rejects(vault.verifyLinkPassword(tokenOf(b.url), 'clave-de-beto-02', ctx), { status: 404 });
  assert.equal((await fileRow(f.id)).status, 'PURGED');
});

test('condición de carrera: dos descargas simultáneas con el mismo ticket → sólo una pasa', async () => {
  const f = await vault.uploadFile(user.id, { originalname: 'a.txt', buffer: Buffer.from('hola') }, { expiresInHours: 1, autoPurge: false }, ctx);
  const l = await vault.createLink(user.id, f.id, { recipientLabel: 'X', password: 'clave-larga-xx' }, ctx);
  const { ticket } = await vault.verifyLinkPassword(tokenOf(l.url), 'clave-larga-xx', ctx);
  const results = await Promise.allSettled(Array.from({ length: 8 }, () => vault.redeemTicket(ticket, ctx)));
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal((await linkRow(l.id)).download_count, 1);
});

test('tampering en disco: la descarga se cancela sin enviar nada', async () => {
  const f = await vault.uploadFile(user.id, { originalname: 'b.pdf', buffer: Buffer.from(SECRET) }, { expiresInHours: 1 }, ctx);
  const l = await vault.createLink(user.id, f.id, { recipientLabel: 'Y', password: 'clave-larga-yy' }, ctx);
  const p = path.join(dir, (await fileRow(f.id)).storage_key);
  const enc = fs.readFileSync(p);
  enc[enc.length - 100] ^= 0x01; // un solo bit en el último bloque
  fs.writeFileSync(p, enc);
  const { ticket } = await vault.verifyLinkPassword(tokenOf(l.url), 'clave-larga-yy', ctx);
  const r = await vault.redeemTicket(ticket, ctx);
  await assert.rejects(vault.openDownload(r, ctx), { status: 422, code: 'INTEGRITY_FAIL' });
});

test('expiración por tiempo y purga automática', async () => {
  const f = await vault.uploadFile(user.id, { originalname: 'c.txt', buffer: Buffer.from('temporal') }, { expiresInHours: 1 }, ctx);
  const l = await vault.createLink(user.id, f.id, { recipientLabel: 'Z', password: 'clave-larga-zz', expiresInMinutes: 1 }, ctx);
  await db.query(`UPDATE share_links SET expires_at = now() - interval '1 second' WHERE id = $1 RETURNING id`, [l.id]);
  const r = await vault.runPurgeCycle();
  assert.ok(r.expiredLinks >= 1);
  assert.equal((await linkRow(l.id)).status, 'EXPIRED');
  assert.equal((await fileRow(f.id)).status, 'PURGED');
  await assert.rejects(vault.publicLinkInfo(tokenOf(l.url)), { status: 404 });

  // Archivo vencido (aunque tenga enlaces activos)
  const g = await vault.uploadFile(user.id, { originalname: 'd.txt', buffer: Buffer.from('x') }, { expiresInHours: 1 }, ctx);
  const gl = await vault.createLink(user.id, g.id, { recipientLabel: 'W', password: 'clave-larga-ww' }, ctx);
  await db.query(`UPDATE vault_files SET expires_at = now() - interval '1 second' WHERE id = $1 RETURNING id`, [g.id]);
  await vault.runPurgeCycle();
  assert.equal((await fileRow(g.id)).status, 'PURGED');
  assert.equal((await linkRow(gl.id)).status, 'REVOKED');
});

test('respuestas uniformes, revocación, aislamiento entre usuarios y auditoría sin secretos', async () => {
  const fake = crypto.randomBytes(32).toString('base64url');
  const e1 = await vault.publicLinkInfo(fake).catch((e) => e);
  const e2 = await vault.publicLinkInfo('no-es-un-token').catch((e) => e);
  assert.equal(e1.status, 404);
  assert.equal(e1.message, e2.message);

  const f = await vault.uploadFile(user.id, { originalname: 'e.txt', buffer: Buffer.from('y') }, { expiresInHours: 1 }, ctx);
  const l = await vault.createLink(user.id, f.id, { recipientLabel: 'R', password: 'clave-larga-rr' }, ctx);

  const intruso = await vault.register({ email: 'intruso@example.com', password: 'clave-del-intruso' }, ctx);
  await assert.rejects(vault.listLinks(intruso.id, f.id), { status: 404 });
  await assert.rejects(vault.revokeLink(intruso.id, l.id, ctx), { status: 404 });
  await assert.rejects(vault.deleteFile(intruso.id, f.id, ctx), { status: 404 });

  await vault.revokeLink(user.id, l.id, ctx);
  await assert.rejects(vault.verifyLinkPassword(tokenOf(l.url), 'clave-larga-rr', ctx), { status: 404 });

  const events = await vault.listAudit(user.id);
  const kinds = new Set(events.map((e) => e.event));
  for (const k of ['FILE_UPLOADED', 'LINK_CREATED', 'VERIFY_FAIL', 'VERIFY_OK', 'DOWNLOAD_STARTED', 'DOWNLOAD_COMPLETED',
    'LINK_LOCKED', 'INTEGRITY_FAIL', 'LINK_EXPIRED', 'FILE_PURGED', 'LINK_REVOKED']) {
    assert.ok(kinds.has(k), `falta evento ${k}`);
  }
  const dump = await db.raw(`SELECT string_agg(row_to_json(a)::text, ' ') FROM access_logs a`);
  assert.equal(dump.includes(tokenOf(l.url)), false, 'la bitácora no debe contener tokens');
  assert.equal(dump.includes('clave-larga'), false, 'la bitácora no debe contener claves');
  assert.equal((await vault.listAudit(intruso.id)).some((e) => e.file_id === f.id), false);
});
