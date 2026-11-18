import './helpers/env.js';
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { config } from '../src/config/env.js';
import { pool, query } from '../src/db/pool.js';
import { runMigrations } from '../src/db/migrate.js';
import { unwrapKek, decryptFile } from '../src/services/crypto.service.js';
import { sanitizeFilename } from '../src/services/file-validation.service.js';
import { startServer, createClient, uniqueEmail } from './helpers/http.js';

const PASSWORD = 'Contraseña-Segura-123';
const FORBIDDEN_KEYS = ['wrapped_kek', 'wrapped_dek', 'iv', 'auth_tag', 'storage_key', 'token_hash', 'password_hash', 'ticket_hash'];
const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64',
);
const pdf = (marker = 'contenido-confidencial') =>
  Buffer.from(`%PDF-1.4\n1 0 obj\n<< /Type /Catalog >>\nendobj\n% ${marker}\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n`);

let srv;
let localDir;
const createdEmails = [];
const future = (days = 30) => new Date(Date.now() + days * 86_400_000).toISOString();
const storedFiles = () => fs.readdirSync(localDir);

before(async () => {
  localDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secdocs-vaults-'));
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

async function registerUser(tag = 'owner') {
  const email = uniqueEmail(tag);
  createdEmails.push(email);
  const c = createClient(srv.base);
  const r = await c.post('/auth/register', { email, password: PASSWORD });
  assert.equal(r.status, 201);
  return { c, id: r.json.user.id, email };
}

async function createVault(c, name = 'Bóveda de prueba', expires_at = future()) {
  const r = await c.post('/vaults', { name, expires_at });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  return r.json.vault;
}

const metrics = async (userId) =>
  (await query('SELECT total_storage_bytes, total_files_active, total_vaults_active FROM user_metrics WHERE owner_id = $1', [userId])).rows[0];

function assertNoSecrets(json) {
  const seen = [];
  (function walk(v) {
    if (Array.isArray(v)) return v.forEach(walk);
    if (v && typeof v === 'object') {
      for (const [k, val] of Object.entries(v)) {
        seen.push(k);
        walk(val);
      }
    }
  })(json);
  for (const f of FORBIDDEN_KEYS) assert.ok(!seen.includes(f), `la respuesta expone "${f}"`);
}

// ------------------------------- bóvedas -------------------------------

test('crear bóveda: KEK envuelta en BD, ausente en la respuesta; métricas y evento', async () => {
  const { c, id } = await registerUser();
  const r = await c.post('/vaults', { name: '  Contratos 2026  ', expires_at: future() });
  assert.equal(r.status, 201);
  const v = r.json.vault;
  assert.equal(v.name, 'Contratos 2026');
  assert.equal(v.status, 'ACTIVE');
  assertNoSecrets(r.json);

  const row = (await query('SELECT wrapped_kek FROM vaults WHERE id = $1', [v.id])).rows[0];
  assert.ok(row.wrapped_kek);
  assert.equal(row.wrapped_kek.split(':').length, 3);
  assert.ok(!JSON.stringify(r.json).includes(row.wrapped_kek));
  assert.equal(unwrapKek(row.wrapped_kek).length, 32); // KEK recuperable solo con la MEK

  assert.equal((await metrics(id)).total_vaults_active, 1);
  assert.equal((await query(`SELECT 1 FROM access_logs WHERE vault_id = $1 AND event = 'VAULT_CREATED'`, [v.id])).rowCount, 1);

  const list = await c.get('/vaults');
  assert.equal(list.status, 200);
  assert.equal(list.json.metrics.total_vaults_active, 1);
  assert.equal(list.json.vaults.length, 1);
  assert.equal(list.json.vaults[0].files_count, 0);
  assert.equal(list.json.vaults[0].members_count, 0);
  assertNoSecrets(list.json);
});

test('crear bóveda: validaciones de name y expires_at', async () => {
  const { c } = await registerUser();
  const bad = [
    {},
    { name: '', expires_at: future() },
    { name: '   ', expires_at: future() },
    { name: 'x'.repeat(151), expires_at: future() },
    { name: 123, expires_at: future() },
    { name: 'a\u0000b', expires_at: future() },
    { name: 'ok' },
    { name: 'ok', expires_at: 'no-es-fecha' },
    { name: 'ok', expires_at: new Date(Date.now() - 1000).toISOString() },
    { name: 'ok', expires_at: future(config.vaultMaxDays + 5) },
  ];
  for (const b of bad) assert.equal((await c.post('/vaults', b)).status, 400, JSON.stringify(b).slice(0, 60));
  assert.equal((await c.post('/vaults', { name: 'x'.repeat(150), expires_at: future(config.vaultMaxDays - 1) })).status, 201);
});

test('detalle de bóveda: metadatos, archivos activos y miembros, sin secretos', async () => {
  const { c } = await registerUser();
  const v = await createVault(c);
  await c.upload(`/vaults/${v.id}/files`, pdf(), 'a.pdf', 'application/pdf');
  await query(
    `INSERT INTO workspace_members (vault_id, recipient_email, recipient_label, token_hash, password_hash, expires_at)
     VALUES ($1, 'inv@example.com', 'Cliente', $2, $3, now() + interval '7 days')`,
    [v.id, crypto.randomBytes(32).toString('hex'), '$2b$12$' + 'x'.repeat(53)],
  );
  const r = await c.get(`/vaults/${v.id}`);
  assert.equal(r.status, 200);
  assertNoSecrets(r.json);
  assert.deepEqual(r.json.vault.keys, { algorithm: 'AES-256-GCM', kekStatus: 'ACTIVE' });
  assert.equal(r.json.files.length, 1);
  assert.deepEqual(Object.keys(r.json.files[0]).sort(), ['created_at', 'id', 'mime_type', 'original_filename', 'size_bytes', 'status']);
  assert.equal(r.json.members.length, 1);
  assert.deepEqual(
    Object.keys(r.json.members[0]).sort(),
    ['download_count', 'expires_at', 'failed_attempts', 'id', 'last_access_at', 'locked_until', 'max_downloads', 'recipient_email', 'recipient_label', 'status'],
  );
  assert.equal((await c.get('/vaults')).json.vaults[0].members_count, 1);
});

// ------------------------------- subida -------------------------------

test('subida válida: cifrada en storage (≠ texto plano), recuperable con MEK->KEK->DEK, métricas y MIME real', async () => {
  const { c, id } = await registerUser();
  const v = await createVault(c);
  const plain = pdf('MARCA-SECRETA-XYZ');

  const r = await c.upload(`/vaults/${v.id}/files`, plain, 'Informe.pdf', 'application/pdf');
  assert.equal(r.status, 201, JSON.stringify(r.json));
  assertNoSecrets(r.json);
  const f = r.json.file;
  assert.equal(f.mime_type, 'application/pdf');
  assert.equal(f.size_bytes, plain.length);
  assert.equal(f.original_filename, 'Informe.pdf');

  const row = (await query('SELECT * FROM vault_files WHERE id = $1', [f.id])).rows[0];
  assert.match(row.storage_key, /^[0-9a-f-]{36}\.enc$/);
  assert.ok(row.wrapped_dek && row.iv && row.auth_tag);
  const stored = fs.readFileSync(path.join(localDir, row.storage_key));
  assert.notDeepEqual(stored, plain);
  assert.ok(!stored.includes('MARCA-SECRETA-XYZ'), 'el binario en storage no debe contener texto plano');
  assert.equal(stored.length, plain.length); // GCM: ciphertext del mismo tamaño

  // Descifrado de punta a punta con la cadena real de llaves
  const kek = unwrapKek((await query('SELECT wrapped_kek FROM vaults WHERE id = $1', [v.id])).rows[0].wrapped_kek);
  const back = decryptFile({ encrypted: stored, wrappedDek: row.wrapped_dek, iv: row.iv, authTag: row.auth_tag }, kek);
  assert.deepEqual(back, plain);

  const m = await metrics(id);
  assert.equal(m.total_files_active, 1);
  assert.equal(m.total_storage_bytes, plain.length);
  assert.equal((await query(`SELECT 1 FROM access_logs WHERE file_id = $1 AND event = 'FILE_UPLOADED'`, [f.id])).rowCount, 1);
});

test('el MIME se detecta por magic bytes, ignorando Content-Type y extensión del cliente', async () => {
  const { c } = await registerUser();
  const v = await createVault(c);
  const png = await c.upload(`/vaults/${v.id}/files`, PNG, 'foto.pdf', 'application/pdf'); // PNG real "disfrazado" de PDF
  assert.equal(png.status, 201);
  assert.equal(png.json.file.mime_type, 'image/png');
  const txt = await c.upload(`/vaults/${v.id}/files`, Buffer.from('hola, ñandú\nsegunda línea\n'), 'nota.bin', 'image/png');
  assert.equal(txt.status, 201);
  assert.equal(txt.json.file.mime_type, 'text/plain');
  const csv = await c.upload(`/vaults/${v.id}/files`, Buffer.from('a,b\n1,2\n'), 'datos.csv', 'application/pdf');
  assert.equal(csv.status, 201);
  assert.equal(csv.json.file.mime_type, 'text/csv');
});

test('archivo > 15 MB se rechaza con 413 y no deja rastro', async () => {
  const { c, id } = await registerUser();
  const v = await createVault(c);
  const before = storedFiles().length;
  const big = Buffer.concat([pdf(), Buffer.alloc(16 * 1024 * 1024)]);
  const r = await c.upload(`/vaults/${v.id}/files`, big, 'enorme.pdf', 'application/pdf');
  assert.equal(r.status, 413);
  assert.equal(storedFiles().length, before);
  assert.equal((await query('SELECT count(*)::int AS n FROM vault_files WHERE vault_id = $1', [v.id])).rows[0].n, 0);
  assert.equal((await metrics(id)).total_files_active, 0);
  // Justo bajo el límite sí pasa
  const ok = Buffer.concat([pdf(), Buffer.alloc(14 * 1024 * 1024)]);
  assert.equal((await c.upload(`/vaults/${v.id}/files`, ok, 'grande.pdf', 'application/pdf')).status, 201);
});

test('archivos maliciosos disfrazados de PDF -> 415 (y nada se guarda)', async () => {
  const { c, id } = await registerUser();
  const v = await createVault(c);
  const before = storedFiles().length;
  const samples = {
    'ejecutable PE (MZ)': Buffer.concat([Buffer.from('MZ'), Buffer.alloc(62), Buffer.from('This program cannot be run in DOS mode.')]),
    'ELF': Buffer.concat([Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0]), Buffer.alloc(64)]),
    'script shell': Buffer.from('#!/bin/sh\nrm -rf /tmp/x\n'),
    'HTML': Buffer.from('<!DOCTYPE html><html><body>hola</body></html>'),
    'HTML con script': Buffer.from('<script>alert(document.cookie)</script>'),
    'SVG': Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
    'SVG con prólogo XML': Buffer.from('<?xml version="1.0"?><svg onload="alert(1)"/>'),
    'PHP': Buffer.from('<?php system($_GET["c"]); ?>'),
    'binario con bytes nulos': Buffer.from([0x01, 0x00, 0x02, 0x00, 0x03, 0x04, 0x00, 0x00]),
    'texto con byte nulo': Buffer.from('texto normal\u0000con nulo'),
    'no UTF-8': Buffer.from([0xff, 0xfe, 0xfd, 0x80, 0x81]),
  };
  for (const [label, buf] of Object.entries(samples)) {
    const r = await c.upload(`/vaults/${v.id}/files`, buf, 'inofensivo.pdf', 'application/pdf');
    assert.equal(r.status, 415, `${label} debería ser 415 y fue ${r.status}`);
  }
  assert.equal(storedFiles().length, before);
  assert.equal((await metrics(id)).total_files_active, 0);
  assert.equal((await c.upload(`/vaults/${v.id}/files`, Buffer.alloc(0), 'vacio.pdf', 'application/pdf')).status, 400);
  const noFile = await c.request('POST', `/vaults/${v.id}/files`, undefined, { body: new FormData() });
  assert.equal(noFile.status, 400);
});

test('sanitizeFilename elimina separadores, .. y caracteres de control', async () => {
  assert.equal(sanitizeFilename('../../etc/passwd'), 'etcpasswd');
  assert.equal(sanitizeFilename('..\\..\\windows\\system32\\a.pdf'), 'windowssystem32a.pdf');
  assert.equal(sanitizeFilename('a\u0000b\u001f.pdf'), 'ab.pdf');
  assert.equal(sanitizeFilename('....'), 'archivo');
  assert.equal(sanitizeFilename(''), 'archivo');
  assert.equal(sanitizeFilename('x'.repeat(400)).length, 255);
  assert.equal(sanitizeFilename(Buffer.from('Reseña final.pdf', 'utf8').toString('latin1')), 'Reseña final.pdf');

  const { c } = await registerUser();
  const v = await createVault(c);
  const r = await c.upload(`/vaults/${v.id}/files`, pdf(), '../../../etc/pass\\wd.pdf', 'application/pdf');
  assert.equal(r.status, 201);
  assert.ok(!/[\\/]|\.\./.test(r.json.file.original_filename), r.json.file.original_filename);
});

// ------------------------------- estado -------------------------------

test('bóveda LOCKED o expirada: subida 409; reactivar permite subir de nuevo', async () => {
  const { c, id } = await registerUser();
  const v = await createVault(c);

  assert.equal((await c.patch(`/vaults/${v.id}/status`, { status: 'LOCKED' })).status, 200);
  assert.equal((await query('SELECT status FROM vaults WHERE id = $1', [v.id])).rows[0].status, 'LOCKED');
  assert.equal((await c.upload(`/vaults/${v.id}/files`, pdf(), 'a.pdf', 'application/pdf')).status, 409);
  assert.equal((await query(`SELECT 1 FROM access_logs WHERE vault_id = $1 AND event = 'VAULT_LOCKED'`, [v.id])).rowCount, 1);

  assert.equal((await c.patch(`/vaults/${v.id}/status`, { status: 'ACTIVE' })).status, 200);
  assert.equal((await query(`SELECT 1 FROM access_logs WHERE vault_id = $1 AND event = 'VAULT_UNLOCKED'`, [v.id])).rowCount, 1);
  assert.equal((await c.upload(`/vaults/${v.id}/files`, pdf(), 'a.pdf', 'application/pdf')).status, 201);

  for (const bad of [{ status: 'PURGED' }, { status: 'EXPIRED' }, { status: 'x' }, {}]) {
    assert.equal((await c.patch(`/vaults/${v.id}/status`, bad)).status, 400);
  }

  // Expirada por fecha (aunque el status siga ACTIVE): no se sube ni se reactiva
  await query(`UPDATE vaults SET expires_at = now() - interval '1 minute' WHERE id = $1`, [v.id]);
  assert.equal((await c.upload(`/vaults/${v.id}/files`, pdf(), 'b.pdf', 'application/pdf')).status, 409);
  assert.equal((await c.patch(`/vaults/${v.id}/status`, { status: 'ACTIVE' })).status, 409);

  // EXPIRED / PURGED -> 409 al cambiar estado
  await query(`UPDATE vaults SET status = 'EXPIRED' WHERE id = $1`, [v.id]);
  assert.equal((await c.patch(`/vaults/${v.id}/status`, { status: 'LOCKED' })).status, 409);
  assert.equal((await metrics(id)).total_files_active, 1);
});

// ------------------------------- borrado -------------------------------

test('borrar archivo: crypto-shredding (wrapped_dek NULL), objeto eliminado y métricas', async () => {
  const { c, id } = await registerUser();
  const v = await createVault(c);
  const f1 = (await c.upload(`/vaults/${v.id}/files`, pdf('uno'), 'uno.pdf', 'application/pdf')).json.file;
  const f2 = (await c.upload(`/vaults/${v.id}/files`, PNG, 'dos.png', 'image/png')).json.file;
  const key1 = (await query('SELECT storage_key FROM vault_files WHERE id = $1', [f1.id])).rows[0].storage_key;
  assert.ok(fs.existsSync(path.join(localDir, key1)));
  assert.equal((await metrics(id)).total_files_active, 2);

  const r = await c.del(`/vaults/${v.id}/files/${f1.id}`);
  assert.equal(r.status, 200);
  const row = (await query('SELECT status, wrapped_dek, purged_at FROM vault_files WHERE id = $1', [f1.id])).rows[0];
  assert.equal(row.status, 'PURGED');
  assert.equal(row.wrapped_dek, null);
  assert.ok(row.purged_at);
  assert.ok(!fs.existsSync(path.join(localDir, key1)), 'el .enc debe borrarse del storage');
  const m = await metrics(id);
  assert.equal(m.total_files_active, 1);
  assert.equal(m.total_storage_bytes, PNG.length);
  assert.equal((await query(`SELECT 1 FROM access_logs WHERE file_id = $1 AND event = 'FILE_PURGED'`, [f1.id])).rowCount, 1);

  assert.equal((await c.del(`/vaults/${v.id}/files/${f1.id}`)).status, 404); // ya purgado
  assert.equal((await c.get(`/vaults/${v.id}`)).json.files.length, 1);
  assert.equal((await c.del(`/vaults/${v.id}/files/${f2.id}`)).status, 200);
  const m2 = await metrics(id);
  assert.equal(m2.total_files_active, 0);
  assert.equal(m2.total_storage_bytes, 0);
});

test('borrar bóveda completa: KEK y DEKs NULL, objetos eliminados, miembros revocados, métricas en 0', async () => {
  const { c, id } = await registerUser();
  const v = await createVault(c);
  const files = [];
  for (const [buf, name] of [[pdf('a'), 'a.pdf'], [PNG, 'b.png'], [pdf('c'), 'c.pdf']]) {
    files.push((await c.upload(`/vaults/${v.id}/files`, buf, name)).json.file);
  }
  const keys = (await query('SELECT storage_key FROM vault_files WHERE vault_id = $1', [v.id])).rows.map((r) => r.storage_key);
  assert.equal(keys.length, 3);
  assert.ok(keys.every((k) => fs.existsSync(path.join(localDir, k))));
  const mem = await query(
    `INSERT INTO workspace_members (vault_id, recipient_email, token_hash, password_hash, expires_at, status, ticket_hash, ticket_expires_at)
     VALUES ($1, 'x@example.com', $2, 'h', now() + interval '1 day', 'ACCEPTED', $3, now() + interval '1 minute') RETURNING id`,
    [v.id, crypto.randomBytes(32).toString('hex'), crypto.randomBytes(32).toString('hex')],
  );

  const r = await c.del(`/vaults/${v.id}`);
  assert.equal(r.status, 200);
  assert.equal(r.json.purged_files, 3);

  const vault = (await query('SELECT status, wrapped_kek, purged_at FROM vaults WHERE id = $1', [v.id])).rows[0];
  assert.equal(vault.status, 'PURGED');
  assert.equal(vault.wrapped_kek, null);
  assert.ok(vault.purged_at);
  const rows = (await query('SELECT status, wrapped_dek, iv, auth_tag FROM vault_files WHERE vault_id = $1', [v.id])).rows;
  assert.equal(rows.length, 3);
  assert.ok(rows.every((x) => x.status === 'PURGED' && x.wrapped_dek === null && x.iv === null && x.auth_tag === null));
  assert.ok(keys.every((k) => !fs.existsSync(path.join(localDir, k))), 'todos los .enc eliminados');
  const member = (await query('SELECT status, ticket_hash FROM workspace_members WHERE id = $1', [mem.rows[0].id])).rows[0];
  assert.equal(member.status, 'REVOKED');
  assert.equal(member.ticket_hash, null);

  const m = await metrics(id);
  assert.deepEqual(m, { total_storage_bytes: 0, total_files_active: 0, total_vaults_active: 0 });
  assert.equal((await query(`SELECT 1 FROM access_logs WHERE vault_id = $1 AND event = 'VAULT_PURGED'`, [v.id])).rowCount, 1);

  assert.equal((await c.get('/vaults')).json.vaults.length, 0);
  assert.equal((await c.get('/vaults?include_purged=true')).json.vaults.length, 1);
  const detail = await c.get(`/vaults/${v.id}`);
  assert.equal(detail.json.vault.keys.kekStatus, 'PURGED');
  assert.equal(detail.json.files.length, 0);
  assert.equal((await c.del(`/vaults/${v.id}`)).status, 404);
  assert.equal((await c.upload(`/vaults/${v.id}/files`, pdf(), 'z.pdf')).status, 409);
  void files;
});

// ------------------------------- anti-IDOR -------------------------------

test('anti-IDOR: el usuario B no puede ver, modificar, subir ni borrar la bóveda/archivos de A (404)', async () => {
  const a = await registerUser('victima');
  const b = await registerUser('atacante');
  const v = await createVault(a.c, 'Privada de A');
  const f = (await a.c.upload(`/vaults/${v.id}/files`, pdf('privado'), 'secreto.pdf')).json.file;
  const filesBefore = storedFiles().length;

  assert.equal((await b.c.get(`/vaults/${v.id}`)).status, 404);
  assert.equal((await b.c.patch(`/vaults/${v.id}/status`, { status: 'LOCKED' })).status, 404);
  assert.equal((await b.c.upload(`/vaults/${v.id}/files`, pdf(), 'intruso.pdf')).status, 404);
  assert.equal((await b.c.del(`/vaults/${v.id}/files/${f.id}`)).status, 404);
  assert.equal((await b.c.del(`/vaults/${v.id}`)).status, 404);
  // Mismo archivo pero apuntando a una bóveda propia de B
  const vb = await createVault(b.c, 'Propia de B');
  assert.equal((await b.c.del(`/vaults/${vb.id}/files/${f.id}`)).status, 404);
  // Ids inválidos
  for (const bad of ['no-uuid', "1' OR '1'='1", '../x']) {
    assert.equal((await b.c.get(`/vaults/${encodeURIComponent(bad)}`)).status, 404);
    assert.equal((await b.c.del(`/vaults/${encodeURIComponent(bad)}`)).status, 404);
  }
  // B no ve la bóveda de A en su listado
  const listB = (await b.c.get('/vaults')).json.vaults;
  assert.deepEqual(listB.map((x) => x.id), [vb.id]);

  // Todo de A intacto
  assert.equal(storedFiles().length, filesBefore);
  const vault = (await query('SELECT status, wrapped_kek FROM vaults WHERE id = $1', [v.id])).rows[0];
  assert.equal(vault.status, 'ACTIVE');
  assert.ok(vault.wrapped_kek);
  assert.equal((await query('SELECT status FROM vault_files WHERE id = $1', [f.id])).rows[0].status, 'ACTIVE');
  assert.equal((await a.c.get(`/vaults/${v.id}`)).json.files.length, 1);
});

test('todos los endpoints de /vaults exigen autenticación', async () => {
  const c = createClient(srv.base);
  const id = crypto.randomUUID();
  assert.equal((await c.get('/vaults')).status, 401);
  assert.equal((await c.post('/vaults', { name: 'x', expires_at: future() })).status, 401);
  assert.equal((await c.get(`/vaults/${id}`)).status, 401);
  assert.equal((await c.patch(`/vaults/${id}/status`, { status: 'LOCKED' })).status, 401);
  assert.equal((await c.del(`/vaults/${id}`)).status, 401);
  assert.equal((await c.upload(`/vaults/${id}/files`, pdf(), 'a.pdf')).status, 401);
  assert.equal((await c.del(`/vaults/${id}/files/${id}`)).status, 401);
});

test('si la transacción falla tras subir al storage, el objeto huérfano se elimina', async () => {
  const { c } = await registerUser();
  const v = await createVault(c);
  const before = storedFiles().length;
  // Se fuerza el fallo: la bóveda se purga a nivel BD justo antes de la inserción (simulado con trigger temporal)
  await query(`CREATE OR REPLACE FUNCTION tmp_fail_insert() RETURNS trigger AS $$ BEGIN RAISE EXCEPTION 'fallo simulado'; END $$ LANGUAGE plpgsql`);
  await query('CREATE TRIGGER tmp_fail BEFORE INSERT ON vault_files FOR EACH ROW EXECUTE FUNCTION tmp_fail_insert()');
  try {
    const r = await c.upload(`/vaults/${v.id}/files`, pdf(), 'a.pdf');
    assert.equal(r.status, 500);
  } finally {
    await query('DROP TRIGGER tmp_fail ON vault_files');
    await query('DROP FUNCTION tmp_fail_insert()');
  }
  assert.equal(storedFiles().length, before, 'no debe quedar objeto huérfano');
});
