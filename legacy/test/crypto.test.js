'use strict';

// Pruebas del módulo criptográfico. Sólo usan Node nativo: `node --test test/`

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const { Readable, Writable } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const fc = require('../src/crypto/fileCipher');
const keys = require('../src/crypto/keys');
const ft = require('../src/crypto/fileType');

const CHUNK = 1024; // bloques chicos para ejercitar muchos casos
const masterKeys = { keys: new Map([[1, crypto.randomBytes(32)]]), current: 1 };

async function streamDecrypt(dek, enc, pieceSize = 333) {
  const pieces = [];
  for (let i = 0; i < enc.length; i += pieceSize) pieces.push(enc.subarray(i, i + pieceSize));
  if (pieces.length === 0) pieces.push(Buffer.alloc(0));
  const out = [];
  await pipeline(Readable.from(pieces), fc.createDecryptStream(dek), new Writable({
    write(c, _e, cb) { out.push(c); cb(); },
  }));
  return Buffer.concat(out);
}

for (const size of [1, 100, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 5 * CHUNK + 17]) {
  test(`ida y vuelta: ${size} bytes (buffer y stream)`, async () => {
    const dek = keys.generateDek();
    const plain = crypto.randomBytes(size);
    const enc = fc.encryptBuffer(dek, plain, CHUNK);
    assert.equal(enc.length, fc.encryptedSize(size, CHUNK));
    assert.deepEqual(fc.decryptBuffer(dek, enc), plain);
    assert.deepEqual(await streamDecrypt(dek, enc), plain);
  });
}

test('el cifrado no contiene el texto claro y dos cifrados del mismo archivo difieren', () => {
  const dek = keys.generateDek();
  const plain = Buffer.from('CURP: XXXX000000HCSXXX00 · contraseña=supersecreta '.repeat(50));
  const a = fc.encryptBuffer(dek, plain, CHUNK);
  const b = fc.encryptBuffer(dek, plain, CHUNK);
  assert.equal(a.includes(Buffer.from('supersecreta')), false);
  assert.notDeepEqual(a, b); // prefijo de nonce aleatorio por archivo
});

test('tampering: cambiar 1 bit en cualquier posición se detecta', async () => {
  const dek = keys.generateDek();
  const plain = crypto.randomBytes(3 * CHUNK + 10);
  const enc = fc.encryptBuffer(dek, plain, CHUNK);
  for (const pos of [0, 5, 12, fc.HEADER_LEN, fc.HEADER_LEN + CHUNK + 3, enc.length - 1]) {
    const bad = Buffer.from(enc);
    bad[pos] ^= 0x01;
    assert.throws(() => fc.decryptBuffer(dek, bad), fc.IntegrityError, `pos ${pos}`);
    await assert.rejects(streamDecrypt(dek, bad), fc.IntegrityError, `stream pos ${pos}`);
  }
});

test('truncar el archivo (quitar el último bloque) se detecta', async () => {
  const dek = keys.generateDek();
  const enc = fc.encryptBuffer(dek, crypto.randomBytes(3 * CHUNK), CHUNK);
  const truncated = enc.subarray(0, enc.length - (CHUNK + fc.TAG_LEN));
  await assert.rejects(streamDecrypt(dek, truncated), fc.IntegrityError);
});

test('reordenar bloques se detecta', () => {
  const dek = keys.generateDek();
  const enc = fc.encryptBuffer(dek, crypto.randomBytes(3 * CHUNK), CHUNK);
  const rec = CHUNK + fc.TAG_LEN;
  const h = fc.HEADER_LEN;
  const swapped = Buffer.concat([enc.subarray(0, h), enc.subarray(h + rec, h + 2 * rec), enc.subarray(h, h + rec), enc.subarray(h + 2 * rec)]);
  assert.throws(() => fc.decryptBuffer(dek, swapped), fc.IntegrityError);
});

test('el stream nunca emite texto claro de un bloque alterado', async () => {
  const dek = keys.generateDek();
  const plain = crypto.randomBytes(4 * CHUNK);
  const enc = Buffer.from(fc.encryptBuffer(dek, plain, CHUNK));
  enc[fc.HEADER_LEN + 2 * (CHUNK + fc.TAG_LEN) + 7] ^= 0xff; // daña el bloque 2
  const out = [];
  await assert.rejects(pipeline(Readable.from([enc]), fc.createDecryptStream(dek), new Writable({
    write(c, _e, cb) { out.push(c); cb(); },
  })));
  const emitted = Buffer.concat(out);
  assert.ok(emitted.length <= 2 * CHUNK, 'sólo bloques 0 y 1 (verificados) pudieron salir');
  assert.deepEqual(emitted, plain.subarray(0, emitted.length));
});

test('llave equivocada falla', () => {
  const enc = fc.encryptBuffer(keys.generateDek(), Buffer.from('hola'), CHUNK);
  assert.throws(() => fc.decryptBuffer(keys.generateDek(), enc), fc.IntegrityError);
});

test('envelope: wrap/unwrap y la DEK queda amarrada a su archivo', () => {
  const dek = keys.generateDek();
  const id = crypto.randomUUID();
  const w = keys.wrapDek(dek, id, masterKeys);
  assert.match(w, /^v1\./);
  assert.deepEqual(keys.unwrapDek(w, id, masterKeys), dek);
  assert.throws(() => keys.unwrapDek(w, crypto.randomUUID(), masterKeys));
  assert.throws(() => keys.unwrapDek(null, id, masterKeys), /purgado/);
});

test('tokens: 256 bits, formato fijo, hash SHA-256', () => {
  const t = keys.generateToken();
  assert.ok(keys.isWellFormedToken(t));
  assert.equal(Buffer.from(t, 'base64url').length, 32);
  assert.equal(keys.hashToken(t).length, 64);
  assert.equal(keys.isWellFormedToken('../../etc/passwd'), false);
  assert.equal(new Set(Array.from({ length: 2000 }, keys.generateToken)).size, 2000);
});

test('tipos de archivo por magic bytes', () => {
  assert.equal(ft.detect('a.pdf', Buffer.from('%PDF-1.7\n...')).mime, 'application/pdf');
  assert.equal(ft.detect('.env', Buffer.from('DB_PASS=123\n')).mime, 'text/plain');
  assert.equal(ft.detect('id_ed25519.key', Buffer.from('-----BEGIN OPENSSH PRIVATE KEY-----')).ext, 'key');
  assert.throws(() => ft.detect('virus.pdf', Buffer.from('MZ\x90\x00')), /no corresponde/);
  assert.throws(() => ft.detect('a.exe', Buffer.from('MZ')), /no permitida/);
  assert.throws(() => ft.detect('a.txt', Buffer.from([0x41, 0x00, 0x42])), /no corresponde/);
  assert.equal(ft.sanitizeFilename('../../etc/passwd'), 'passwd');
  assert.equal(ft.sanitizeFilename('C:\\x\\a"b<c>.pdf'), 'a_b_c_.pdf');
});
