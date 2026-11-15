import './helpers/env.js';
import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import * as c from '../src/services/crypto.service.js';

test('generateKek/generateDek producen 32 bytes aleatorios distintos', () => {
  const a = c.generateKek();
  const b = c.generateDek();
  assert.equal(a.length, 32);
  assert.equal(b.length, 32);
  assert.notDeepEqual(a, b);
});

test('encryptBuffer/decryptBuffer: ciclo completo, IV de 12 bytes y tag de 16', () => {
  const key = crypto.randomBytes(32);
  const plain = crypto.randomBytes(5000);
  const enc = c.encryptBuffer(plain, key);
  assert.equal(enc.iv.length, 12);
  assert.equal(enc.authTag.length, 16);
  assert.equal(enc.ciphertext.length, plain.length);
  assert.deepEqual(c.decryptBuffer(enc, key), plain);
});

test('IV distinto en cada operación (mismo texto y llave)', () => {
  const key = crypto.randomBytes(32);
  const plain = Buffer.from('mismo contenido');
  const ivs = new Set();
  for (let i = 0; i < 200; i++) ivs.add(c.encryptBuffer(plain, key).iv.toString('hex'));
  assert.equal(ivs.size, 200);
});

test('alterar 1 byte del ciphertext hace fallar el descifrado', () => {
  const key = crypto.randomBytes(32);
  const enc = c.encryptBuffer(Buffer.from('documento confidencial'), key);
  for (let i = 0; i < enc.ciphertext.length; i++) {
    const bad = Buffer.from(enc.ciphertext);
    bad[i] ^= 0x01;
    assert.throws(() => c.decryptBuffer({ ...enc, ciphertext: bad }, key), /autenticación/);
  }
});

test('alterar 1 byte del AuthTag o del IV hace fallar el descifrado', () => {
  const key = crypto.randomBytes(32);
  const enc = c.encryptBuffer(Buffer.from('documento confidencial'), key);
  for (let i = 0; i < 16; i++) {
    const tag = Buffer.from(enc.authTag);
    tag[i] ^= 0x80;
    assert.throws(() => c.decryptBuffer({ ...enc, authTag: tag }, key), /autenticación/);
  }
  const iv = Buffer.from(enc.iv);
  iv[0] ^= 0x01;
  assert.throws(() => c.decryptBuffer({ ...enc, iv }, key), /autenticación/);
});

test('llave incorrecta o de longitud inválida es rechazada', () => {
  const enc = c.encryptBuffer(Buffer.from('x'), crypto.randomBytes(32));
  assert.throws(() => c.decryptBuffer(enc, crypto.randomBytes(32)), /autenticación/);
  assert.throws(() => c.encryptBuffer(Buffer.from('x'), crypto.randomBytes(16)), /32 bytes/);
});

test('wrapKek/unwrapKek con MEK y formato iv:authTag:ciphertext en base64', () => {
  const kek = c.generateKek();
  const w = c.wrapKek(kek);
  const parts = w.split(':');
  assert.equal(parts.length, 3);
  assert.equal(Buffer.from(parts[0], 'base64').length, 12);
  assert.equal(Buffer.from(parts[1], 'base64').length, 16);
  assert.equal(Buffer.from(parts[2], 'base64').length, 32);
  assert.ok(!w.includes(kek.toString('base64')), 'la KEK no debe aparecer en claro');
  assert.deepEqual(c.unwrapKek(w), kek);
  // IV nuevo por cada envoltura
  assert.notEqual(c.wrapKek(kek), w);
});

test('wrapDek/unwrapDek con KEK; KEK equivocada falla; alteración falla', () => {
  const kek = c.generateKek();
  const dek = c.generateDek();
  const w = c.wrapDek(dek, kek);
  assert.deepEqual(c.unwrapDek(w, kek), dek);
  assert.throws(() => c.unwrapDek(w, c.generateKek()), /autenticación/);

  const [iv, tag, ct] = w.split(':');
  const ctBuf = Buffer.from(ct, 'base64');
  ctBuf[0] ^= 1;
  assert.throws(() => c.unwrapDek([iv, tag, ctBuf.toString('base64')].join(':'), kek), /autenticación/);
  const tagBuf = Buffer.from(tag, 'base64');
  tagBuf[3] ^= 1;
  assert.throws(() => c.unwrapDek([iv, tagBuf.toString('base64'), ct].join(':'), kek), /autenticación/);
  assert.throws(() => c.unwrapKek('basura'), /inválido/);
  assert.throws(() => c.unwrapKek(null), /inválida|ausente/);
});

test('cadena completa MEK -> KEK -> DEK: encryptFile/decryptFile', () => {
  const kek = c.generateKek();
  const wrappedKek = c.wrapKek(kek); // lo que se guardaría en vaults.wrapped_kek
  const file = crypto.randomBytes(100_000);

  const meta = c.encryptFile(file, kek);
  assert.notDeepEqual(meta.encrypted, file);
  assert.equal(meta.encrypted.length, file.length);

  // Descifrado como en el flujo real: MEK -> KEK -> DEK
  const kek2 = c.unwrapKek(wrappedKek);
  assert.deepEqual(c.decryptFile({ ...meta }, kek2), file);

  // Alterar 1 byte del binario .enc
  const bad = Buffer.from(meta.encrypted);
  bad[bad.length >> 1] ^= 1;
  assert.throws(() => c.decryptFile({ ...meta, encrypted: bad }, kek2), /autenticación/);

  // Alterar el AuthTag guardado en BD
  const tag = Buffer.from(meta.authTag, 'base64');
  tag[0] ^= 1;
  assert.throws(() => c.decryptFile({ ...meta, authTag: tag.toString('base64') }, kek2), /autenticación/);

  // Crypto-shredding: sin wrapped_dek es irrecuperable
  assert.throws(() => c.decryptFile({ ...meta, wrappedDek: null }, kek2), /crypto-shredding/);
});

test('cada archivo usa una DEK distinta', () => {
  const kek = c.generateKek();
  const a = c.encryptFile(Buffer.from('igual'), kek);
  const b = c.encryptFile(Buffer.from('igual'), kek);
  assert.notEqual(a.wrappedDek, b.wrappedDek);
  assert.notDeepEqual(a.encrypted, b.encrypted);
});

test('sha256Hex coincide con vector conocido; randomToken y safeEqualHex', () => {
  assert.equal(c.sha256Hex('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
  assert.notEqual(c.randomToken(), c.randomToken());
  assert.ok(c.safeEqualHex(c.sha256Hex('a'), c.sha256Hex('a')));
  assert.ok(!c.safeEqualHex(c.sha256Hex('a'), c.sha256Hex('b')));
});

test('MASTER_ENCRYPTION_KEY de longitud inválida es rechazada al cargar la configuración', async () => {
  const { parseKey32 } = await import('../src/config/env.js');
  assert.throws(() => parseKey32('abcd', 'MASTER_ENCRYPTION_KEY'), /32 bytes/);
  assert.equal(parseKey32('00'.repeat(32), 'K').length, 32);
  assert.equal(parseKey32(crypto.randomBytes(32).toString('base64'), 'K').length, 32);
});
