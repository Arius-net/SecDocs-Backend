import './helpers/env.js';
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import crypto from 'node:crypto';
import os from 'node:os';
import path from 'node:path';
import fs from 'node:fs';
import { config } from '../src/config/env.js';
import * as storage from '../src/services/storage.service.js';
import { encryptFile, generateKek } from '../src/services/crypto.service.js';

const newKey = () => `${crypto.randomUUID()}.enc`;
let fake;
let fakeStore;
let localDir;

before(async () => {
  localDir = fs.mkdtempSync(path.join(os.tmpdir(), 'secdocs-store-'));
  config.storage.localDir = localDir;

  // Servidor S3 falso (path-style) para ejercitar el SDK real de R2 sin credenciales.
  fakeStore = new Map();
  fake = http.createServer((req, res) => {
    const key = decodeURIComponent(req.url.split('?')[0]); // /bucket/key
    const chunks = [];
    req.on('data', (d) => chunks.push(d));
    req.on('end', () => {
      if (req.method === 'PUT') {
        fakeStore.set(key, Buffer.concat(chunks));
        res.writeHead(200, { ETag: '"x"' }).end();
      } else if (req.method === 'GET') {
        const v = fakeStore.get(key);
        if (!v) return res.writeHead(404, { 'Content-Type': 'application/xml' }).end('<Error><Code>NoSuchKey</Code></Error>');
        res.writeHead(200, { 'Content-Length': v.length }).end(v);
      } else if (req.method === 'DELETE') {
        fakeStore.delete(key);
        res.writeHead(204).end();
      } else res.writeHead(405).end();
    });
  });
  await new Promise((r) => fake.listen(0, '127.0.0.1', r));
});

after(async () => {
  await new Promise((r) => fake.close(r));
  fs.rmSync(localDir, { recursive: true, force: true });
});

test('driver local: upload/get/delete (idempotente)', async () => {
  config.storage.driver = 'local';
  const key = newKey();
  const data = crypto.randomBytes(2048);
  await storage.uploadEncryptedObject(key, data);
  assert.deepEqual(await storage.getEncryptedObject(key), data);
  await storage.deleteEncryptedObject(key);
  await storage.deleteEncryptedObject(key); // no falla si ya no existe
  await assert.rejects(() => storage.getEncryptedObject(key));
});

test('rechaza claves que no sean <uuid>.enc (path traversal)', async () => {
  config.storage.driver = 'local';
  for (const bad of ['../../etc/passwd', 'a.enc', `${crypto.randomUUID()}.txt`, '', null]) {
    await assert.rejects(() => storage.getEncryptedObject(bad), /storage key inválida/);
    await assert.rejects(() => storage.deleteEncryptedObject(bad), /storage key inválida/);
  }
  await assert.rejects(() => storage.uploadEncryptedObject(newKey(), 'no-buffer'), /Buffer/);
});

test('driver r2 sin configurar falla de forma clara', async () => {
  config.storage.driver = 'r2';
  Object.assign(config.r2, { accountId: '', accessKeyId: '', secretAccessKey: '', endpoint: '' });
  await assert.rejects(() => storage.getEncryptedObject(newKey()), /Cloudflare R2 no configurado: faltan R2_ACCESS_KEY_ID/);
});

test('driver r2 (SDK real @aws-sdk/client-s3): ciclo upload/get/delete', async () => {
  config.storage.driver = 'r2';
  Object.assign(config.r2, {
    accessKeyId: 'test-access',
    secretAccessKey: 'test-secret',
    bucket: 'secdocs',
    endpoint: `http://127.0.0.1:${fake.address().port}`,
  });
  const key = newKey();
  // Ciclo real con binario cifrado
  const plain = crypto.randomBytes(30_000);
  const { encrypted } = encryptFile(plain, generateKek());
  await storage.uploadEncryptedObject(key, encrypted);
  assert.ok(fakeStore.has(`/secdocs/${key}`));
  assert.deepEqual(await storage.getEncryptedObject(key), encrypted);
  await storage.deleteEncryptedObject(key);
  assert.ok(!fakeStore.has(`/secdocs/${key}`));
  await assert.rejects(() => storage.getEncryptedObject(key));
});

test('driver inválido es rechazado', async () => {
  config.storage.driver = 'ftp';
  await assert.rejects(() => storage.getEncryptedObject(newKey()), /STORAGE_DRIVER inválido/);
});
