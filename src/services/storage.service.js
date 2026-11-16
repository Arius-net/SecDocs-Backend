import fs from 'node:fs/promises';
import path from 'node:path';
import {
  S3Client,
  PutObjectCommand,
  GetObjectCommand,
  DeleteObjectCommand,
} from '@aws-sdk/client-s3';
import { config } from '../config/env.js';

// Las claves de almacenamiento son siempre `<uuid>.enc` (evita path traversal y claves arbitrarias).
const KEY_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.enc$/i;

function assertKey(key) {
  if (typeof key !== 'string' || !KEY_RE.test(key)) {
    throw new Error('storage key inválida (se espera <uuid>.enc)');
  }
}

function assertBuffer(buf) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('El objeto a subir debe ser un Buffer');
}

// ---------------------------- Driver R2 (principal) ----------------------------

let s3Client = null;

function getR2() {
  if (s3Client) return s3Client;
  const { accountId, accessKeyId, secretAccessKey, bucket, endpoint } = config.r2;
  const missing = [
    ['R2_ACCESS_KEY_ID', accessKeyId],
    ['R2_SECRET_ACCESS_KEY', secretAccessKey],
    ['R2_BUCKET', bucket],
    ...(endpoint ? [] : [['R2_ACCOUNT_ID (o R2_ENDPOINT)', accountId]]),
  ]
    .filter(([, v]) => !v)
    .map(([n]) => n);
  if (missing.length) {
    throw new Error(
      `Cloudflare R2 no configurado: faltan ${missing.join(', ')}. ` +
        `Configúralas en .env o usa STORAGE_DRIVER=local solo para pruebas locales.`,
    );
  }
  s3Client = new S3Client({
    region: 'auto',
    endpoint: endpoint || `https://${accountId}.r2.cloudflarestorage.com`,
    credentials: { accessKeyId, secretAccessKey },
    forcePathStyle: true,
    // R2 no soporta los checksums opcionales por defecto del SDK reciente.
    requestChecksumCalculation: 'WHEN_REQUIRED',
    responseChecksumValidation: 'WHEN_REQUIRED',
  });
  return s3Client;
}

const r2Driver = {
  async upload(key, buffer) {
    await getR2().send(
      new PutObjectCommand({
        Bucket: config.r2.bucket,
        Key: key,
        Body: buffer,
        ContentType: 'application/octet-stream',
        ContentLength: buffer.length,
      }),
    );
  },
  async get(key) {
    const res = await getR2().send(new GetObjectCommand({ Bucket: config.r2.bucket, Key: key }));
    return Buffer.from(await res.Body.transformToByteArray());
  },
  async remove(key) {
    // S3/R2 DeleteObject es idempotente (no falla si no existe).
    await getR2().send(new DeleteObjectCommand({ Bucket: config.r2.bucket, Key: key }));
  },
};

// ---------------------- Driver local (solo pruebas locales) ----------------------

function localPath(key) {
  return path.join(path.resolve(config.storage.localDir), key);
}

const localDriver = {
  async upload(key, buffer) {
    await fs.mkdir(path.resolve(config.storage.localDir), { recursive: true });
    await fs.writeFile(localPath(key), buffer);
  },
  async get(key) {
    return fs.readFile(localPath(key));
  },
  async remove(key) {
    await fs.rm(localPath(key), { force: true });
  },
};

function driver() {
  const name = config.storage.driver;
  if (name === 'r2') return r2Driver;
  if (name === 'local') {
    if (config.isProd) throw new Error('STORAGE_DRIVER=local está prohibido en producción');
    return localDriver;
  }
  throw new Error(`STORAGE_DRIVER inválido: "${name}" (usa r2 o local)`);
}

// ------------------------------- API pública -------------------------------

/** Sube el binario ya cifrado (`<uuid>.enc`). */
export async function uploadEncryptedObject(key, buffer) {
  assertKey(key);
  assertBuffer(buffer);
  await driver().upload(key, buffer);
}

/** Descarga el binario cifrado completo como Buffer. */
export async function getEncryptedObject(key) {
  assertKey(key);
  return driver().get(key);
}

/** Borra el binario (idempotente). */
export async function deleteEncryptedObject(key) {
  assertKey(key);
  await driver().remove(key);
}
