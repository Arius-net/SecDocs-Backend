import crypto from 'node:crypto';
import { config } from '../config/env.js';

const ALGORITHM = 'aes-256-gcm';
const KEY_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;

/** Valida que una llave sea un Buffer de exactamente 32 bytes (256 bits). */
function assertKey(key, name) {
  if (!Buffer.isBuffer(key) || key.length !== KEY_BYTES) {
    throw new Error(`${name} debe ser un Buffer de exactamente ${KEY_BYTES} bytes`);
  }
}

// Valida la Master Key (MEK) al inicializar el módulo.
const MEK = config.masterKey;
assertKey(MEK, 'MASTER_ENCRYPTION_KEY');

// --------------------------------------------------------------------------
// Primitivas AES-256-GCM (IV aleatorio de 12 bytes en CADA operación)
// --------------------------------------------------------------------------

/** Cifra `plaintext` con `key`. Devuelve { iv, authTag, ciphertext } (Buffers). */
export function encryptBuffer(plaintext, key) {
  assertKey(key, 'key');
  if (!Buffer.isBuffer(plaintext)) throw new TypeError('plaintext debe ser un Buffer');
  const iv = crypto.randomBytes(IV_BYTES);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return { iv, authTag: cipher.getAuthTag(), ciphertext };
}

/** Descifra y autentica. Lanza error si ciphertext, IV o AuthTag fueron alterados. */
export function decryptBuffer({ iv, authTag, ciphertext }, key) {
  assertKey(key, 'key');
  if (!Buffer.isBuffer(iv) || iv.length !== IV_BYTES) throw new Error('IV inválido');
  if (!Buffer.isBuffer(authTag) || authTag.length !== TAG_BYTES) throw new Error('AuthTag inválido');
  if (!Buffer.isBuffer(ciphertext)) throw new TypeError('ciphertext debe ser un Buffer');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv, { authTagLength: TAG_BYTES });
  decipher.setAuthTag(authTag);
  try {
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    // Mensaje genérico: no revelar detalles del fallo criptográfico.
    throw new Error('Fallo de autenticación al descifrar: datos alterados o llave incorrecta');
  }
}

// --------------------------------------------------------------------------
// Generación de llaves
// --------------------------------------------------------------------------

/** KEK aleatoria de 32 bytes (una por bóveda). */
export function generateKek() {
  return crypto.randomBytes(KEY_BYTES);
}

/** DEK aleatoria de 32 bytes (una por archivo). */
export function generateDek() {
  return crypto.randomBytes(KEY_BYTES);
}

// --------------------------------------------------------------------------
// Empaquetado `iv:authTag:ciphertext` (base64) para wrapped_kek / wrapped_dek
// --------------------------------------------------------------------------

function pack({ iv, authTag, ciphertext }) {
  return [iv, authTag, ciphertext].map((b) => b.toString('base64')).join(':');
}

function unpack(packed) {
  if (typeof packed !== 'string') throw new Error('Llave envuelta ausente o inválida');
  const parts = packed.split(':');
  if (parts.length !== 3) throw new Error('Formato de llave envuelta inválido');
  const [iv, authTag, ciphertext] = parts.map((p) => Buffer.from(p, 'base64'));
  return { iv, authTag, ciphertext };
}

function wrap(keyToWrap, wrappingKey, name) {
  assertKey(keyToWrap, name);
  return pack(encryptBuffer(keyToWrap, wrappingKey));
}

function unwrap(packed, wrappingKey, name) {
  const key = decryptBuffer(unpack(packed), wrappingKey);
  assertKey(key, name);
  return key;
}

/** Envuelve una KEK con la MEK -> valor para `vaults.wrapped_kek`. */
export function wrapKek(kek) {
  return wrap(kek, MEK, 'KEK');
}

/** Desenvuelve `vaults.wrapped_kek` con la MEK. */
export function unwrapKek(wrappedKek) {
  return unwrap(wrappedKek, MEK, 'KEK');
}

/** Envuelve una DEK con la KEK de la bóveda -> valor para `vault_files.wrapped_dek`. */
export function wrapDek(dek, kek) {
  assertKey(kek, 'KEK');
  return wrap(dek, kek, 'DEK');
}

/** Desenvuelve `vault_files.wrapped_dek` con la KEK de la bóveda. */
export function unwrapDek(wrappedDek, kek) {
  assertKey(kek, 'KEK');
  return unwrap(wrappedDek, kek, 'DEK');
}

// --------------------------------------------------------------------------
// Cifrado de archivos (Envelope): genera DEK, cifra el buffer y envuelve la DEK
// --------------------------------------------------------------------------

/**
 * Cifra el contenido de un archivo con una DEK nueva.
 * Devuelve el binario a subir a R2 (`encrypted`) y los metadatos para `vault_files`
 * (`wrappedDek`, `iv`, `authTag` en base64). La DEK en claro no se devuelve.
 */
export function encryptFile(plaintext, kek) {
  const dek = generateDek();
  try {
    const { iv, authTag, ciphertext } = encryptBuffer(plaintext, dek);
    return {
      encrypted: ciphertext,
      wrappedDek: wrapDek(dek, kek),
      iv: iv.toString('base64'),
      authTag: authTag.toString('base64'),
    };
  } finally {
    dek.fill(0);
  }
}

/** Descifra el binario de R2 usando metadatos de `vault_files` y la KEK de la bóveda. */
export function decryptFile({ encrypted, wrappedDek, iv, authTag }, kek) {
  if (!wrappedDek) throw new Error('Archivo purgado: DEK destruida (crypto-shredding)');
  const dek = unwrapDek(wrappedDek, kek);
  try {
    return decryptBuffer(
      { iv: Buffer.from(iv, 'base64'), authTag: Buffer.from(authTag, 'base64'), ciphertext: encrypted },
      dek,
    );
  } finally {
    dek.fill(0);
  }
}

// --------------------------------------------------------------------------
// Hashing / utilidades
// --------------------------------------------------------------------------

/** SHA-256 en hex (64 chars): tokens de invitación y tickets. */
export function sha256Hex(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

/** Token aleatorio URL-safe (CSPRNG). */
export function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

/** Comparación de hashes en tiempo constante. */
export function safeEqualHex(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}
