'use strict';

/**
 * Envelope encryption.
 *
 *  - DEK (Data Encryption Key): 32 bytes aleatorios, una por archivo.
 *  - KEK (Key Encryption Key): llave maestra en variables de entorno (MASTER_KEY_Vn).
 *
 * En la base de datos sólo se guarda la DEK *envuelta* (cifrada con la KEK).
 * Robar la base de datos o el disco por separado no basta para leer un archivo.
 * Al purgar un archivo se borra su DEK envuelta → crypto-shredding: aunque quede
 * una copia del .enc en un respaldo, ya no existe llave para descifrarla.
 */

const crypto = require('node:crypto');

const ALGO = 'aes-256-gcm';

function generateDek() {
  return crypto.randomBytes(32);
}

/** Devuelve "v<versión>.<iv>.<cifrado>.<tag>" en base64url. */
function wrapDek(dek, fileId, masterKeys) {
  const version = masterKeys.current;
  const kek = masterKeys.keys.get(version);
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv(ALGO, kek, iv);
  // La AAD amarra la DEK a su archivo: no se puede copiar la DEK de otro registro.
  c.setAAD(Buffer.from(`secdocs:file:${fileId}`));
  const ct = Buffer.concat([c.update(dek), c.final()]);
  const tag = c.getAuthTag();
  return [`v${version}`, iv.toString('base64url'), ct.toString('base64url'), tag.toString('base64url')].join('.');
}

function unwrapDek(wrapped, fileId, masterKeys) {
  if (!wrapped) throw new Error('El archivo fue purgado: la llave ya no existe');
  const [v, ivB, ctB, tagB] = wrapped.split('.');
  const version = Number(String(v).slice(1));
  const kek = masterKeys.keys.get(version);
  if (!kek) throw new Error(`No hay KEK para la versión ${version}`);
  const d = crypto.createDecipheriv(ALGO, kek, Buffer.from(ivB, 'base64url'));
  d.setAAD(Buffer.from(`secdocs:file:${fileId}`));
  d.setAuthTag(Buffer.from(tagB, 'base64url'));
  return Buffer.concat([d.update(Buffer.from(ctB, 'base64url')), d.final()]);
}

/** Token de enlace: 256 bits del CSPRNG en base64url (43 caracteres). */
function generateToken() {
  return crypto.randomBytes(32).toString('base64url');
}

/** En la BD sólo se guarda el SHA-256 del token: una fuga de la BD no revela URLs válidas. */
function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;
function isWellFormedToken(t) {
  return typeof t === 'string' && TOKEN_RE.test(t);
}

module.exports = { generateDek, wrapDek, unwrapDek, generateToken, hashToken, isWellFormedToken };
