'use strict';

/**
 * Cifrado de archivos por bloques con AES-256-GCM (construcción tipo STREAM).
 *
 * ¿Por qué por bloques? El modo GCM sólo verifica el tag al FINAL del mensaje.
 * Si se descifra un archivo entero en streaming, Node entrega texto claro antes
 * de saber si el archivo fue manipulado. Al dividirlo en bloques, cada bloque
 * tiene su propio tag y sólo se libera texto claro ya verificado.
 *
 * Formato del archivo .enc:
 *   HEADER (16 bytes) = "SDOC" | versión (1) | tamañoBloque uint32 BE (4) | prefijoNonce (7)
 *   BLOQUE i          = cifrado (<= tamañoBloque) | tag (16)
 *
 * Nonce de cada bloque (12 bytes) = prefijoNonce(7) | contador uint32 BE (4) | banderaFinal (1)
 * AAD de cada bloque = HEADER completo.
 *
 * - El contador impide reordenar bloques.
 * - La bandera final impide truncar el archivo (quitar bloques del final).
 * - El HEADER como AAD impide alterar el tamaño de bloque o el prefijo.
 * - Cada archivo tiene su propia DEK aleatoria, así que el nonce nunca se repite
 *   con la misma llave.
 */

const crypto = require('node:crypto');
const { Transform } = require('node:stream');

const MAGIC = Buffer.from('SDOC');
const VERSION = 1;
const HEADER_LEN = 16;
const TAG_LEN = 16;
const PREFIX_LEN = 7;
const DEFAULT_CHUNK = 64 * 1024;
const ALGO = 'aes-256-gcm';

class IntegrityError extends Error {
  constructor(msg) {
    super(msg);
    this.name = 'IntegrityError';
  }
}

function buildHeader(chunkSize, prefix) {
  const h = Buffer.alloc(HEADER_LEN);
  MAGIC.copy(h, 0);
  h.writeUInt8(VERSION, 4);
  h.writeUInt32BE(chunkSize, 5);
  prefix.copy(h, 9);
  return h;
}

function parseHeader(h) {
  if (h.length !== HEADER_LEN || !h.subarray(0, 4).equals(MAGIC)) {
    throw new IntegrityError('Encabezado inválido');
  }
  if (h.readUInt8(4) !== VERSION) throw new IntegrityError('Versión de formato no soportada');
  const chunkSize = h.readUInt32BE(5);
  if (chunkSize < 1024 || chunkSize > 16 * 1024 * 1024) throw new IntegrityError('Tamaño de bloque inválido');
  return { chunkSize, prefix: h.subarray(9, 16) };
}

function nonceFor(prefix, index, isFinal) {
  if (index > 0xffffffff) throw new Error('Archivo demasiado grande');
  const n = Buffer.alloc(12);
  prefix.copy(n, 0);
  n.writeUInt32BE(index, PREFIX_LEN);
  n.writeUInt8(isFinal ? 1 : 0, 11);
  return n;
}

function sealChunk(dek, header, prefix, index, isFinal, plain) {
  const c = crypto.createCipheriv(ALGO, dek, nonceFor(prefix, index, isFinal), { authTagLength: TAG_LEN });
  c.setAAD(header);
  const ct = Buffer.concat([c.update(plain), c.final()]);
  return Buffer.concat([ct, c.getAuthTag()]);
}

function openChunk(dek, header, prefix, index, isFinal, record) {
  if (record.length < TAG_LEN) throw new IntegrityError('Bloque truncado');
  const ct = record.subarray(0, record.length - TAG_LEN);
  const tag = record.subarray(record.length - TAG_LEN);
  const d = crypto.createDecipheriv(ALGO, dek, nonceFor(prefix, index, isFinal), { authTagLength: TAG_LEN });
  d.setAAD(header);
  d.setAuthTag(tag);
  try {
    return Buffer.concat([d.update(ct), d.final()]);
  } catch {
    throw new IntegrityError(`Falló la verificación del bloque ${index}: el archivo fue alterado`);
  }
}

/**
 * Cifra un Buffer en memoria. Genera los bloques uno por uno (generador),
 * para escribirlos en disco sin duplicar el archivo completo en memoria.
 */
function* encryptChunks(dek, plaintext, chunkSize = DEFAULT_CHUNK) {
  if (dek.length !== 32) throw new Error('La DEK debe ser de 32 bytes');
  const prefix = crypto.randomBytes(PREFIX_LEN);
  const header = buildHeader(chunkSize, prefix);
  yield header;
  const total = plaintext.length;
  let index = 0;
  let offset = 0;
  // Siempre hay al menos un bloque (el final), aunque el archivo esté vacío.
  do {
    const end = Math.min(offset + chunkSize, total);
    const isFinal = end >= total;
    yield sealChunk(dek, header, prefix, index, isFinal, plaintext.subarray(offset, end));
    offset = end;
    index += 1;
  } while (offset < total);
}

function encryptBuffer(dek, plaintext, chunkSize) {
  return Buffer.concat([...encryptChunks(dek, plaintext, chunkSize)]);
}

/**
 * Transform stream: recibe el .enc y emite texto claro, bloque por bloque,
 * sólo después de verificar el tag de cada bloque.
 */
function createDecryptStream(dek) {
  let buf = Buffer.alloc(0);
  let header = null;
  let meta = null;
  let index = 0;
  let sawFinal = false;

  return new Transform({
    transform(chunk, _enc, cb) {
      try {
        buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
        if (!header) {
          if (buf.length < HEADER_LEN) return cb();
          header = Buffer.from(buf.subarray(0, HEADER_LEN));
          meta = parseHeader(header);
          buf = buf.subarray(HEADER_LEN);
        }
        const rec = meta.chunkSize + TAG_LEN;
        // Sólo procesamos un bloque completo si sabemos que NO es el último,
        // es decir, si ya hay más bytes después de él.
        while (buf.length > rec) {
          this.push(openChunk(dek, header, meta.prefix, index, false, buf.subarray(0, rec)));
          buf = buf.subarray(rec);
          index += 1;
        }
        cb();
      } catch (e) {
        cb(e);
      }
    },
    flush(cb) {
      try {
        if (!header) throw new IntegrityError('Archivo vacío o sin encabezado');
        if (sawFinal) return cb();
        this.push(openChunk(dek, header, meta.prefix, index, true, buf));
        sawFinal = true;
        cb();
      } catch (e) {
        cb(e);
      }
    },
  });
}

function decryptBuffer(dek, data) {
  const header = Buffer.from(data.subarray(0, HEADER_LEN));
  const meta = parseHeader(header);
  const rec = meta.chunkSize + TAG_LEN;
  const out = [];
  let off = HEADER_LEN;
  let index = 0;
  while (data.length - off > rec) {
    out.push(openChunk(dek, header, meta.prefix, index, false, data.subarray(off, off + rec)));
    off += rec;
    index += 1;
  }
  out.push(openChunk(dek, header, meta.prefix, index, true, data.subarray(off)));
  return Buffer.concat(out);
}

/** Tamaño exacto del .enc para un archivo de `size` bytes. */
function encryptedSize(size, chunkSize = DEFAULT_CHUNK) {
  const chunks = Math.max(1, Math.ceil(size / chunkSize));
  return HEADER_LEN + size + chunks * TAG_LEN;
}

module.exports = {
  encryptChunks,
  encryptBuffer,
  decryptBuffer,
  createDecryptStream,
  encryptedSize,
  IntegrityError,
  DEFAULT_CHUNK,
  HEADER_LEN,
  TAG_LEN,
};
