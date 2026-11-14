'use strict';

/**
 * Almacenamiento de binarios cifrados con interfaz intercambiable.
 *
 *   put(key, chunksIterable) -> Promise<void>
 *   createReadStream(key)    -> Readable
 *   remove(key)              -> Promise<void>
 *
 * Hoy: disco local (volumen Docker aislado).
 * Para Railway (disco efímero) se agrega un driver "supabase" con la misma
 * interfaz usando Supabase Storage; el resto del código no cambia.
 */

const fs = require('node:fs');
const fsp = require('node:fs/promises');
const path = require('node:path');
const { pipeline } = require('node:stream/promises');
const { Readable } = require('node:stream');

const KEY_RE = /^[0-9a-f-]{36}\.enc$/;

function localDisk(baseDir) {
  fs.mkdirSync(baseDir, { recursive: true, mode: 0o700 });

  function resolve(key) {
    if (!KEY_RE.test(key)) throw new Error('Clave de almacenamiento inválida');
    return path.join(baseDir, key);
  }

  return {
    async put(key, chunks) {
      const final = resolve(key);
      const tmp = `${final}.tmp`;
      await pipeline(Readable.from(chunks), fs.createWriteStream(tmp, { mode: 0o600, flags: 'wx' }));
      await fsp.rename(tmp, final);
    },
    createReadStream(key) {
      return fs.createReadStream(resolve(key));
    },
    async remove(key) {
      const p = resolve(key);
      try {
        // Sobrescritura de mejor esfuerzo antes de borrar. En SSD/volúmenes no es
        // garantía; la garantía real es que la DEK ya fue destruida (crypto-shredding).
        const { size } = await fsp.stat(p);
        const fh = await fsp.open(p, 'r+');
        try {
          await fh.write(Buffer.alloc(Math.min(size, 1024 * 1024)), 0);
        } finally {
          await fh.close();
        }
        await fsp.unlink(p);
      } catch (e) {
        if (e.code !== 'ENOENT') throw e;
      }
    },
    async exists(key) {
      try {
        await fsp.access(resolve(key));
        return true;
      } catch {
        return false;
      }
    },
  };
}

function createStorage(config) {
  const driver = process.env.STORAGE_DRIVER || 'local';
  if (driver === 'local') return localDisk(config.storageDir);
  throw new Error(`STORAGE_DRIVER desconocido: ${driver}`);
}

module.exports = { createStorage, localDisk };
