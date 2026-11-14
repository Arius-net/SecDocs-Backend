'use strict';

// Configuración centralizada. Falla al arrancar si falta algún secreto:
// es preferible no levantar el servidor a levantarlo inseguro.

function required(name) {
  const v = process.env[name];
  if (!v) throw new Error(`Falta la variable de entorno obligatoria ${name}`);
  return v;
}

function parseMasterKeys() {
  // MASTER_KEY_V1, MASTER_KEY_V2... permiten rotar la KEK sin perder archivos antiguos.
  const keys = new Map();
  for (const [name, value] of Object.entries(process.env)) {
    const m = /^MASTER_KEY_V(\d+)$/.exec(name);
    if (!m) continue;
    const buf = Buffer.from(value, 'base64');
    if (buf.length !== 32) {
      throw new Error(`${name} debe ser de 32 bytes codificados en base64 (openssl rand -base64 32)`);
    }
    keys.set(Number(m[1]), buf);
  }
  if (keys.size === 0) throw new Error('Define al menos MASTER_KEY_V1 (openssl rand -base64 32)');
  const current = Number(process.env.MASTER_KEY_CURRENT || Math.max(...keys.keys()));
  if (!keys.has(current)) throw new Error(`MASTER_KEY_CURRENT=${current} no tiene llave definida`);
  return { keys, current };
}

function load() {
  const jwtSecret = required('JWT_SECRET');
  if (Buffer.byteLength(jwtSecret) < 32) throw new Error('JWT_SECRET debe tener al menos 32 caracteres');

  return {
    port: Number(process.env.PORT || 4000),
    databaseUrl: required('DATABASE_URL'),
    jwtSecret,
    jwtTtlSeconds: Number(process.env.JWT_TTL_SECONDS || 2 * 60 * 60),
    cookieSecure: process.env.COOKIE_SECURE !== 'false',
    trustProxy: process.env.TRUST_PROXY ?? '1',
    publicBaseUrl: (process.env.PUBLIC_BASE_URL || 'http://localhost:3000').replace(/\/$/, ''),
    storageDir: process.env.STORAGE_DIR || '/data/vault',
    maxUploadBytes: Number(process.env.MAX_UPLOAD_MB || 25) * 1024 * 1024,
    masterKeys: parseMasterKeys(),
    bcryptCost: 12,
    purgeIntervalMs: Number(process.env.PURGE_INTERVAL_MS || 30_000),
  };
}

module.exports = { load };
