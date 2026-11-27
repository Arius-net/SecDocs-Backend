import pg from 'pg';
import { config } from '../config/env.js';

// BIGINT (size_bytes, total_storage_bytes) -> number (los tamaños caben en Number).
pg.types.setTypeParser(20, (v) => Number.parseInt(v, 10));

export const pool = new pg.Pool({
  connectionString: config.db.url,
  ssl: config.db.ssl
    ? { rejectUnauthorized: process.env.DATABASE_SSL_REJECT_UNAUTHORIZED !== 'false' }
    : false,
  max: 10,
  idleTimeoutMillis: 30_000,
});

pool.on('error', (err) => {
  console.error('[db] error en cliente inactivo:', err.message);
});

/** Consulta parametrizada. Nunca concatenar valores en `text`. */
export function query(text, params = []) {
  return pool.query(text, params);
}

/** Ejecuta `fn(client)` dentro de una transacción. */
export async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const result = await fn(client);
    await client.query('COMMIT');
    return result;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}
