'use strict';

const fs = require('node:fs');
const path = require('node:path');

function createDb(databaseUrl) {
  const { Pool } = require('pg');
  const ssl = /sslmode=require/.test(databaseUrl) ? { rejectUnauthorized: false } : undefined;
  const pool = new Pool({ connectionString: databaseUrl, max: 10, ssl });

  return {
    query: (text, params) => pool.query(text, params),
    /** Ejecuta fn(client) dentro de una transacción. */
    async tx(fn) {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const result = await fn({ query: (t, p) => client.query(t, p) });
        await client.query('COMMIT');
        return result;
      } catch (e) {
        await client.query('ROLLBACK').catch(() => {});
        throw e;
      } finally {
        client.release();
      }
    },
    end: () => pool.end(),
  };
}

async function migrate(db) {
  // El esquema vive en el repositorio SecDocs-DB (schema/schema.sql).
  const schemaPath = process.env.SCHEMA_PATH || path.join(__dirname, 'schema.sql');
  if (!fs.existsSync(schemaPath)) {
    throw new Error('No se encontró el esquema SQL. Define SCHEMA_PATH con la ruta a schema/schema.sql del repositorio SecDocs-DB.');
  }
  const sql = fs.readFileSync(schemaPath, 'utf8');
  await db.query(sql);
}

module.exports = { createDb, migrate };
