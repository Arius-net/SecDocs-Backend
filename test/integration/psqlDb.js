'use strict';

// Adaptador de pruebas: ejecuta las consultas reales del servicio contra PostgreSQL
// usando el cliente `psql` (sin el driver `pg`). Sólo para pruebas locales.

const { execFile } = require('node:child_process');

function literal(v) {
  if (v === null || v === undefined) return 'NULL';
  if (typeof v === 'number') return String(v);
  if (typeof v === 'boolean') return v ? 'TRUE' : 'FALSE';
  if (v instanceof Date) return `'${v.toISOString()}'`;
  if (Array.isArray(v)) return `'{${v.map((x) => `"${String(x)}"`).join(',')}}'`;
  return `'${String(v).replace(/'/g, "''")}'`;
}

function createPsqlDb({ host, port, user, database }) {
  function run(sql) {
    return new Promise((resolve, reject) => {
      execFile('psql', ['-h', host, '-p', String(port), '-U', user, '-d', database, '-At', '-v', 'ON_ERROR_STOP=1', '-c', sql],
        { maxBuffer: 64 * 1024 * 1024 }, (err, stdout, stderr) => {
          if (err) {
            const e = new Error(stderr.trim() || err.message);
            if (/duplicate key/.test(stderr)) e.code = '23505';
            return reject(e);
          }
          resolve(stdout);
        });
    });
  }

  async function query(text, params = []) {
    const sql = text.replace(/\$(\d+)/g, (_m, n) => literal(params[Number(n) - 1]));
    const returnsRows = /^\s*SELECT\b/i.test(sql) || /\bRETURNING\b/i.test(sql);
    if (!returnsRows) {
      await run(sql);
      return { rows: [], rowCount: 0 };
    }
    const out = await run(`WITH t AS (${sql}) SELECT coalesce(json_agg(t), '[]'::json) FROM t`);
    const rows = JSON.parse(out.trim() || '[]');
    return { rows, rowCount: rows.length };
  }

  return {
    query,
    tx: async (fn) => fn({ query }), // sin transacción real: suficiente para estas pruebas
    end: async () => {},
    raw: run,
  };
}

module.exports = { createPsqlDb };
