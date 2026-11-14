'use strict';
// Prueba 1a · Inspección del almacenamiento en reposo.
// docker compose exec api node scripts/inspect-vault.js
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('pg');

(async () => {
  const dir = process.env.STORAGE_DIR || '/data/vault';
  const db = new Client({ connectionString: process.env.DATABASE_URL });
  await db.connect();
  const { rows } = await db.query(
    `SELECT original_filename, storage_key, status, left(wrapped_dek, 24) AS dek
       FROM vault_files ORDER BY created_at DESC LIMIT 10`);
  console.log(`\nContenido de ${dir}:`);
  for (const f of fs.readdirSync(dir)) {
    const buf = fs.readFileSync(path.join(dir, f));
    const markers = ['%PDF', 'PK\u0003\u0004', '\u0089PNG', 'BEGIN', 'PASS', 'password'].filter((m) => buf.includes(Buffer.from(m, 'latin1')));
    console.log(`  ${f}  ${buf.length} bytes  primeros bytes: ${buf.subarray(0, 24).toString('hex')}`);
    console.log(`     firmas de formato o texto legible encontradas: ${markers.length ? markers.join(', ') : 'ninguna ✔'}`);
  }
  console.log('\nÚltimos registros en vault_files (la DEK sólo existe envuelta; NULL = destruida):');
  console.table(rows);
  await db.end();
})().catch((e) => { console.error(e); process.exit(1); });
