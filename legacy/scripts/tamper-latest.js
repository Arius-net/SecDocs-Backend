'use strict';
// Prueba 1b · Tampering: invierte UN bit del archivo cifrado activo más reciente.
// docker compose exec api node scripts/tamper-latest.js
const fs = require('node:fs');
const path = require('node:path');
const { Client } = require('pg');

(async () => {
  const db = new Client({ connectionString: process.env.DATABASE_URL });
  await db.connect();
  const { rows } = await db.query(
    `SELECT original_filename, storage_key FROM vault_files WHERE status = 'ACTIVE' ORDER BY created_at DESC LIMIT 1`);
  await db.end();
  if (!rows[0]) return console.log('No hay archivos activos.');
  const p = path.join(process.env.STORAGE_DIR || '/data/vault', rows[0].storage_key);
  const buf = fs.readFileSync(p);
  const pos = Math.floor(buf.length / 2);
  buf[pos] ^= 0x01;
  fs.writeFileSync(p, buf);
  console.log(`Bit invertido en el byte ${pos} de ${rows[0].storage_key} («${rows[0].original_filename}»).`);
  console.log('Ahora intenta descargarlo con su enlace: la API debe responder 422 INTEGRITY_FAIL y registrarlo en Auditoría.');
})().catch((e) => { console.error(e); process.exit(1); });
