'use strict';

const bcrypt = require('bcryptjs');
const { load } = require('./config');
const { createDb, migrate } = require('./db');
const { createStorage } = require('./storage');
const { createVault } = require('./services/vault');
const { createApp } = require('./app');

async function main() {
  const config = load();
  const db = createDb(config.databaseUrl);

  // Espera a que PostgreSQL esté listo (útil al arrancar con Docker Compose).
  for (let i = 1; ; i++) {
    try {
      await db.query('SELECT 1');
      break;
    } catch (e) {
      if (i >= 30) throw e;
      console.log(`[db] esperando a PostgreSQL (${i}/30)…`);
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
  await migrate(db);

  const hasher = {
    hash: (pw) => bcrypt.hash(pw, config.bcryptCost),
    compare: (pw, hash) => bcrypt.compare(pw, hash),
  };
  const vault = createVault({ db, storage: createStorage(config), hasher, config });
  const app = createApp({ vault, config });

  const server = app.listen(config.port, () => console.log(`[api] SecDocs escuchando en :${config.port}`));

  // Purga periódica: vence enlaces, destruye archivos vencidos (crypto-shredding).
  const tick = async () => {
    try {
      const r = await vault.runPurgeCycle();
      if (r.expiredLinks || r.purgedFiles) console.log('[purge]', r);
    } catch (e) {
      console.error('[purge] error', e.message);
    }
  };
  const timer = setInterval(tick, config.purgeIntervalMs);
  tick();

  const shutdown = () => {
    clearInterval(timer);
    server.close(() => db.end().then(() => process.exit(0)));
  };
  process.on('SIGTERM', shutdown);
  process.on('SIGINT', shutdown);
}

main().catch((e) => {
  console.error('[api] no se pudo iniciar:', e.message);
  process.exit(1);
});
