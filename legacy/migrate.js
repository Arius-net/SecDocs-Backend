'use strict';

const { createDb, migrate } = require('./index');

(async () => {
  const db = createDb(process.env.DATABASE_URL);
  await migrate(db);
  await db.end();
  console.log('Migración aplicada');
})().catch((e) => {
  console.error(e);
  process.exit(1);
});
