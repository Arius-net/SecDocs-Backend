import cron from 'node-cron';
import { config } from '../config/env.js';
import { purgeOldAuditLogs } from './audit-retention.job.js';
import { expireVaults } from './vault-expiry.job.js';
import { cleanupExpiredTokens } from './token-cleanup.job.js';

export { purgeOldAuditLogs, expireVaults, cleanupExpiredTokens };

export const JOBS = {
  purgeOldAuditLogs: { schedule: '15 3 * * *', run: purgeOldAuditLogs }, // diario 03:15 UTC
  expireVaults: { schedule: '*/5 * * * *', run: expireVaults }, // cada 5 minutos
  cleanupExpiredTokens: { schedule: '0 * * * *', run: cleanupExpiredTokens }, // cada hora
};

const running = new Set();

/** Ejecuta una tarea evitando solapamientos; nunca lanza (registra solo conteos, sin datos sensibles). */
function guarded(name, fn) {
  return async () => {
    if (running.has(name)) return;
    running.add(name);
    try {
      console.log(`[jobs] ${name}:`, JSON.stringify(await fn()));
    } catch (err) {
      console.error(`[jobs] ${name} falló: ${err.message}`);
    } finally {
      running.delete(name);
    }
  };
}

/**
 * Programa los cron jobs. Solo se invoca desde server.js y NUNCA en NODE_ENV=test.
 * Devuelve las tareas programadas (para detenerlas en el cierre ordenado).
 */
export function startJobs() {
  if (config.nodeEnv === 'test') return [];
  const tasks = Object.entries(JOBS).map(([name, { schedule, run }]) =>
    cron.schedule(schedule, guarded(name, run), { timezone: 'UTC' }),
  );
  // Puesta al día tras un arranque/reinicio: vence lo que expiró mientras el servicio estaba caído.
  setImmediate(() => {
    guarded('expireVaults', expireVaults)();
    guarded('cleanupExpiredTokens', cleanupExpiredTokens)();
  });
  return tasks;
}

export function stopJobs(tasks) {
  for (const t of tasks) t.stop();
}
