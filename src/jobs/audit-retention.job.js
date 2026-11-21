import { query } from '../db/pool.js';

/**
 * Purga de retención LFPDPPP: elimina access_logs con más de 6 meses.
 * NO toca daily_stats_rollup (agregados anónimos, conservación indefinida).
 */
export async function purgeOldAuditLogs() {
  const { rowCount } = await query(`DELETE FROM access_logs WHERE created_at < now() - INTERVAL '6 months'`);
  return { deleted: rowCount };
}
