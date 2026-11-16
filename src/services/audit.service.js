import { query } from '../db/pool.js';

// Claves de `detail` que jamás deben persistirse (contraseñas, tokens, tickets, llaves, hashes).
// Se compara contra el nombre normalizado a snake_case (apiKey -> api_key).
const SENSITIVE_KEY_RE = /pass|pwd|token|ticket|secret|authorization|cookie|credential|(^|_)key($|_)|(^|_)(kek|dek|iv|otp|jwt|salt)($|_)|hash|auth_?tag/;
const MAX_DEPTH = 4;
const normalizeKey = (k) => k.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/[-\s]+/g, '_').toLowerCase();

/** Copia `detail` eliminando campos sensibles (recursivo, también dentro de arrays). */
export function sanitizeDetail(value, depth = 0) {
  if (value === null || value === undefined) return value;
  if (depth > MAX_DEPTH) return '[truncado]';
  if (Array.isArray(value)) return value.slice(0, 50).map((v) => sanitizeDetail(v, depth + 1));
  if (typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SENSITIVE_KEY_RE.test(normalizeKey(k))) continue;
      out[k] = sanitizeDetail(v, depth + 1);
    }
    return out;
  }
  if (typeof value === 'string') return value.length > 500 ? value.slice(0, 500) : value;
  return value;
}

const clip = (v, n) => (v == null ? null : String(v).slice(0, n));

/**
 * Registra un evento en access_logs (sin secretos).
 * `db` puede ser el pool o un client de transacción.
 */
export async function logEvent(
  { ownerId = null, vaultId = null, fileId = null, memberId = null, event, ip = null, userAgent = null, detail = {} },
  db = { query },
) {
  if (!event || typeof event !== 'string') throw new Error('logEvent requiere `event`');
  await db.query(
    `INSERT INTO access_logs (owner_id, vault_id, file_id, member_id, event, ip, user_agent, detail)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
    [ownerId, vaultId, fileId, memberId, clip(event, 50), clip(ip, 64), clip(userAgent, 300), JSON.stringify(sanitizeDetail(detail) ?? {})],
  );
}

/**
 * Suma contadores del día en daily_stats_rollup de forma atómica
 * (INSERT ... ON CONFLICT (owner_id, stat_date) DO UPDATE).
 */
export async function incrementDailyStats(
  ownerId,
  { downloads = 0, failedAttempts = 0, uniqueVisitors = 0 } = {},
  db = { query },
) {
  await db.query(
    `INSERT INTO daily_stats_rollup (owner_id, stat_date, total_downloads, total_failed_attempts, unique_visitors)
     VALUES ($1, CURRENT_DATE, $2, $3, $4)
     ON CONFLICT (owner_id, stat_date) DO UPDATE SET
       total_downloads       = daily_stats_rollup.total_downloads + EXCLUDED.total_downloads,
       total_failed_attempts = daily_stats_rollup.total_failed_attempts + EXCLUDED.total_failed_attempts,
       unique_visitors       = daily_stats_rollup.unique_visitors + EXCLUDED.unique_visitors`,
    [ownerId, downloads, failedAttempts, uniqueVisitors],
  );
}

/**
 * Ajusta user_metrics con deltas (positivos o negativos); los valores nunca bajan de 0.
 * Crea la fila si no existe.
 */
export async function adjustUserMetrics(
  ownerId,
  { storageBytes = 0, files = 0, vaults = 0 } = {},
  db = { query },
) {
  await db.query(
    `INSERT INTO user_metrics (owner_id, total_storage_bytes, total_files_active, total_vaults_active, updated_at)
     VALUES ($1, GREATEST($2::bigint, 0), GREATEST($3::int, 0), GREATEST($4::int, 0), now())
     ON CONFLICT (owner_id) DO UPDATE SET
       total_storage_bytes = GREATEST(user_metrics.total_storage_bytes + $2::bigint, 0),
       total_files_active  = GREATEST(user_metrics.total_files_active + $3::int, 0),
       total_vaults_active = GREATEST(user_metrics.total_vaults_active + $4::int, 0),
       updated_at          = now()`,
    [ownerId, storageBytes, files, vaults],
  );
}

// Helpers semánticos
export const metricsFileAdded = (ownerId, sizeBytes, db) =>
  adjustUserMetrics(ownerId, { storageBytes: sizeBytes, files: 1 }, db);
export const metricsFileRemoved = (ownerId, sizeBytes, db) =>
  adjustUserMetrics(ownerId, { storageBytes: -sizeBytes, files: -1 }, db);
export const metricsVaultAdded = (ownerId, db) => adjustUserMetrics(ownerId, { vaults: 1 }, db);
export const metricsVaultRemoved = (ownerId, db) => adjustUserMetrics(ownerId, { vaults: -1 }, db);
