import { HttpError } from '../../middlewares/error.middleware.js';
import { logEvent, adjustUserMetrics } from '../../services/audit.service.js';
import { deleteEncryptedObject } from '../../services/storage.service.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** Borra objetos .enc tras el commit (best-effort: la DEK/KEK ya fueron destruidas). */
export async function deleteStorageObjects(keys) {
  const results = await Promise.allSettled(keys.map((k) => deleteEncryptedObject(k)));
  const failed = results.filter((r) => r.status === 'rejected').length;
  if (failed) console.error(`[storage] no se pudieron borrar ${failed}/${keys.length} objetos (ya irrecuperables por crypto-shredding)`);
}

/** Lanza 404 si el parámetro no es un UUID (evita errores de pg y no filtra información). */
export function assertUuid(value, what = 'Recurso') {
  if (typeof value !== 'string' || !UUID_RE.test(value)) throw new HttpError(404, `${what} no encontrado`);
  return value;
}

/**
 * Obtiene una bóveda del dueño (anti-IDOR: filtra por owner_id). 404 si no existe o es ajena.
 * Devuelve columnas internas (wrapped_kek) SOLO para uso del servidor; nunca serializar tal cual.
 */
export async function getOwnedVault(db, vaultId, ownerId, { lock = false } = {}) {
  assertUuid(vaultId, 'Bóveda');
  const { rows } = await db.query(
    `SELECT id, owner_id, name, status, wrapped_kek, expires_at, purged_at, created_at,
            (expires_at <= now()) AS expired
       FROM vaults WHERE id = $1 AND owner_id = $2 ${lock ? 'FOR UPDATE' : ''}`,
    [vaultId, ownerId],
  );
  if (!rows[0]) throw new HttpError(404, 'Bóveda no encontrada');
  return rows[0];
}

/** Bóveda apta para recibir archivos: ACTIVE, no expirada y con KEK vigente. */
export function assertVaultWritable(vault) {
  if (vault.status === 'PURGED' || !vault.wrapped_kek) throw new HttpError(409, 'La bóveda fue purgada');
  if (vault.status === 'LOCKED') throw new HttpError(409, 'La bóveda está bloqueada');
  if (vault.status === 'EXPIRED' || vault.expired) throw new HttpError(409, 'La bóveda expiró');
  if (vault.status !== 'ACTIVE') throw new HttpError(409, 'La bóveda no está activa');
}

/**
 * Crypto-shredding total de una bóveda dentro de una transacción (reutilizable por el cron de expiración).
 * Devuelve las storage_key a borrar de R2 DESPUÉS del commit.
 */
export async function purgeVaultTx(
  client,
  vault,
  { event = 'VAULT_PURGED', reason = 'owner_request', ip = null, userAgent = null, finalStatus = 'PURGED', memberStatus = 'REVOKED' } = {},
) {
  const files = await client.query(
    `UPDATE vault_files
        SET status = 'PURGED', wrapped_dek = NULL, iv = NULL, auth_tag = NULL, purged_at = now()
      WHERE vault_id = $1 AND status = 'ACTIVE'
      RETURNING storage_key, size_bytes`,
    [vault.id],
  );
  await client.query(
    `UPDATE vaults SET status = $2, wrapped_kek = NULL, purged_at = now() WHERE id = $1`,
    [vault.id, finalStatus],
  );
  const members = await client.query(
    `UPDATE workspace_members
        SET status = $2, ticket_hash = NULL, ticket_expires_at = NULL
      WHERE vault_id = $1 AND status NOT IN ('REVOKED', 'EXPIRED')`,
    [vault.id, memberStatus],
  );
  const bytes = files.rows.reduce((acc, f) => acc + Number(f.size_bytes), 0);
  await adjustUserMetrics(vault.owner_id, { storageBytes: -bytes, files: -files.rowCount, vaults: -1 }, client);
  await logEvent(
    {
      ownerId: vault.owner_id,
      vaultId: vault.id,
      event,
      ip,
      userAgent,
      detail: { reason, files_purged: files.rowCount, members_revoked: members.rowCount },
    },
    client,
  );
  return files.rows.map((f) => f.storage_key);
}
