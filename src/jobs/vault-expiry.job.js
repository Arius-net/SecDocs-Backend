import { query, withTransaction } from '../db/pool.js';
import { purgeVaultTx, deleteStorageObjects } from '../modules/vaults/vault.service.js';

/**
 * Expira bóvedas vencidas con crypto-shredding: una transacción por bóveda
 * (EXPIRED, wrapped_kek/wrapped_dek = NULL, miembros EXPIRED, métricas, VAULT_EXPIRED);
 * los .enc se borran del storage DESPUÉS del commit.
 * Además marca como EXPIRED a los miembros vencidos de bóvedas aún vigentes.
 */
export async function expireVaults({ batchSize = 100 } = {}) {
  const due = await query(
    `SELECT id FROM vaults WHERE status IN ('ACTIVE', 'LOCKED') AND expires_at <= now() ORDER BY expires_at LIMIT $1`,
    [batchSize],
  );

  let vaults = 0;
  let files = 0;
  for (const { id } of due.rows) {
    try {
      const keys = await withTransaction(async (client) => {
        const { rows } = await client.query(
          `SELECT id, owner_id, status FROM vaults
            WHERE id = $1 AND status IN ('ACTIVE', 'LOCKED') AND expires_at <= now() FOR UPDATE`,
          [id],
        );
        if (!rows[0]) return null; // otro proceso ya la procesó
        return purgeVaultTx(client, rows[0], {
          event: 'VAULT_EXPIRED',
          reason: 'expired',
          finalStatus: 'EXPIRED',
          memberStatus: 'EXPIRED',
        });
      });
      if (keys === null) continue;
      vaults += 1;
      files += keys.length;
      await deleteStorageObjects(keys);
    } catch (err) {
      console.error(`[jobs] expireVaults: falló la bóveda ${id}: ${err.message}`);
    }
  }

  const members = await query(
    `UPDATE workspace_members
        SET status = 'EXPIRED', ticket_hash = NULL, ticket_expires_at = NULL
      WHERE expires_at <= now() AND status NOT IN ('REVOKED', 'EXPIRED')`,
  );
  return { vaults, files, membersExpired: members.rowCount };
}
