import { Router } from 'express';
import { query, withTransaction } from '../../db/pool.js';
import { HttpError } from '../../middlewares/error.middleware.js';
import { asyncHandler } from '../../middlewares/async.js';
import { requireAuth } from '../../middlewares/auth.middleware.js';
import { sha256Hex, unwrapKek, decryptFile } from '../../services/crypto.service.js';
import { getEncryptedObject } from '../../services/storage.service.js';
import { logEvent, incrementDailyStats } from '../../services/audit.service.js';
import { assertUuid } from '../vaults/vault.service.js';
import { denyAccess } from '../invitations/invitation.service.js';

export const sharedRouter = Router();
sharedRouter.use(requireAuth);

const ctx = (req) => ({ ip: req.ip, userAgent: req.get('user-agent') });

sharedRouter.get(
  '/',
  asyncHandler(async (req, res) => {
    const { rows } = await query(
      `SELECT v.id AS vault_id, v.name, v.status AS vault_status, v.expires_at AS vault_expires_at,
              u.email AS owner_email,
              m.status AS member_status, m.expires_at AS member_expires_at,
              m.max_downloads, m.download_count,
              GREATEST(m.max_downloads - m.download_count, 0) AS downloads_remaining,
              (SELECT count(*)::int FROM vault_files f WHERE f.vault_id = v.id AND f.status = 'ACTIVE') AS files_count
         FROM workspace_members m
         JOIN vaults v ON v.id = m.vault_id
         JOIN users u ON u.id = v.owner_id
        WHERE lower(m.recipient_email) = lower($1)
          AND m.status IN ('ACCEPTED', 'TEMP_LOCKED')
          AND m.expires_at > now()
          AND v.status <> 'PURGED' AND v.expires_at > now()
        ORDER BY m.created_at DESC`,
      [req.user.email],
    );
    res.json({ shared: rows });
  }),
);

/** Content-Disposition seguro: fallback ASCII + filename* UTF-8 (RFC 6266). */
function contentDisposition(filename) {
  const ascii = filename.replace(/[^\x20-\x7E]/g, '_').replace(/["\\]/g, '_');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(filename).replace(/['()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)}`;
}

sharedRouter.get(
  '/:vaultId/files/:fileId/download',
  asyncHandler(async (req, res) => {
    const { vaultId, fileId } = req.params;
    assertUuid(vaultId, 'Archivo');
    assertUuid(fileId, 'Archivo');

    const vault = (
      await query(
        `SELECT id, owner_id, status, wrapped_kek, (expires_at <= now()) AS expired FROM vaults WHERE id = $1`,
        [vaultId],
      )
    ).rows[0];
    if (!vault) throw new HttpError(404, 'Archivo no encontrado');

    // El usuario debe ser el destinatario (correo) de un miembro vigente de esa bóveda.
    const member = (
      await query(
        `SELECT id FROM workspace_members
          WHERE vault_id = $1 AND lower(recipient_email) = lower($2) AND status NOT IN ('REVOKED', 'EXPIRED')
          ORDER BY created_at DESC LIMIT 1`,
        [vaultId, req.user.email],
      )
    ).rows[0];
    if (!member) throw await denyAccess(req, { ownerId: vault.owner_id, vaultId }, 'download');

    if (vault.status !== 'ACTIVE' || vault.expired || !vault.wrapped_kek) throw new HttpError(410, 'La bóveda no está disponible');

    const file = (
      await query(
        `SELECT id, original_filename, mime_type, size_bytes, storage_key, wrapped_dek, iv, auth_tag
           FROM vault_files
          WHERE id = $1 AND vault_id = $2 AND status = 'ACTIVE' AND wrapped_dek IS NOT NULL`,
        [fileId, vaultId],
      )
    ).rows[0];
    if (!file) throw new HttpError(404, 'Archivo no encontrado');

    const ticket = req.get('x-download-ticket') ?? req.query.ticket;
    const denyTicket = async () => {
      await logEvent({
        ownerId: vault.owner_id, vaultId, fileId, memberId: member.id, event: 'DOWNLOAD_DENIED', ...ctx(req),
        detail: { reason: 'ticket_invalid_expired_used_or_limit' },
      });
      return new HttpError(401, 'Ticket inválido, expirado o ya utilizado');
    };
    if (typeof ticket !== 'string' || ticket.length < 20 || ticket.length > 200) throw await denyTicket();

    // Consumo ATÓMICO del ticket + auditoría en la misma transacción.
    const consumed = await withTransaction(async (client) => {
      const upd = await client.query(
        `UPDATE workspace_members
            SET ticket_hash = NULL, ticket_expires_at = NULL,
                download_count = download_count + 1, last_access_at = now()
          WHERE id = $1 AND vault_id = $2 AND status = 'ACCEPTED' AND expires_at > now()
            AND ticket_hash = $3 AND ticket_expires_at > now() AND download_count < max_downloads
        RETURNING id`,
        [member.id, vaultId, sha256Hex(ticket)],
      );
      if (upd.rowCount === 0) return false;
      await logEvent(
        {
          ownerId: vault.owner_id, vaultId, fileId, memberId: member.id, event: 'FILE_DOWNLOADED', ...ctx(req),
          detail: { size_bytes: file.size_bytes, mime_type: file.mime_type },
        },
        client,
      );
      await incrementDailyStats(vault.owner_id, { downloads: 1 }, client);
      return true;
    });
    if (!consumed) throw await denyTicket();

    let plain;
    try {
      const encrypted = await getEncryptedObject(file.storage_key);
      const kek = unwrapKek(vault.wrapped_kek); // MEK -> KEK
      try {
        plain = decryptFile({ encrypted, wrappedDek: file.wrapped_dek, iv: file.iv, authTag: file.auth_tag }, kek); // KEK -> DEK -> AES-256-GCM
      } finally {
        kek.fill(0);
      }
    } catch (err) {
      // Fallo del servidor tras consumir el ticket: se devuelve la descarga al contador.
      await query('UPDATE workspace_members SET download_count = GREATEST(download_count - 1, 0) WHERE id = $1', [member.id]);
      await logEvent({ ownerId: vault.owner_id, vaultId, fileId, memberId: member.id, event: 'DOWNLOAD_FAILED', ...ctx(req), detail: { reason: 'server_error' } });
      throw err;
    }

    res.set({
      'Content-Type': file.mime_type,
      'Content-Length': String(plain.length),
      'Content-Disposition': contentDisposition(file.original_filename),
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      'X-Robots-Tag': 'noindex, nofollow, noarchive',
      'Referrer-Policy': 'no-referrer',
    });
    res.status(200).end(plain);
  }),
);
