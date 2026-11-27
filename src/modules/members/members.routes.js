import { Router } from 'express';
import crypto from 'node:crypto';
import bcrypt from 'bcrypt';
import { config } from '../../config/env.js';
import { query, withTransaction } from '../../db/pool.js';
import { HttpError } from '../../middlewares/error.middleware.js';
import { asyncHandler } from '../../middlewares/async.js';
import { validateBody, createMemberSchema } from '../../middlewares/validate.middleware.js';
import { sha256Hex } from '../../services/crypto.service.js';
import { logEvent } from '../../services/audit.service.js';
import { normalizeEmail } from '../../services/validators.js';
import { getOwnedVault, assertVaultWritable, assertUuid } from './../vaults/vault.service.js';

const ctx = (req) => ({ ip: req.ip, userAgent: req.get('user-agent') });
const CONTROL_RE = /[\x00-\x1F\x7F]/;

const publicMember = (m) => ({
  id: m.id,
  recipient_email: m.recipient_email,
  recipient_label: m.recipient_label,
  status: m.status,
  max_downloads: m.max_downloads,
  expires_at: m.expires_at,
  created_at: m.created_at,
});

export const membersRouter = Router({ mergeParams: true });

membersRouter.post(
  '/',
  validateBody(createMemberSchema),
  asyncHandler(async (req, res) => {
    const { vaultId } = req.params;
    const body = req.body ?? {};

    const email = normalizeEmail(body.recipient_email, 'recipient_email inválido');
    if (email === req.user.email.toLowerCase()) throw new HttpError(400, 'No puedes invitarte a ti mismo');

    let label = null;
    if (body.recipient_label !== undefined && body.recipient_label !== null) {
      if (typeof body.recipient_label !== 'string') throw new HttpError(400, 'recipient_label inválido');
      label = body.recipient_label.trim() || null;
      if (label && (label.length > 120 || CONTROL_RE.test(label))) throw new HttpError(400, 'recipient_label inválido (máx. 120 caracteres)');
    }

    let maxDownloads = 3;
    if (body.max_downloads !== undefined) {
      if (!Number.isInteger(body.max_downloads) || body.max_downloads < 1 || body.max_downloads > 10) {
        throw new HttpError(400, 'max_downloads debe ser un entero entre 1 y 10');
      }
      maxDownloads = body.max_downloads;
    }

    // Antes de gastar CPU en bcrypt: propiedad (404) y estado de la bóveda (409).
    const pre = await getOwnedVault({ query }, vaultId, req.user.id);
    assertVaultWritable(pre);

    let expiresAt = new Date(pre.expires_at);
    if (body.expires_at !== undefined) {
      const t = typeof body.expires_at === 'string' ? Date.parse(body.expires_at) : NaN;
      if (Number.isNaN(t)) throw new HttpError(400, 'expires_at no es una fecha válida');
      if (t <= Date.now()) throw new HttpError(400, 'expires_at debe ser una fecha futura');
      if (t > new Date(pre.expires_at).getTime()) throw new HttpError(400, 'expires_at no puede exceder la expiración de la bóveda');
      expiresAt = new Date(t);
    }

    // Token CSPRNG (192 bits). Solo se guarda su SHA-256.
    const token = crypto.randomBytes(24).toString('base64url');
    // Hash inicial aleatorio e inutilizable: la clave real se genera en verify-identity.
    const placeholderHash = await bcrypt.hash(crypto.randomBytes(32).toString('hex'), 12);

    const member = await withTransaction(async (client) => {
      const vault = await getOwnedVault(client, vaultId, req.user.id, { lock: true });
      assertVaultWritable(vault);
      const dup = await client.query(
        `SELECT 1 FROM workspace_members
          WHERE vault_id = $1 AND lower(recipient_email) = $2 AND status NOT IN ('REVOKED', 'EXPIRED') AND expires_at > now()`,
        [vault.id, email],
      );
      if (dup.rowCount > 0) throw new HttpError(409, 'Ya existe una invitación vigente para ese correo');
      const { rows } = await client.query(
        `INSERT INTO workspace_members
           (vault_id, recipient_email, recipient_label, token_hash, password_hash, max_downloads, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING id, recipient_email, recipient_label, status, max_downloads, expires_at, created_at`,
        [vault.id, email, label, sha256Hex(token), placeholderHash, maxDownloads, expiresAt],
      );
      await logEvent(
        { ownerId: req.user.id, vaultId: vault.id, memberId: rows[0].id, event: 'MEMBER_INVITED', ...ctx(req), detail: { max_downloads: maxDownloads } },
        client,
      );
      return rows[0];
    });

    // El enlace se devuelve UNA sola vez; no se puede recuperar después.
    res.status(201).json({
      member: publicMember(member),
      invitationPath: `/invitacion/${token}`,
      invitationUrl: `${config.frontendUrl}/invitacion/${token}`,
    });
  }),
);

membersRouter.delete(
  '/:memberId',
  asyncHandler(async (req, res) => {
    const { vaultId, memberId } = req.params;
    assertUuid(memberId, 'Miembro');
    await withTransaction(async (client) => {
      const vault = await getOwnedVault(client, vaultId, req.user.id); // anti-IDOR
      const { rowCount } = await client.query(
        `UPDATE workspace_members
            SET status = 'REVOKED', ticket_hash = NULL, ticket_expires_at = NULL
          WHERE id = $1 AND vault_id = $2 AND status <> 'REVOKED'`,
        [memberId, vault.id],
      );
      if (rowCount === 0) throw new HttpError(404, 'Miembro no encontrado');
      await logEvent({ ownerId: req.user.id, vaultId: vault.id, memberId, event: 'MEMBER_REVOKED', ...ctx(req) }, client);
    });
    res.json({ ok: true });
  }),
);
