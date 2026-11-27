import { Router } from 'express';
import { config } from '../../config/env.js';
import { query, withTransaction } from '../../db/pool.js';
import { HttpError } from '../../middlewares/error.middleware.js';
import { asyncHandler } from '../../middlewares/async.js';
import { requireAuth } from '../../middlewares/auth.middleware.js';
import { validateBody, createVaultSchema } from '../../middlewares/validate.middleware.js';
import { generateKek, wrapKek } from '../../services/crypto.service.js';
import { logEvent, metricsVaultAdded } from '../../services/audit.service.js';
import { getOwnedVault, assertUuid, purgeVaultTx, deleteStorageObjects } from './vault.service.js';
import { filesRouter } from './files.routes.js';
import { membersRouter } from '../members/members.routes.js';

const ctx = (req) => ({ ip: req.ip, userAgent: req.get('user-agent') });
const CONTROL_RE = /[\x00-\x1F\x7F]/;

// Metadatos seguros de bóveda (nunca wrapped_kek).
const publicVault = (v) => ({
  id: v.id,
  name: v.name,
  status: v.status,
  expires_at: v.expires_at,
  expired: v.expired ?? new Date(v.expires_at) <= new Date(),
  purged_at: v.purged_at,
  created_at: v.created_at,
});

function parseName(value) {
  if (typeof value !== 'string') throw new HttpError(400, 'El nombre es obligatorio');
  const name = value.trim();
  if (name.length < 1 || name.length > 150) throw new HttpError(400, 'El nombre debe tener entre 1 y 150 caracteres');
  if (CONTROL_RE.test(name)) throw new HttpError(400, 'El nombre contiene caracteres no permitidos');
  return name;
}

function parseExpiresAt(value) {
  if (typeof value !== 'string' || !value.trim()) throw new HttpError(400, 'expires_at es obligatorio (fecha ISO 8601)');
  const t = Date.parse(value);
  if (Number.isNaN(t)) throw new HttpError(400, 'expires_at no es una fecha válida');
  const now = Date.now();
  if (t <= now) throw new HttpError(400, 'expires_at debe ser una fecha futura');
  if (t > now + config.vaultMaxDays * 86_400_000) {
    throw new HttpError(400, `expires_at no puede exceder ${config.vaultMaxDays} días desde hoy`);
  }
  return new Date(t);
}

export const vaultsRouter = Router();
vaultsRouter.use(requireAuth);

vaultsRouter.get(
  '/',
  asyncHandler(async (req, res) => {
    const includePurged = req.query.include_purged === 'true';
    const metrics = (
      await query(
        'SELECT total_storage_bytes, total_files_active, total_vaults_active FROM user_metrics WHERE owner_id = $1',
        [req.user.id],
      )
    ).rows[0] ?? { total_storage_bytes: 0, total_files_active: 0, total_vaults_active: 0 };

    const { rows } = await query(
      `SELECT v.id, v.name, v.status, v.expires_at, v.purged_at, v.created_at, (v.expires_at <= now()) AS expired,
              (SELECT count(*)::int FROM vault_files f WHERE f.vault_id = v.id AND f.status = 'ACTIVE') AS files_count,
              (SELECT count(*)::int FROM workspace_members m WHERE m.vault_id = v.id AND m.status NOT IN ('REVOKED', 'EXPIRED')) AS members_count
         FROM vaults v
        WHERE v.owner_id = $1 AND ($2::boolean OR v.status <> 'PURGED')
        ORDER BY v.created_at DESC`,
      [req.user.id, includePurged],
    );
    res.json({
      metrics,
      vaults: rows.map((v) => ({ ...publicVault(v), files_count: v.files_count, members_count: v.members_count })),
    });
  }),
);

vaultsRouter.post(
  '/',
  validateBody(createVaultSchema),
  asyncHandler(async (req, res) => {
    const name = parseName(req.body?.name);
    const expiresAt = parseExpiresAt(req.body?.expires_at);

    const vault = await withTransaction(async (client) => {
      const kek = generateKek();
      let wrapped;
      try {
        wrapped = wrapKek(kek);
      } finally {
        kek.fill(0);
      }
      const { rows } = await client.query(
        `INSERT INTO vaults (owner_id, name, wrapped_kek, expires_at) VALUES ($1, $2, $3, $4)
         RETURNING id, name, status, expires_at, purged_at, created_at, (expires_at <= now()) AS expired`,
        [req.user.id, name, wrapped, expiresAt],
      );
      await metricsVaultAdded(req.user.id, client);
      await logEvent({ ownerId: req.user.id, vaultId: rows[0].id, event: 'VAULT_CREATED', ...ctx(req) }, client);
      return rows[0];
    });
    res.status(201).json({ vault: { ...publicVault(vault), files_count: 0, members_count: 0 } });
  }),
);

vaultsRouter.get(
  '/:vaultId',
  asyncHandler(async (req, res) => {
    const vault = await getOwnedVault({ query }, req.params.vaultId, req.user.id);
    const files = await query(
      `SELECT id, original_filename, mime_type, size_bytes, status, created_at
         FROM vault_files WHERE vault_id = $1 AND status = 'ACTIVE' ORDER BY created_at DESC`,
      [vault.id],
    );
    const members = await query(
      `SELECT id, recipient_email, recipient_label, status, failed_attempts, locked_until,
              download_count, max_downloads, expires_at, last_access_at
         FROM workspace_members WHERE vault_id = $1 ORDER BY created_at DESC`,
      [vault.id],
    );
    res.json({
      vault: {
        ...publicVault(vault),
        keys: { algorithm: 'AES-256-GCM', kekStatus: vault.wrapped_kek ? 'ACTIVE' : 'PURGED' },
      },
      files: files.rows,
      members: members.rows,
    });
  }),
);

vaultsRouter.patch(
  '/:vaultId/status',
  asyncHandler(async (req, res) => {
    const target = req.body?.status;
    if (target !== 'ACTIVE' && target !== 'LOCKED') {
      throw new HttpError(400, "status debe ser 'ACTIVE' o 'LOCKED'");
    }
    const vault = await withTransaction(async (client) => {
      const v = await getOwnedVault(client, req.params.vaultId, req.user.id, { lock: true });
      if (v.status === 'PURGED' || v.status === 'EXPIRED') throw new HttpError(409, `La bóveda está ${v.status} y no puede cambiar de estado`);
      if (target === 'ACTIVE' && v.expired) throw new HttpError(409, 'La bóveda expiró y no puede reactivarse');
      if (v.status !== target) {
        await client.query('UPDATE vaults SET status = $1 WHERE id = $2', [target, v.id]);
        await logEvent(
          { ownerId: req.user.id, vaultId: v.id, event: target === 'LOCKED' ? 'VAULT_LOCKED' : 'VAULT_UNLOCKED', ...ctx(req) },
          client,
        );
      }
      return { ...v, status: target };
    });
    res.json({ vault: publicVault(vault) });
  }),
);

vaultsRouter.delete(
  '/:vaultId',
  asyncHandler(async (req, res) => {
    const { keys } = await withTransaction(async (client) => {
      const v = await getOwnedVault(client, req.params.vaultId, req.user.id, { lock: true });
      if (v.status === 'PURGED') throw new HttpError(404, 'Bóveda no encontrada');
      return { keys: await purgeVaultTx(client, v, { ...ctx(req), reason: 'owner_request' }) };
    });
    await deleteStorageObjects(keys); // después del commit
    res.json({ ok: true, purged_files: keys.length });
  }),
);

vaultsRouter.use('/:vaultId/members', (req, res, next) => {
  assertUuid(req.params.vaultId, 'Bóveda');
  next();
}, membersRouter);

vaultsRouter.use('/:vaultId/files', (req, res, next) => {
  assertUuid(req.params.vaultId, 'Bóveda');
  next();
}, filesRouter);
