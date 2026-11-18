import { Router } from 'express';
import crypto from 'node:crypto';
import multer from 'multer';
import { config } from '../../config/env.js';
import { withTransaction, query } from '../../db/pool.js';
import { HttpError } from '../../middlewares/error.middleware.js';
import { asyncHandler } from '../../middlewares/async.js';
import { unwrapKek, encryptFile } from '../../services/crypto.service.js';
import { uploadEncryptedObject, deleteEncryptedObject } from '../../services/storage.service.js';
import { detectAllowedMime, sanitizeFilename } from '../../services/file-validation.service.js';
import { logEvent, metricsFileAdded, metricsFileRemoved } from '../../services/audit.service.js';
import { getOwnedVault, assertVaultWritable, assertUuid, deleteStorageObjects } from './vault.service.js';

const ctx = (req) => ({ ip: req.ip, userAgent: req.get('user-agent') });

const uploader = multer({
  storage: multer.memoryStorage(), // el archivo vive solo en RAM; nunca toca el disco en claro
  limits: { fileSize: config.maxFileBytes, files: 1, fields: 5, parts: 7 },
}).single('file');

const parseUpload = (req, res) =>
  new Promise((resolve, reject) => uploader(req, res, (err) => (err ? reject(err) : resolve())));

export const filesRouter = Router({ mergeParams: true });

filesRouter.post(
  '/',
  asyncHandler(async (req, res) => {
    const { vaultId } = req.params;
    // 1) Antes de leer el cuerpo: propiedad (404), estado y expiración (409).
    const pre = await getOwnedVault({ query }, vaultId, req.user.id);
    assertVaultWritable(pre);

    // 2) Parseo multipart en memoria con límite estricto (413 si se excede).
    await parseUpload(req, res);
    if (!req.file) throw new HttpError(400, "Falta el archivo (campo multipart 'file')");

    // 3) Tipo real por magic bytes (se ignora el Content-Type y la extensión del cliente).
    const filename = sanitizeFilename(req.file.originalname);
    const mime = await detectAllowedMime(req.file.buffer, filename);

    // 4) Envelope encryption: MEK -> KEK (bóveda) -> DEK (archivo), AES-256-GCM en RAM.
    const kek = unwrapKek(pre.wrapped_kek);
    let enc;
    try {
      enc = encryptFile(req.file.buffer, kek);
    } finally {
      kek.fill(0);
    }

    // 5) Subida del .enc y registro transaccional; si la BD falla se elimina el huérfano.
    const storageKey = `${crypto.randomUUID()}.enc`;
    await uploadEncryptedObject(storageKey, enc.encrypted);
    try {
      const file = await withTransaction(async (client) => {
        const v = await getOwnedVault(client, vaultId, req.user.id, { lock: true });
        assertVaultWritable(v); // revalida por si cambió durante la subida
        const { rows } = await client.query(
          `INSERT INTO vault_files
             (vault_id, owner_id, original_filename, mime_type, size_bytes, storage_key, wrapped_dek, iv, auth_tag)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           RETURNING id, original_filename, mime_type, size_bytes, status, created_at`,
          [v.id, req.user.id, filename, mime, req.file.size, storageKey, enc.wrappedDek, enc.iv, enc.authTag],
        );
        await metricsFileAdded(req.user.id, req.file.size, client);
        await logEvent(
          { ownerId: req.user.id, vaultId: v.id, fileId: rows[0].id, event: 'FILE_UPLOADED', ...ctx(req), detail: { size_bytes: req.file.size, mime_type: mime } },
          client,
        );
        return rows[0];
      });
      res.status(201).json({ file });
    } catch (err) {
      await deleteEncryptedObject(storageKey).catch(() => {});
      throw err;
    }
  }),
);

filesRouter.delete(
  '/:fileId',
  asyncHandler(async (req, res) => {
    const { vaultId, fileId } = req.params;
    assertUuid(fileId, 'Archivo');
    const key = await withTransaction(async (client) => {
      // Propiedad verificada vía JOIN con la bóveda del dueño (anti-IDOR).
      const found = await client.query(
        `SELECT f.id, f.storage_key, f.size_bytes
           FROM vault_files f JOIN vaults v ON v.id = f.vault_id
          WHERE f.id = $1 AND f.vault_id = $2 AND v.owner_id = $3 AND f.status = 'ACTIVE'
          FOR UPDATE OF f`,
        [fileId, vaultId, req.user.id],
      );
      if (!found.rows[0]) throw new HttpError(404, 'Archivo no encontrado');
      const f = found.rows[0];
      await client.query(
        `UPDATE vault_files
            SET status = 'PURGED', wrapped_dek = NULL, iv = NULL, auth_tag = NULL, purged_at = now()
          WHERE id = $1`,
        [f.id],
      );
      await metricsFileRemoved(req.user.id, f.size_bytes, client);
      await logEvent({ ownerId: req.user.id, vaultId, fileId: f.id, event: 'FILE_PURGED', ...ctx(req) }, client);
      return f.storage_key;
    });
    await deleteStorageObjects([key]); // después del commit
    res.json({ ok: true });
  }),
);
