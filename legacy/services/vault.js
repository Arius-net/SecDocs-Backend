'use strict';

/**
 * Lógica de negocio de SecDocs, independiente de Express.
 * Recibe sus dependencias (db, storage, hasher, config) para poder probarse aislada.
 */

const crypto = require('node:crypto');
const { encryptChunks, createDecryptStream, IntegrityError } = require('../crypto/fileCipher');
const keys = require('../crypto/keys');
const fileType = require('../crypto/fileType');
const { HttpError, notAvailable, bad } = require('../errors');

const MAX_FAILED_ATTEMPTS = 5;
const TICKET_TTL_SECONDS = 60;
const EMAIL_RE = /^[^\s@]{1,64}@[^\s@]{1,190}\.[^\s@]{2,}$/;

function int(v, name, min, max) {
  const n = Number(v);
  if (!Number.isInteger(n) || n < min || n > max) throw bad(`${name} debe ser un entero entre ${min} y ${max}`);
  return n;
}

function checkPassword(pw, min, label) {
  if (typeof pw !== 'string' || pw.length < min) throw bad(`${label} debe tener al menos ${min} caracteres`);
  // bcrypt sólo usa los primeros 72 bytes; rechazamos más para no dar falsa sensación de seguridad.
  if (Buffer.byteLength(pw) > 72) throw bad(`${label} no puede exceder 72 bytes`);
}

function createVault({ db, storage, hasher, config, log = console }) {
  // Hash de relleno: si el correo no existe, igual se ejecuta un bcrypt.compare
  // para que el tiempo de respuesta no revele qué correos están registrados.
  let dummyHash = null;
  const getDummyHash = async () => (dummyHash ??= await hasher.hash(crypto.randomBytes(16).toString('hex')));

  async function audit({ ownerId = null, fileId = null, linkId = null, event, ctx = {}, detail = {} }) {
    try {
      await db.query(
        `INSERT INTO access_logs (owner_id, file_id, link_id, event, ip, user_agent, detail)
         VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [ownerId, fileId, linkId, event, ctx.ip ?? null, (ctx.userAgent ?? '').slice(0, 300) || null, JSON.stringify(detail)],
      );
    } catch (e) {
      log.error('[audit] no se pudo registrar el evento', event, e.message);
    }
  }

  // ───────────────────────── Usuarios ─────────────────────────

  async function register({ email, password }, ctx) {
    email = String(email ?? '').trim().toLowerCase();
    if (!EMAIL_RE.test(email)) throw bad('Correo inválido');
    checkPassword(password, 12, 'La contraseña');
    const hash = await hasher.hash(password);
    try {
      const { rows } = await db.query(
        `INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id, email, role, created_at`,
        [email, hash],
      );
      await audit({ ownerId: rows[0].id, event: 'USER_REGISTERED', ctx });
      return rows[0];
    } catch (e) {
      if (e.code === '23505') throw new HttpError(409, 'EMAIL_TAKEN', 'Ese correo ya está registrado');
      throw e;
    }
  }

  async function login({ email, password }, ctx) {
    email = String(email ?? '').trim().toLowerCase();
    const { rows } = await db.query(`SELECT id, email, role, password_hash FROM users WHERE lower(email) = $1`, [email]);
    const user = rows[0];
    const ok = await hasher.compare(String(password ?? ''), user ? user.password_hash : await getDummyHash());
    if (!user || !ok) {
      if (user) await audit({ ownerId: user.id, event: 'LOGIN_FAIL', ctx });
      throw new HttpError(401, 'INVALID_CREDENTIALS', 'Correo o contraseña incorrectos');
    }
    await audit({ ownerId: user.id, event: 'LOGIN_OK', ctx });
    return { id: user.id, email: user.email, role: user.role };
  }

  async function getUser(id) {
    const { rows } = await db.query(`SELECT id, email, role, created_at FROM users WHERE id = $1`, [id]);
    return rows[0] ?? null;
  }

  // ───────────────────────── Archivos ─────────────────────────

  async function uploadFile(ownerId, upload, { expiresInHours, autoPurge = true }, ctx) {
    if (!upload || !Buffer.isBuffer(upload.buffer)) throw bad('No se recibió ningún archivo');
    if (upload.buffer.length === 0) throw bad('El archivo está vacío');
    const hours = int(expiresInHours ?? 24, 'expiresInHours', 1, 168);
    const name = fileType.sanitizeFilename(upload.originalname);
    const { mime } = fileType.detect(name, upload.buffer);

    const fileId = crypto.randomUUID();
    const storageKey = `${crypto.randomUUID()}.enc`; // no se deriva del id ni del nombre
    const dek = keys.generateDek();
    const chunkSize = 64 * 1024;
    try {
      const wrapped = keys.wrapDek(dek, fileId, config.masterKeys);
      await storage.put(storageKey, encryptChunks(dek, upload.buffer, chunkSize));
      try {
        const { rows } = await db.query(
          `INSERT INTO vault_files
             (id, owner_id, original_filename, mime_type, size_bytes, storage_key, wrapped_dek, chunk_size, auto_purge, expires_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now() + make_interval(hours => $10))
           RETURNING id, original_filename, mime_type, size_bytes, auto_purge, status, expires_at, created_at`,
          [fileId, ownerId, name, mime, upload.buffer.length, storageKey, wrapped, chunkSize, autoPurge !== false && autoPurge !== 'false', hours],
        );
        await audit({ ownerId, fileId, event: 'FILE_UPLOADED', ctx, detail: { size: upload.buffer.length, mime } });
        return rows[0];
      } catch (e) {
        await storage.remove(storageKey).catch(() => {});
        throw e;
      }
    } finally {
      // Mejor esfuerzo: no dejar la DEK ni el texto claro en memoria más de lo necesario.
      dek.fill(0);
      upload.buffer.fill(0);
    }
  }

  async function listFiles(ownerId) {
    const { rows } = await db.query(
      `SELECT f.id, f.original_filename, f.mime_type, f.size_bytes, f.status, f.auto_purge,
              f.expires_at, f.purged_at, f.created_at,
              count(l.id)::int AS links_total,
              count(l.id) FILTER (WHERE l.status = 'ACTIVE' AND l.expires_at > now())::int AS links_active
         FROM vault_files f
         LEFT JOIN share_links l ON l.file_id = f.id
        WHERE f.owner_id = $1
        GROUP BY f.id
        ORDER BY f.created_at DESC`,
      [ownerId],
    );
    return rows;
  }

  async function ownFile(ownerId, fileId) {
    if (!/^[0-9a-f-]{36}$/i.test(String(fileId))) throw new HttpError(404, 'NOT_FOUND', 'Archivo no encontrado');
    const { rows } = await db.query(`SELECT * FROM vault_files WHERE id = $1 AND owner_id = $2`, [fileId, ownerId]);
    if (!rows[0]) throw new HttpError(404, 'NOT_FOUND', 'Archivo no encontrado');
    return rows[0];
  }

  async function deleteFile(ownerId, fileId, ctx) {
    await ownFile(ownerId, fileId);
    await purgeFile(fileId, 'OWNER_DELETED', ctx);
  }

  // ───────────────────────── Enlaces ─────────────────────────

  async function createLink(ownerId, fileId, body, ctx) {
    const file = await ownFile(ownerId, fileId);
    if (file.status !== 'ACTIVE' || new Date(file.expires_at) <= new Date()) {
      throw new HttpError(409, 'FILE_UNAVAILABLE', 'El archivo ya fue purgado o expiró');
    }
    const label = String(body.recipientLabel ?? '').trim();
    if (label.length < 1 || label.length > 120) throw bad('Indica a quién va dirigido el enlace (máx. 120 caracteres)');
    checkPassword(body.password, 10, 'La clave de acceso');
    const minutes = int(body.expiresInMinutes ?? 60, 'expiresInMinutes', 1, 7 * 24 * 60);
    const maxDownloads = int(body.maxDownloads ?? 1, 'maxDownloads', 1, 3);

    const token = keys.generateToken();
    const passwordHash = await hasher.hash(body.password);
    const { rows } = await db.query(
      `INSERT INTO share_links (file_id, recipient_label, token_hash, password_hash, max_downloads, expires_at)
       VALUES ($1, $2, $3, $4, $5, LEAST(now() + make_interval(mins => $6), $7::timestamptz))
       RETURNING id, recipient_label, max_downloads, download_count, status, expires_at, created_at`,
      [fileId, label, keys.hashToken(token), passwordHash, maxDownloads, minutes, file.expires_at],
    );
    const link = rows[0];
    await audit({ ownerId, fileId, linkId: link.id, event: 'LINK_CREATED', ctx, detail: { recipient: label, maxDownloads } });
    // El token sólo se devuelve esta única vez; en la BD queda su hash.
    return { ...link, url: `${config.publicBaseUrl}/s/${token}` };
  }

  async function listLinks(ownerId, fileId) {
    await ownFile(ownerId, fileId);
    const { rows } = await db.query(
      `SELECT id, recipient_label, max_downloads, download_count, failed_attempts, status,
              CASE WHEN status = 'ACTIVE' AND expires_at <= now() THEN 'EXPIRED' ELSE status END AS effective_status,
              expires_at, last_access_at, created_at
         FROM share_links WHERE file_id = $1 ORDER BY created_at DESC`,
      [fileId],
    );
    return rows;
  }

  async function revokeLink(ownerId, linkId, ctx) {
    if (!/^[0-9a-f-]{36}$/i.test(String(linkId))) throw new HttpError(404, 'NOT_FOUND', 'Enlace no encontrado');
    const { rows } = await db.query(
      `UPDATE share_links l SET status = 'REVOKED', ticket_hash = NULL, ticket_expires_at = NULL
         FROM vault_files f
        WHERE l.id = $1 AND l.file_id = f.id AND f.owner_id = $2 AND l.status = 'ACTIVE'
        RETURNING l.id, l.file_id`,
      [linkId, ownerId],
    );
    if (!rows[0]) throw new HttpError(404, 'NOT_FOUND', 'Enlace no encontrado o ya inactivo');
    await audit({ ownerId, fileId: rows[0].file_id, linkId, event: 'LINK_REVOKED', ctx });
    await maybeAutoPurge(rows[0].file_id, ctx);
  }

  // ───────────────────────── Acceso público ─────────────────────────

  async function findActiveLinkByToken(token) {
    if (!keys.isWellFormedToken(token)) throw notAvailable();
    const { rows } = await db.query(
      `SELECT l.*, f.owner_id, f.status AS file_status, f.expires_at AS file_expires_at
         FROM share_links l JOIN vault_files f ON f.id = l.file_id
        WHERE l.token_hash = $1`,
      [keys.hashToken(token)],
    );
    const link = rows[0];
    if (!link) throw notAvailable();
    const now = new Date();
    if (link.status === 'ACTIVE' && new Date(link.expires_at) <= now) {
      await expireLinks([link.id]);
      throw notAvailable();
    }
    if (
      link.status !== 'ACTIVE' ||
      link.file_status !== 'ACTIVE' ||
      new Date(link.file_expires_at) <= now ||
      link.download_count >= link.max_downloads
    ) {
      throw notAvailable();
    }
    return link;
  }

  /** Información mínima antes de autenticar: no revela nombre ni tamaño del archivo. */
  async function publicLinkInfo(token) {
    const link = await findActiveLinkByToken(token);
    return { expiresAt: link.expires_at, requiresPassword: true };
  }

  async function verifyLinkPassword(token, password, ctx) {
    const link = await findActiveLinkByToken(token);
    const base = { ownerId: link.owner_id, fileId: link.file_id, linkId: link.id, ctx };

    if (link.locked_until && new Date(link.locked_until) > new Date()) {
      const retryAfter = Math.ceil((new Date(link.locked_until) - Date.now()) / 1000);
      throw new HttpError(429, 'SLOW_DOWN', `Espera ${retryAfter} s antes de volver a intentar`, { retryAfter });
    }

    const ok = await hasher.compare(String(password ?? ''), link.password_hash);
    if (!ok) {
      // Retardo exponencial: 1, 2, 4, 8 s… y bloqueo definitivo al llegar a 5 fallos.
      const { rows } = await db.query(
        `UPDATE share_links
            SET failed_attempts = failed_attempts + 1,
                locked_until    = now() + make_interval(secs => power(2, failed_attempts)),
                status          = CASE WHEN failed_attempts + 1 >= $2 THEN 'LOCKED' ELSE status END,
                ticket_hash     = CASE WHEN failed_attempts + 1 >= $2 THEN NULL ELSE ticket_hash END
          WHERE id = $1 AND status = 'ACTIVE'
          RETURNING failed_attempts, status`,
        [link.id, MAX_FAILED_ATTEMPTS],
      );
      const r = rows[0] ?? { failed_attempts: MAX_FAILED_ATTEMPTS, status: 'LOCKED' };
      await audit({ ...base, event: 'VERIFY_FAIL', detail: { attempt: r.failed_attempts } });
      if (r.status === 'LOCKED') {
        await audit({ ...base, event: 'LINK_LOCKED', detail: { reason: 'MAX_FAILED_ATTEMPTS' } });
        await maybeAutoPurge(link.file_id, ctx);
        throw Object.assign(notAvailable(), { countsAsFailure: true });
      }
      throw Object.assign(
        new HttpError(401, 'WRONG_PASSWORD', 'Clave de acceso incorrecta', {
          remainingAttempts: MAX_FAILED_ATTEMPTS - r.failed_attempts,
        }),
        { countsAsFailure: true },
      );
    }

    const ticket = crypto.randomBytes(32).toString('base64url');
    const { rowCount } = await db.query(
      `UPDATE share_links
          SET ticket_hash = $2, ticket_expires_at = now() + make_interval(secs => $3), locked_until = NULL
        WHERE id = $1 AND status = 'ACTIVE'
        RETURNING id`,
      [link.id, keys.hashToken(ticket), TICKET_TTL_SECONDS],
    );
    if (!rowCount) throw notAvailable();
    await audit({ ...base, event: 'VERIFY_OK' });
    return { ticket, expiresIn: TICKET_TTL_SECONDS };
  }

  /**
   * Canjea el ticket de un solo uso. La actualización es ATÓMICA: si llegan dos
   * peticiones a la vez, sólo una pasa la condición download_count < max_downloads.
   */
  async function redeemTicket(ticket, ctx) {
    if (!keys.isWellFormedToken(ticket)) throw notAvailable();
    const { rows } = await db.query(
      `UPDATE share_links l
          SET download_count    = l.download_count + 1,
              ticket_hash       = NULL,
              ticket_expires_at = NULL,
              last_access_at    = now(),
              status            = CASE WHEN l.download_count + 1 >= l.max_downloads THEN 'CONSUMED' ELSE l.status END
         FROM vault_files f
        WHERE l.ticket_hash = $1
          AND l.ticket_expires_at > now()
          AND l.status = 'ACTIVE'
          AND l.expires_at > now()
          AND l.download_count < l.max_downloads
          AND f.id = l.file_id
          AND f.status = 'ACTIVE'
          AND f.expires_at > now()
        RETURNING l.id AS link_id, l.status AS link_status, l.download_count, l.max_downloads,
                  f.id AS file_id, f.owner_id, f.original_filename, f.size_bytes, f.storage_key, f.wrapped_dek`,
      [keys.hashToken(ticket)],
    );
    const r = rows[0];
    if (!r) throw notAvailable();
    await audit({
      ownerId: r.owner_id, fileId: r.file_id, linkId: r.link_id, ctx,
      event: 'DOWNLOAD_STARTED', detail: { download: r.download_count, of: r.max_downloads },
    });
    return r;
  }

  /** Recorre el archivo completo verificando todos los tags, sin emitir nada. */
  async function verifyIntegrity(storageKey, dek) {
    const { pipeline } = require('node:stream/promises');
    const { Writable } = require('node:stream');
    await pipeline(storage.createReadStream(storageKey), createDecryptStream(dek), new Writable({ write: (_c, _e, cb) => cb() }));
  }

  /**
   * Prepara la descarga: verifica la integridad del archivo COMPLETO antes de enviar
   * un solo byte, y devuelve un stream que vuelve a verificar cada bloque al enviarlo.
   */
  async function openDownload(redeemed, ctx) {
    const dek = keys.unwrapDek(redeemed.wrapped_dek, redeemed.file_id, config.masterKeys);
    try {
      await verifyIntegrity(redeemed.storage_key, dek);
    } catch (e) {
      dek.fill(0);
      if (e instanceof IntegrityError || e.code === 'ENOENT') {
        await audit({
          ownerId: redeemed.owner_id, fileId: redeemed.file_id, linkId: redeemed.link_id, ctx,
          event: 'INTEGRITY_FAIL', detail: { error: e.message },
        });
        throw new HttpError(422, 'INTEGRITY_FAIL', 'El archivo cifrado fue alterado o está dañado; descarga cancelada');
      }
      throw e;
    }
    const decrypt = createDecryptStream(dek);
    const source = storage.createReadStream(redeemed.storage_key);
    const done = () => dek.fill(0);
    decrypt.once('close', done);
    return { source, decrypt };
  }

  async function finishDownload(redeemed, ok, ctx) {
    await audit({
      ownerId: redeemed.owner_id, fileId: redeemed.file_id, linkId: redeemed.link_id, ctx,
      event: ok ? 'DOWNLOAD_COMPLETED' : 'DOWNLOAD_ABORTED',
    });
    if (redeemed.link_status === 'CONSUMED') await maybeAutoPurge(redeemed.file_id, ctx);
  }

  // ───────────────────────── Purga / crypto-shredding ─────────────────────────

  async function purgeFile(fileId, reason, ctx = {}) {
    const purged = await db.tx(async (t) => {
      const { rows } = await t.query(
        `UPDATE vault_files SET status = 'PURGED', wrapped_dek = NULL, purged_at = now()
          WHERE id = $1 AND status = 'ACTIVE'
          RETURNING owner_id, storage_key`,
        [fileId],
      );
      if (!rows[0]) return null;
      await t.query(
        `UPDATE share_links SET status = 'REVOKED', ticket_hash = NULL, ticket_expires_at = NULL
          WHERE file_id = $1 AND status = 'ACTIVE'`,
        [fileId],
      );
      return rows[0];
    });
    if (!purged) return false;
    // La DEK ya no existe en la BD: aunque el borrado del disco fallara, el .enc es irrecuperable.
    try {
      await storage.remove(purged.storage_key);
    } catch (e) {
      log.error('[purge] no se pudo borrar el binario', purged.storage_key, e.message);
    }
    await audit({ ownerId: purged.owner_id, fileId, event: 'FILE_PURGED', ctx, detail: { reason } });
    return true;
  }

  /** Si el archivo tiene auto_purge y ya no le queda ningún enlace activo, se destruye. */
  async function maybeAutoPurge(fileId, ctx) {
    const { rows } = await db.query(
      `SELECT f.auto_purge, f.status,
              count(l.id)::int AS total,
              count(l.id) FILTER (WHERE l.status = 'ACTIVE' AND l.expires_at > now())::int AS active
         FROM vault_files f LEFT JOIN share_links l ON l.file_id = f.id
        WHERE f.id = $1 GROUP BY f.id`,
      [fileId],
    );
    const r = rows[0];
    if (r && r.auto_purge && r.status === 'ACTIVE' && r.total > 0 && r.active === 0) {
      return purgeFile(fileId, 'ALL_LINKS_FINISHED', ctx);
    }
    return false;
  }

  async function expireLinks(ids) {
    const { rows } = await db.query(
      `UPDATE share_links l SET status = 'EXPIRED', ticket_hash = NULL, ticket_expires_at = NULL
         FROM vault_files f
        WHERE l.file_id = f.id AND l.status = 'ACTIVE' AND l.expires_at <= now()
          AND ($1::uuid[] IS NULL OR l.id = ANY($1::uuid[]))
        RETURNING l.id, l.file_id, f.owner_id`,
      [ids ?? null],
    );
    for (const r of rows) await audit({ ownerId: r.owner_id, fileId: r.file_id, linkId: r.id, event: 'LINK_EXPIRED' });
    for (const fileId of new Set(rows.map((r) => r.file_id))) await maybeAutoPurge(fileId);
    return rows.length;
  }

  /** Ciclo periódico: vence enlaces, purga archivos vencidos y limpia tickets viejos. */
  async function runPurgeCycle() {
    const expiredLinks = await expireLinks(null);
    const { rows } = await db.query(`SELECT id FROM vault_files WHERE status = 'ACTIVE' AND expires_at <= now()`);
    let purged = 0;
    for (const { id } of rows) if (await purgeFile(id, 'FILE_EXPIRED')) purged += 1;
    await db.query(
      `UPDATE share_links SET ticket_hash = NULL, ticket_expires_at = NULL
        WHERE ticket_hash IS NOT NULL AND ticket_expires_at <= now()
        RETURNING id`,
    );
    return { expiredLinks, purgedFiles: purged };
  }

  // ───────────────────────── Auditoría ─────────────────────────

  async function listAudit(ownerId, { fileId, limit = 200 } = {}) {
    const lim = int(limit, 'limit', 1, 500);
    const { rows } = await db.query(
      `SELECT a.id, a.event, a.ip, a.user_agent, a.detail, a.created_at,
              a.file_id, f.original_filename, a.link_id, l.recipient_label
         FROM access_logs a
         LEFT JOIN vault_files f ON f.id = a.file_id
         LEFT JOIN share_links l ON l.id = a.link_id
        WHERE a.owner_id = $1 AND ($2::uuid IS NULL OR a.file_id = $2::uuid)
        ORDER BY a.created_at DESC, a.id DESC
        LIMIT $3`,
      [ownerId, fileId || null, lim],
    );
    return rows;
  }

  return {
    register, login, getUser,
    uploadFile, listFiles, deleteFile,
    createLink, listLinks, revokeLink,
    publicLinkInfo, verifyLinkPassword, redeemTicket, openDownload, finishDownload,
    purgeFile, maybeAutoPurge, runPurgeCycle,
    listAudit,
  };
}

module.exports = { createVault, MAX_FAILED_ATTEMPTS };
