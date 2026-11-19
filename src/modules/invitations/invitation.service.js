import crypto from 'node:crypto';
import { HttpError } from '../../middlewares/error.middleware.js';
import { sha256Hex } from '../../services/crypto.service.js';
import { logEvent } from '../../services/audit.service.js';

const TOKEN_RE = /^[A-Za-z0-9_-]{20,100}$/;
const ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'; // sin caracteres ambiguos

export const MAX_ATTEMPTS = 5;
export const LONG_LOCK_SECONDS = 15 * 60;
export const TICKET_TTL_SECONDS = 60;

const BASE_SQL = `
  SELECT m.id, m.vault_id, m.recipient_email, m.recipient_label, m.password_hash, m.max_downloads,
         m.download_count, m.failed_attempts, m.locked_until, m.status, m.expires_at, m.last_access_at,
         (m.expires_at <= now()) AS member_expired,
         CASE WHEN m.locked_until > now()
              THEN CEIL(EXTRACT(EPOCH FROM (m.locked_until - now())))::int ELSE 0 END AS lock_seconds,
         v.name AS vault_name, v.status AS vault_status, v.owner_id, v.expires_at AS vault_expires_at,
         (v.expires_at <= now()) AS vault_expired,
         u.email AS owner_email
    FROM workspace_members m
    JOIN vaults v ON v.id = m.vault_id
    JOIN users u ON u.id = v.owner_id
   WHERE m.token_hash = $1`;

/** Busca una invitación por SHA-256(token). Devuelve null si el formato es inválido o no existe. */
export async function loadInvitation(db, token, { lock = false } = {}) {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) return null;
  const { rows } = await db.query(BASE_SQL + (lock ? ' FOR UPDATE OF m' : ''), [sha256Hex(token)]);
  return rows[0] ?? null;
}

export function isAvailable(row) {
  return (
    row.status !== 'REVOKED' &&
    row.status !== 'EXPIRED' &&
    !row.member_expired &&
    row.vault_status === 'ACTIVE' &&
    !row.vault_expired
  );
}

/** 404 si no existe; 410 si fue revocada/expiró o la bóveda no está activa (sin detalles internos). */
export function requireAvailable(row) {
  if (!row) throw new HttpError(404, 'Invitación no encontrada');
  if (!isAvailable(row)) throw new HttpError(410, 'Invitación no disponible');
  return row;
}

export const emailMatches = (user, row) => user.email.toLowerCase() === row.recipient_email.toLowerCase();

/** Registra ACCESS_DENIED (con owner de la bóveda) y devuelve el 403 a lanzar. */
export async function denyAccess(req, { ownerId, vaultId, memberId = null }, action) {
  await logEvent({
    ownerId,
    vaultId,
    memberId,
    event: 'ACCESS_DENIED',
    ip: req.ip,
    userAgent: req.get('user-agent'),
    detail: { action },
  });
  return new HttpError(403, 'Acceso denegado');
}

/** Contraseña aleatoria segura para el Canal 2 (14 caracteres, ~81 bits). */
export function generateChannel2Password(length = 14) {
  let out = '';
  for (let i = 0; i < length; i++) out += ALPHABET[crypto.randomInt(ALPHABET.length)];
  return out;
}
