import { config } from '../config/env.js';
import { query } from '../db/pool.js';
import { verifyToken, clearSessionCookie } from '../services/session.service.js';
import { asyncHandler } from './async.js';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function unauthorized(res) {
  clearSessionCookie(res);
  return res.status(401).json({ error: 'No autenticado' });
}

/**
 * Autenticación por cookie HttpOnly (única fuente del JWT; nunca header/query).
 * Verifica firma HS256 + expiración, consulta revoked_tokens por jti y adjunta
 * req.user = { id, email, role, jti, exp }.
 */
export const requireAuth = asyncHandler(async (req, res, next) => {
  const token = req.cookies?.[config.cookieName];
  if (!token || typeof token !== 'string') return unauthorized(res);

  const payload = verifyToken(token);
  if (!payload || !UUID_RE.test(String(payload.sub)) || typeof payload.jti !== 'string' || !payload.jti || payload.jti.length > 128) {
    return unauthorized(res);
  }

  const { rows } = await query(
    `SELECT u.id, u.email, u.role,
            EXISTS (SELECT 1 FROM revoked_tokens r WHERE r.jti = $2) AS revoked
       FROM users u WHERE u.id = $1`,
    [payload.sub, payload.jti],
  );
  const row = rows[0];
  if (!row || row.revoked) return unauthorized(res);

  req.user = { id: row.id, email: row.email, role: row.role, jti: payload.jti, exp: payload.exp };
  return next();
});

/** Restringe a un rol (usar después de requireAuth). */
export const requireRole = (role) => (req, res, next) =>
  req.user?.role === role ? next() : res.status(403).json({ error: 'Acceso denegado' });
