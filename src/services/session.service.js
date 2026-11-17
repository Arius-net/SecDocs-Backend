import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import { config } from '../config/env.js';

export const JWT_ALGORITHM = 'HS256';

const cookieBase = () => ({
  httpOnly: true,
  secure: config.isProd,
  sameSite: 'strict',
  path: '/',
});

/**
 * Crea un JWT con `jti` único y registra la sesión en user_sessions.
 * `db` es el pool o un client de transacción.
 */
export async function createSession(db, user, { ip, userAgent }) {
  const jti = crypto.randomUUID();
  const expiresAt = new Date(Date.now() + config.jwt.expiresHours * 3600 * 1000);
  const token = jwt.sign({ sub: user.id, jti }, config.jwt.secret, {
    algorithm: JWT_ALGORITHM,
    expiresIn: Math.floor((expiresAt.getTime() - Date.now()) / 1000),
  });
  await db.query(
    `INSERT INTO user_sessions (jti, user_id, ip, user_agent, expires_at) VALUES ($1, $2, $3, $4, $5)`,
    [jti, user.id, ip ? String(ip).slice(0, 64) : null, userAgent ? String(userAgent).slice(0, 300) : null, expiresAt],
  );
  return { token, jti, expiresAt };
}

export function setSessionCookie(res, token, expiresAt) {
  res.cookie(config.cookieName, token, { ...cookieBase(), expires: expiresAt });
}

export function clearSessionCookie(res) {
  res.clearCookie(config.cookieName, cookieBase());
}

/** Verifica firma (solo HS256) y expiración. Devuelve el payload o null. */
export function verifyToken(token) {
  try {
    return jwt.verify(token, config.jwt.secret, { algorithms: [JWT_ALGORITHM] });
  } catch {
    return null;
  }
}
