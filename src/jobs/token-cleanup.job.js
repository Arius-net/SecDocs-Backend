import { query } from '../db/pool.js';

/** Elimina de revoked_tokens y user_sessions los registros ya expirados (el JWT ya no sería válido de todos modos). */
export async function cleanupExpiredTokens() {
  const revoked = await query('DELETE FROM revoked_tokens WHERE expires_at <= now()');
  const sessions = await query('DELETE FROM user_sessions WHERE expires_at <= now()');
  return { revokedTokens: revoked.rowCount, sessions: sessions.rowCount };
}
