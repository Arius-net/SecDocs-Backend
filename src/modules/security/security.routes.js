import { Router } from 'express';
import { query, withTransaction } from '../../db/pool.js';
import { HttpError } from '../../middlewares/error.middleware.js';
import { asyncHandler } from '../../middlewares/async.js';
import { requireAuth } from '../../middlewares/auth.middleware.js';
import { clearSessionCookie } from '../../services/session.service.js';
import { logEvent } from '../../services/audit.service.js';

const ctx = (req) => ({ ip: req.ip, userAgent: req.get('user-agent') });

export const securityRouter = Router();
securityRouter.use(requireAuth);

securityRouter.get(
  '/sessions',
  asyncHandler(async (req, res) => {
    const { rows } = await query(
      `SELECT jti, ip, user_agent, created_at, expires_at
         FROM user_sessions
        WHERE user_id = $1 AND expires_at > now()
        ORDER BY created_at DESC`,
      [req.user.id],
    );
    res.json({
      sessions: rows.map((s) => ({
        jti: s.jti,
        ip: s.ip,
        user_agent: s.user_agent,
        created_at: s.created_at,
        expires_at: s.expires_at,
        current: s.jti === req.user.jti,
      })),
    });
  }),
);

securityRouter.delete(
  '/sessions/:jti',
  asyncHandler(async (req, res) => {
    const { jti } = req.params;
    const { id: userId } = req.user;
    if (!jti || jti.length > 128) throw new HttpError(404, 'Sesión no encontrada');

    await withTransaction(async (client) => {
      // El filtro por user_id evita IDOR: sesiones ajenas son indistinguibles de inexistentes.
      const found = await client.query(
        'SELECT jti, expires_at FROM user_sessions WHERE jti = $1 AND user_id = $2 FOR UPDATE',
        [jti, userId],
      );
      if (found.rowCount === 0) throw new HttpError(404, 'Sesión no encontrada');
      await client.query(
        'INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, $2) ON CONFLICT (jti) DO NOTHING',
        [jti, found.rows[0].expires_at],
      );
      await client.query('DELETE FROM user_sessions WHERE jti = $1 AND user_id = $2', [jti, userId]);
      await logEvent({ ownerId: userId, event: 'SESSION_REVOKED', ...ctx(req), detail: { scope: 'single' } }, client);
    });

    const current = jti === req.user.jti;
    if (current) clearSessionCookie(res);
    res.json({ ok: true, current });
  }),
);

securityRouter.post(
  '/kill-switch',
  asyncHandler(async (req, res) => {
    const { id: userId, jti, exp } = req.user;
    const revoked = await withTransaction(async (client) => {
      const all = await client.query(
        `INSERT INTO revoked_tokens (jti, expires_at)
         SELECT jti, expires_at FROM user_sessions WHERE user_id = $1
         ON CONFLICT (jti) DO NOTHING`,
        [userId],
      );
      // Por seguridad, también el jti actual aunque no figure en user_sessions.
      await client.query(
        'INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, to_timestamp($2)) ON CONFLICT (jti) DO NOTHING',
        [jti, exp],
      );
      const del = await client.query('DELETE FROM user_sessions WHERE user_id = $1', [userId]);
      await logEvent(
        { ownerId: userId, event: 'SESSION_REVOKED', ...ctx(req), detail: { scope: 'all', count: del.rowCount } },
        client,
      );
      return Math.max(all.rowCount, del.rowCount);
    });
    clearSessionCookie(res);
    res.json({ ok: true, revoked });
  }),
);
