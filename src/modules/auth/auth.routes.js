import { Router } from 'express';
import bcrypt from 'bcrypt';
import { query, withTransaction } from '../../db/pool.js';
import { HttpError } from '../../middlewares/error.middleware.js';
import { asyncHandler } from '../../middlewares/async.js';
import { authLimiter } from '../../middlewares/security.middleware.js';
import { requireAuth } from '../../middlewares/auth.middleware.js';
import { validateBody, registerSchema, loginSchema } from '../../middlewares/validate.middleware.js';
import { createSession, setSessionCookie, clearSessionCookie } from '../../services/session.service.js';
import { logEvent, adjustUserMetrics } from '../../services/audit.service.js';
import { normalizeEmail } from '../../services/validators.js';

const BCRYPT_COST = 12;
const MIN_PASSWORD = 8;
const MAX_PASSWORD_BYTES = 72; // bcrypt trunca/ignora más allá de 72 bytes
// Hash dummy para igualar el tiempo de respuesta cuando el usuario no existe.
const DUMMY_HASH = await bcrypt.hash('dummy-password-for-timing', BCRYPT_COST);

function validatePasswordShape(password) {
  if (typeof password !== 'string') throw new HttpError(400, 'Contraseña inválida');
  if (Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) {
    throw new HttpError(400, `La contraseña no puede exceder ${MAX_PASSWORD_BYTES} bytes`);
  }
}

const ctx = (req) => ({ ip: req.ip, userAgent: req.get('user-agent') });
const publicUser = (u) => ({ id: u.id, email: u.email, role: u.role, created_at: u.created_at });

export const authRouter = Router();

authRouter.post(
  '/register',
  authLimiter,
  validateBody(registerSchema),
  asyncHandler(async (req, res) => {
    const email = normalizeEmail(req.body?.email);
    const { password } = req.body ?? {};
    validatePasswordShape(password);
    if (password.length < MIN_PASSWORD) {
      throw new HttpError(400, `La contraseña debe tener al menos ${MIN_PASSWORD} caracteres`);
    }

    const passwordHash = await bcrypt.hash(password, BCRYPT_COST);

    const result = await withTransaction(async (client) => {
      const ins = await client.query(
        `INSERT INTO users (email, password_hash) VALUES ($1, $2)
         ON CONFLICT (lower(email)) DO NOTHING
         RETURNING id, email, role, created_at`,
        [email, passwordHash],
      );
      if (ins.rowCount === 0) return null;
      const user = ins.rows[0];
      await adjustUserMetrics(user.id, {}, client); // inicializa user_metrics en 0
      const session = await createSession(client, user, ctx(req));
      await logEvent({ ownerId: user.id, event: 'USER_REGISTERED', ...ctx(req) }, client);
      return { user, session };
    });

    if (!result) throw new HttpError(409, 'El correo ya está registrado');
    setSessionCookie(res, result.session.token, result.session.expiresAt);
    res.status(201).json({ user: publicUser(result.user) });
  }),
);

authRouter.post(
  '/login',
  authLimiter,
  validateBody(loginSchema, { status: 401, overrideMessage: 'Credenciales inválidas' }),
  asyncHandler(async (req, res) => {
    const invalid = () => new HttpError(401, 'Credenciales inválidas');
    const { email: rawEmail, password } = req.body ?? {};
    if (typeof rawEmail !== 'string' || typeof password !== 'string') throw invalid();
    const email = rawEmail.trim().toLowerCase();
    if (email.length > 255 || Buffer.byteLength(password, 'utf8') > MAX_PASSWORD_BYTES) throw invalid();

    const { rows } = await query(
      'SELECT id, email, role, password_hash, created_at FROM users WHERE lower(email) = $1',
      [email],
    );
    const user = rows[0];
    // Siempre se ejecuta un bcrypt.compare (contra hash dummy si no existe el usuario).
    const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);
    if (!user || !ok) {
      if (user) await logEvent({ ownerId: user.id, event: 'LOGIN_FAILED', ...ctx(req) });
      throw invalid();
    }

    const session = await withTransaction(async (client) => {
      const s = await createSession(client, user, ctx(req));
      await logEvent({ ownerId: user.id, event: 'LOGIN_SUCCESS', ...ctx(req) }, client);
      return s;
    });
    setSessionCookie(res, session.token, session.expiresAt);
    res.json({ user: publicUser(user) });
  }),
);

authRouter.post(
  '/logout',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { id, jti, exp } = req.user;
    await withTransaction(async (client) => {
      await client.query(
        `INSERT INTO revoked_tokens (jti, expires_at) VALUES ($1, to_timestamp($2)) ON CONFLICT (jti) DO NOTHING`,
        [jti, exp],
      );
      await client.query('DELETE FROM user_sessions WHERE jti = $1 AND user_id = $2', [jti, id]);
      await logEvent({ ownerId: id, event: 'SESSION_REVOKED', ...ctx(req), detail: { scope: 'logout' } }, client);
    });
    clearSessionCookie(res);
    res.json({ ok: true });
  }),
);

authRouter.get(
  '/me',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { rows } = await query('SELECT id, email, role, created_at FROM users WHERE id = $1', [req.user.id]);
    if (!rows[0]) throw new HttpError(401, 'No autenticado');
    res.json({ user: publicUser(rows[0]) });
  }),
);
