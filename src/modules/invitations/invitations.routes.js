import { Router } from 'express';
import bcrypt from 'bcrypt';
import { config } from '../../config/env.js';
import { query, withTransaction } from '../../db/pool.js';
import { HttpError } from '../../middlewares/error.middleware.js';
import { asyncHandler } from '../../middlewares/async.js';
import { requireAuth } from '../../middlewares/auth.middleware.js';
import { sha256Hex, randomToken } from '../../services/crypto.service.js';
import { logEvent, incrementDailyStats } from '../../services/audit.service.js';
import { sendChannel2Password } from '../../services/mail.service.js';
import { maskEmail } from '../../services/validators.js';
import {
  loadInvitation,
  requireAvailable,
  emailMatches,
  denyAccess,
  generateChannel2Password,
  MAX_ATTEMPTS,
  LONG_LOCK_SECONDS,
  TICKET_TTL_SECONDS,
} from './invitation.service.js';

const ctx = (req) => ({ ip: req.ip, userAgent: req.get('user-agent') });
export const invitationsRouter = Router();

// Info mínima y segura para la pantalla 05 (no requiere sesión).
invitationsRouter.get(
  '/:token',
  asyncHandler(async (req, res) => {
    const row = requireAvailable(await loadInvitation({ query }, req.params.token));
    res.json({
      invitation: {
        vaultName: row.vault_name,
        ownerEmail: maskEmail(row.owner_email),
        maskedEmail: maskEmail(row.recipient_email),
        status: row.status,
        expires_at: row.expires_at,
      },
    });
  }),
);

// Canal 1 verificado (sesión + correo) -> se envía la clave por Canal 2 (correo).
invitationsRouter.post(
  '/:token/verify-identity',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { token } = req.params;
    const first = requireAvailable(await loadInvitation({ query }, token));
    if (!emailMatches(req.user, first)) {
      throw await denyAccess(req, { ownerId: first.owner_id, vaultId: first.vault_id, memberId: first.id }, 'verify_identity');
    }

    const cooldown = config.invitation.resendCooldownSeconds;
    const outcome = await withTransaction(async (client) => {
      const row = requireAvailable(await loadInvitation(client, token, { lock: true }));
      await logEvent(
        { ownerId: row.owner_id, vaultId: row.vault_id, memberId: row.id, event: 'IDENTITY_VERIFIED', ...ctx(req) },
        client,
      );

      // Cooldown anti-spam entre envíos (basado en el último PASSWORD_SENT del miembro).
      const last = await client.query(
        `SELECT EXTRACT(EPOCH FROM (now() - max(created_at)))::float AS age
           FROM access_logs WHERE member_id = $1 AND event = 'PASSWORD_SENT'`,
        [row.id],
      );
      const age = last.rows[0].age;
      if (age !== null && age < cooldown) return { cooldown: Math.ceil(cooldown - age) };

      const password = generateChannel2Password();
      const hash = await bcrypt.hash(password, 12);
      await client.query('UPDATE workspace_members SET password_hash = $1 WHERE id = $2', [hash, row.id]);
      try {
        await sendChannel2Password({
          to: row.recipient_email,
          password,
          vaultName: row.vault_name,
          ownerEmail: row.owner_email,
        });
      } catch (err) {
        console.error('[mail] fallo al enviar la clave de Canal 2:', err.message);
        throw new HttpError(502, 'No se pudo enviar el correo con la clave. Intenta de nuevo más tarde');
      }
      await logEvent(
        { ownerId: row.owner_id, vaultId: row.vault_id, memberId: row.id, event: 'PASSWORD_SENT', ...ctx(req) },
        client,
      );
      return { sent: true, maskedEmail: maskEmail(row.recipient_email) };
    });

    if (outcome.cooldown) {
      res.set('Retry-After', String(outcome.cooldown));
      return res.status(429).json({ error: 'La clave ya fue enviada recientemente', retryAfterSeconds: outcome.cooldown });
    }
    return res.json({ ok: true, message: 'Clave enviada a tu correo', maskedEmail: outcome.maskedEmail, cooldownSeconds: cooldown });
  }),
);

invitationsRouter.post(
  '/:token/unlock',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { token } = req.params;
    const password = req.body?.password;
    const first = requireAvailable(await loadInvitation({ query }, token));
    if (!emailMatches(req.user, first)) {
      throw await denyAccess(req, { ownerId: first.owner_id, vaultId: first.vault_id, memberId: first.id }, 'unlock');
    }
    if (typeof password !== 'string' || password.length === 0 || password.length > 128) {
      throw new HttpError(400, 'La contraseña es obligatoria');
    }

    // Todo el intento se serializa con el bloqueo de fila: sin carreras en el conteo de fallos.
    const out = await withTransaction(async (client) => {
      const row = requireAvailable(await loadInvitation(client, token, { lock: true }));
      if (row.download_count >= row.max_downloads) return { kind: 'exhausted' };
      if (row.lock_seconds > 0) {
        // Bloqueado: NO se evalúa bcrypt (ni siquiera con la clave correcta).
        return { kind: 'locked', retry: row.lock_seconds, attempts: row.failed_attempts };
      }

      const ok = await bcrypt.compare(password, row.password_hash);
      if (!ok) {
        const attempts = row.failed_attempts + 1;
        const lockSeconds = attempts >= MAX_ATTEMPTS ? LONG_LOCK_SECONDS : 2 ** attempts;
        await client.query(
          `UPDATE workspace_members
              SET failed_attempts = $2::int,
                  locked_until = now() + make_interval(secs => $3::double precision),
                  status = CASE WHEN $2::int >= $4::int THEN 'TEMP_LOCKED' ELSE status END,
                  ticket_hash = NULL, ticket_expires_at = NULL
            WHERE id = $1`,
          [row.id, attempts, lockSeconds, MAX_ATTEMPTS],
        );
        await incrementDailyStats(row.owner_id, { failedAttempts: 1 }, client);
        await logEvent(
          {
            ownerId: row.owner_id, vaultId: row.vault_id, memberId: row.id, event: 'UNLOCK_FAILED', ...ctx(req),
            detail: { attempts_used: attempts, lock_seconds: lockSeconds, temp_locked: attempts >= MAX_ATTEMPTS },
          },
          client,
        );
        return { kind: 'fail', attempts, retry: lockSeconds };
      }

      // Éxito: ticket de un solo uso (60 s). Solo se guarda SHA-256(ticket).
      const ticket = randomToken(32);
      const upd = await client.query(
        `UPDATE workspace_members
            SET failed_attempts = 0, locked_until = NULL, status = 'ACCEPTED', last_access_at = now(),
                ticket_hash = $2, ticket_expires_at = now() + make_interval(secs => $3::double precision)
          WHERE id = $1
        RETURNING ticket_expires_at`,
        [row.id, sha256Hex(ticket), TICKET_TTL_SECONDS],
      );
      const files = await client.query(
        `SELECT id, original_filename, mime_type, size_bytes, status, created_at
           FROM vault_files WHERE vault_id = $1 AND status = 'ACTIVE' ORDER BY created_at DESC`,
        [row.vault_id],
      );
      if (!row.last_access_at) await incrementDailyStats(row.owner_id, { uniqueVisitors: 1 }, client);
      await logEvent(
        { ownerId: row.owner_id, vaultId: row.vault_id, memberId: row.id, event: 'VAULT_UNLOCKED_BY_MEMBER', ...ctx(req) },
        client,
      );
      return {
        kind: 'ok',
        ticket,
        ticketExpiresAt: upd.rows[0].ticket_expires_at,
        vault: { id: row.vault_id, name: row.vault_name, expires_at: row.vault_expires_at },
        files: files.rows,
        downloadsRemaining: row.max_downloads - row.download_count,
      };
    });

    switch (out.kind) {
      case 'exhausted':
        throw new HttpError(403, 'Se alcanzó el límite de descargas de esta invitación');
      case 'locked':
        res.set('Retry-After', String(out.retry));
        return res.status(429).json({
          error: 'Acceso temporalmente bloqueado por intentos fallidos',
          retryAfterSeconds: out.retry,
          failedAttempts: out.attempts,
          attemptsUsed: out.attempts,
          maxAttempts: MAX_ATTEMPTS,
        });
      case 'fail': {
        const locked = out.attempts >= MAX_ATTEMPTS;
        res.set('Retry-After', String(out.retry));
        return res.status(locked ? 429 : 401).json({
          error: locked ? 'Demasiados intentos: acceso bloqueado temporalmente' : 'Contraseña incorrecta',
          attemptsUsed: out.attempts,
          maxAttempts: MAX_ATTEMPTS,
          retryAfterSeconds: out.retry,
        });
      }
      default:
        return res.json({
          ticket: out.ticket,
          ticketExpiresAt: out.ticketExpiresAt,
          vault: out.vault,
          files: out.files,
          downloadsRemaining: out.downloadsRemaining,
        });
    }
  }),
);
