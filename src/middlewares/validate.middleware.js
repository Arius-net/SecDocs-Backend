import { z } from 'zod';
import { HttpError } from './error.middleware.js';
import { config } from '../config/env.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CONTROL_RE = /[\x00-\x1F\x7F]/;
const MAX_PASSWORD_BYTES = 72;

/**
 * Middleware que valida `req.body` contra un esquema de Zod.
 * Si la entrada es inválida, responde 400 (o `status` configurado) con un mensaje claro.
 */
export function validateBody(schema, { status = 400, overrideMessage = null } = {}) {
  return (req, res, next) => {
    const parsed = schema.safeParse(req.body ?? {});
    if (!parsed.success) {
      const firstIssue = parsed.error.issues[0];
      const msg = overrideMessage || firstIssue?.message || 'Datos de entrada inválidos';
      return next(new HttpError(status, msg));
    }
    req.body = parsed.data;
    return next();
  };
}

// ------------------------- Esquemas Zod principales -------------------------

export const registerSchema = z.object({
  email: z
    .string({ required_error: 'Correo inválido', invalid_type_error: 'Correo inválido' })
    .transform((v) => v.trim().toLowerCase())
    .refine((v) => v.length > 0 && v.length <= 255 && EMAIL_RE.test(v), { message: 'Correo inválido' }),
  password: z
    .string({ required_error: 'Contraseña inválida', invalid_type_error: 'Contraseña inválida' })
    .refine((v) => Buffer.byteLength(v, 'utf8') <= MAX_PASSWORD_BYTES, {
      message: `La contraseña no puede exceder ${MAX_PASSWORD_BYTES} bytes`,
    })
    .refine((v) => v.length >= 8, {
      message: 'La contraseña debe tener al menos 8 caracteres',
    }),
});

export const loginSchema = z.object({
  email: z
    .string({ required_error: 'Credenciales inválidas', invalid_type_error: 'Credenciales inválidas' })
    .transform((v) => v.trim().toLowerCase())
    .refine((v) => v.length <= 255, { message: 'Credenciales inválidas' }),
  password: z
    .string({ required_error: 'Credenciales inválidas', invalid_type_error: 'Credenciales inválidas' })
    .refine((v) => Buffer.byteLength(v, 'utf8') <= MAX_PASSWORD_BYTES, {
      message: 'Credenciales inválidas',
    }),
});

export const createVaultSchema = z.object({
  name: z
    .string({ required_error: 'El nombre es obligatorio', invalid_type_error: 'El nombre es obligatorio' })
    .transform((v) => v.trim())
    .refine((v) => v.length >= 1 && v.length <= 150, {
      message: 'El nombre debe tener entre 1 y 150 caracteres',
    })
    .refine((v) => !CONTROL_RE.test(v), {
      message: 'El nombre contiene caracteres no permitidos',
    }),
  expires_at: z
    .string({
      required_error: 'expires_at es obligatorio (fecha ISO 8601)',
      invalid_type_error: 'expires_at es obligatorio (fecha ISO 8601)',
    })
    .refine((v) => v.trim().length > 0, {
      message: 'expires_at es obligatorio (fecha ISO 8601)',
    })
    .refine((v) => !Number.isNaN(Date.parse(v)), {
      message: 'expires_at no es una fecha válida',
    })
    .refine((v) => Date.parse(v) > Date.now(), {
      message: 'expires_at debe ser una fecha futura',
    })
    .refine((v) => Date.parse(v) <= Date.now() + config.vaultMaxDays * 86_400_000, {
      message: `expires_at no puede exceder ${config.vaultMaxDays} días desde hoy`,
    }),
});

export const createMemberSchema = z.object({
  recipient_email: z
    .string({ required_error: 'recipient_email inválido', invalid_type_error: 'recipient_email inválido' })
    .transform((v) => v.trim().toLowerCase())
    .refine((v) => v.length > 0 && v.length <= 255 && EMAIL_RE.test(v), {
      message: 'recipient_email inválido',
    }),
  recipient_label: z
    .string({ invalid_type_error: 'recipient_label inválido' })
    .transform((v) => v.trim() || null)
    .refine((v) => !v || (v.length <= 120 && !CONTROL_RE.test(v)), {
      message: 'recipient_label inválido (máx. 120 caracteres)',
    })
    .nullable()
    .optional(),
  max_downloads: z
    .number({ invalid_type_error: 'max_downloads debe ser un entero entre 1 y 10' })
    .int('max_downloads debe ser un entero entre 1 y 10')
    .min(1, 'max_downloads debe ser un entero entre 1 y 10')
    .max(10, 'max_downloads debe ser un entero entre 1 y 10')
    .optional(),
  expires_at: z
    .string({ invalid_type_error: 'expires_at no es una fecha válida' })
    .refine((v) => !Number.isNaN(Date.parse(v)), {
      message: 'expires_at no es una fecha válida',
    })
    .refine((v) => Date.parse(v) > Date.now(), {
      message: 'expires_at debe ser una fecha futura',
    })
    .optional(),
});
