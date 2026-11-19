import { HttpError } from '../middlewares/error.middleware.js';

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Normaliza (`trim().toLowerCase()`) y valida formato/longitud de un correo. */
export function normalizeEmail(value, message = 'Correo inválido') {
  if (typeof value !== 'string') throw new HttpError(400, message);
  const email = value.trim().toLowerCase();
  if (email.length > 255 || !EMAIL_RE.test(email)) throw new HttpError(400, message);
  return email;
}

/** `alice@dominio.com` -> `a***@dominio.com` */
export function maskEmail(email) {
  const [local = '', domain = ''] = String(email).split('@');
  return `${local.slice(0, 1)}***@${domain}`;
}
