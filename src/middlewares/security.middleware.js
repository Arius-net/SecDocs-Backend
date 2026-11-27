import cors from 'cors';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import { config } from '../config/env.js';

export const helmetMiddleware = helmet({
  hsts: { maxAge: 31536000, includeSubDomains: true },
  contentSecurityPolicy: {
    directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] },
  },
  referrerPolicy: { policy: 'no-referrer' },
  crossOriginResourcePolicy: { policy: 'same-site' },
});

/** CORS estricto: solo orígenes listados en CORS_ORIGINS, con credenciales. */
export const corsMiddleware = cors({
  origin(origin, cb) {
    // Peticiones sin Origin (curl, server-to-server) no son CORS del navegador.
    if (!origin || config.corsOrigins.includes(origin)) return cb(null, true);
    return cb(new Error('Origen no permitido por CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'X-Download-Ticket'],
  maxAge: 600,
});

function limiter(windowMs, limit, message) {
  return rateLimit({
    windowMs,
    limit,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    message: { error: message },
  });
}

/** Límite global por IP. */
export const globalLimiter = limiter(15 * 60 * 1000, 600, 'Demasiadas solicitudes, intenta más tarde');
/** Límite estricto para autenticación (anti fuerza bruta). */
export const authLimiter = limiter(15 * 60 * 1000, config.authRateLimitMax, 'Demasiados intentos de autenticación, intenta más tarde');
/** Límite para endpoints de invitación (públicos / canal 2). */
export const invitationLimiter = limiter(15 * 60 * 1000, config.invitationRateLimitMax, 'Demasiadas solicitudes de invitación, intenta más tarde');

/** Cabeceras anti-indexación/caché para descargas y rutas compartidas. */
export function noStoreHeaders(req, res, next) {
  res.set({
    'X-Robots-Tag': 'noindex, nofollow, noarchive',
    'Referrer-Policy': 'no-referrer',
    'Cache-Control': 'no-store',
  });
  next();
}
