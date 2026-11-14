'use strict';

const helmet = require('helmet');
const { rateLimit } = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const { HttpError } = require('../errors');

const COOKIE = 'sd_session';

function securityHeaders() {
  const h = helmet({
    // La API sólo devuelve JSON o archivos adjuntos: no necesita cargar nada.
    contentSecurityPolicy: { useDefaults: false, directives: { defaultSrc: ["'none'"], frameAncestors: ["'none'"] } },
    xFrameOptions: { action: 'deny' },
    referrerPolicy: { policy: 'no-referrer' },
    crossOriginResourcePolicy: { policy: 'same-origin' },
    strictTransportSecurity: { maxAge: 31536000, includeSubDomains: true },
  });
  return [
    h,
    (_req, res, next) => {
      res.setHeader('X-Robots-Tag', 'noindex, nofollow, noarchive');
      res.setHeader('Cache-Control', 'no-store');
      next();
    },
  ];
}

function limiter({ windowMinutes, max, skipSuccessfulRequests = false, requestWasSuccessful, message }) {
  return rateLimit({
    windowMs: windowMinutes * 60 * 1000,
    limit: max,
    standardHeaders: 'draft-7',
    legacyHeaders: false,
    skipSuccessfulRequests,
    ...(requestWasSuccessful ? { requestWasSuccessful } : {}),
    handler: (_req, res) =>
      res.status(429).json({ error: { code: 'RATE_LIMITED', message: message || 'Demasiadas solicitudes, intenta más tarde' } }),
  });
}

const limiters = {
  // Documento §4.3: máximo 5 intentos FALLIDOS por IP en 15 minutos.
  // Sólo cuentan las claves INCORRECTAS (marcadas por la ruta en res.locals.authFailed);
  // los 404 o los 429 del retardo progresivo no consumen el cupo.
  verify: limiter({
    windowMinutes: 15, max: 5, skipSuccessfulRequests: true,
    requestWasSuccessful: (_req, res) => !res.locals.authFailed,
    message: 'Demasiados intentos fallidos desde esta IP. Espera 15 minutos.',
  }),
  login: limiter({ windowMinutes: 15, max: 10, skipSuccessfulRequests: true, message: 'Demasiados intentos de inicio de sesión. Espera 15 minutos.' }),
  register: limiter({ windowMinutes: 60, max: 10 }),
  publicRead: limiter({ windowMinutes: 1, max: 120 }),
  api: limiter({ windowMinutes: 1, max: 300 }),
};

/**
 * Defensa adicional contra CSRF: además de SameSite=Strict, toda petición que modifica
 * estado debe traer una cabecera personalizada. Un sitio ajeno no puede añadirla sin CORS.
 */
function requireCsrfHeader(req, _res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  if (req.get('X-SecDocs-CSRF') !== '1') return next(new HttpError(403, 'CSRF', 'Falta la cabecera anti-CSRF'));
  next();
}

function sessionCookieOptions(config) {
  return {
    httpOnly: true,
    secure: config.cookieSecure,
    sameSite: 'strict',
    path: '/',
    maxAge: config.jwtTtlSeconds * 1000,
  };
}

function issueSession(res, user, config) {
  const token = jwt.sign({ sub: user.id, role: user.role }, config.jwtSecret, {
    algorithm: 'HS256',
    expiresIn: config.jwtTtlSeconds,
    issuer: 'secdocs',
    audience: 'secdocs-web',
  });
  res.cookie(COOKIE, token, sessionCookieOptions(config));
}

function clearSession(res, config) {
  const { maxAge, ...opts } = sessionCookieOptions(config);
  res.clearCookie(COOKIE, opts);
}

function requireAuth(config) {
  return (req, _res, next) => {
    const token = req.cookies?.[COOKIE];
    if (!token) return next(new HttpError(401, 'UNAUTHENTICATED', 'Inicia sesión para continuar'));
    try {
      // algorithms fijo: evita ataques de confusión de algoritmo ("alg": "none").
      const payload = jwt.verify(token, config.jwtSecret, { algorithms: ['HS256'], issuer: 'secdocs', audience: 'secdocs-web' });
      req.user = { id: payload.sub, role: payload.role };
      next();
    } catch {
      next(new HttpError(401, 'UNAUTHENTICATED', 'Sesión inválida o expirada'));
    }
  };
}

function requestContext(req) {
  return { ip: req.ip, userAgent: req.get('user-agent') || '' };
}

module.exports = {
  securityHeaders, limiters, requireCsrfHeader, issueSession, clearSession, requireAuth, requestContext,
};
