'use strict';

const express = require('express');
const multer = require('multer');
const { pipeline } = require('node:stream/promises');
const { HttpError } = require('./errors');
const {
  limiters, requireCsrfHeader, issueSession, clearSession, requireAuth, requestContext,
} = require('./middleware/security');

const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

/** Content-Disposition seguro (RFC 6266) con nombre ASCII de respaldo y UTF-8. */
function contentDisposition(name) {
  const ascii = name.normalize('NFKD').replace(/[^\x20-\x7e]/g, '_').replace(/["\\]/g, '_');
  return `attachment; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(name)}`;
}

function buildRouter({ vault, config }) {
  const r = express.Router();
  const auth = requireAuth(config);
  const upload = multer({
    // Memoria, NO disco: el texto claro nunca toca el sistema de archivos.
    storage: multer.memoryStorage(),
    limits: { fileSize: config.maxUploadBytes, files: 1, fields: 10, fieldSize: 1024 },
  });

  r.use(requireCsrfHeader);

  // ─────────── Autenticación ───────────
  r.post('/auth/register', limiters.register, wrap(async (req, res) => {
    const user = await vault.register(req.body ?? {}, requestContext(req));
    issueSession(res, user, config);
    res.status(201).json({ user });
  }));

  r.post('/auth/login', limiters.login, wrap(async (req, res) => {
    const user = await vault.login(req.body ?? {}, requestContext(req));
    issueSession(res, user, config);
    res.json({ user });
  }));

  r.post('/auth/logout', (_req, res) => {
    clearSession(res, config);
    res.status(204).end();
  });

  r.get('/auth/me', auth, wrap(async (req, res) => {
    const user = await vault.getUser(req.user.id);
    if (!user) throw new HttpError(401, 'UNAUTHENTICATED', 'Usuario no encontrado');
    res.json({ user });
  }));

  // ─────────── Archivos (requiere sesión) ───────────
  r.get('/files', auth, wrap(async (req, res) => {
    res.json({ files: await vault.listFiles(req.user.id) });
  }));

  r.post('/files', auth, (req, res, next) => {
    upload.single('file')(req, res, (err) => {
      if (err?.code === 'LIMIT_FILE_SIZE') {
        return next(new HttpError(413, 'TOO_LARGE', `El archivo supera ${config.maxUploadBytes / 1024 / 1024} MB`));
      }
      if (err) return next(new HttpError(400, 'UPLOAD_ERROR', err.message));
      next();
    });
  }, wrap(async (req, res) => {
    const file = await vault.uploadFile(req.user.id, req.file, req.body ?? {}, requestContext(req));
    res.status(201).json({ file });
  }));

  r.delete('/files/:id', auth, wrap(async (req, res) => {
    await vault.deleteFile(req.user.id, req.params.id, requestContext(req));
    res.status(204).end();
  }));

  // ─────────── Enlaces por receptor ───────────
  r.get('/files/:id/links', auth, wrap(async (req, res) => {
    res.json({ links: await vault.listLinks(req.user.id, req.params.id) });
  }));

  r.post('/files/:id/links', auth, wrap(async (req, res) => {
    const link = await vault.createLink(req.user.id, req.params.id, req.body ?? {}, requestContext(req));
    res.status(201).json({ link });
  }));

  r.post('/links/:id/revoke', auth, wrap(async (req, res) => {
    await vault.revokeLink(req.user.id, req.params.id, requestContext(req));
    res.status(204).end();
  }));

  r.get('/audit', auth, wrap(async (req, res) => {
    res.json({ events: await vault.listAudit(req.user.id, { fileId: req.query.fileId, limit: req.query.limit ?? 200 }) });
  }));

  // ─────────── Acceso público del receptor ───────────
  r.get('/public/links/:token', limiters.publicRead, wrap(async (req, res) => {
    res.json(await vault.publicLinkInfo(req.params.token));
  }));

  r.post('/public/links/:token/verify', limiters.verify, wrap(async (req, res) => {
    try {
      const result = await vault.verifyLinkPassword(req.params.token, req.body?.password, requestContext(req));
      res.json(result);
    } catch (e) {
      if (e.countsAsFailure) res.locals.authFailed = true; // suma al límite por IP
      throw e;
    }
  }));

  r.get('/public/download/:ticket', limiters.publicRead, wrap(async (req, res) => {
    const ctx = requestContext(req);
    const redeemed = await vault.redeemTicket(req.params.ticket, ctx);
    const { source, decrypt } = await vault.openDownload(redeemed, ctx);

    res.status(200);
    res.setHeader('Content-Type', 'application/octet-stream'); // nunca se renderiza en el navegador
    res.setHeader('Content-Length', String(redeemed.size_bytes));
    res.setHeader('Content-Disposition', contentDisposition(redeemed.original_filename));
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate, private, max-age=0');
    res.setHeader('Pragma', 'no-cache');
    res.setHeader('Expires', '0');

    let ok = false;
    try {
      await pipeline(source, decrypt, res);
      ok = true;
    } catch (e) {
      // Si algo falla a mitad del envío, se corta la conexión: el navegador marca la descarga como fallida.
      res.destroy(e);
    } finally {
      await vault.finishDownload(redeemed, ok, ctx).catch(() => {});
    }
  }));

  return r;
}

function errorHandler(log = console) {
  return (err, req, res, _next) => {
    if (res.headersSent) return res.destroy();
    if (err instanceof HttpError) {
      if (err.extra?.retryAfter) res.setHeader('Retry-After', String(err.extra.retryAfter));
      return res.status(err.status).json({ error: { code: err.code, message: err.message, ...err.extra } });
    }
    if (err.status === 415 || err.status === 400) {
      return res.status(err.status).json({ error: { code: 'BAD_REQUEST', message: err.message } });
    }
    if (err.type === 'entity.parse.failed') {
      return res.status(400).json({ error: { code: 'BAD_JSON', message: 'JSON inválido' } });
    }
    // Se registra la ruta "patrón" (p. ej. /public/links/:token), nunca la URL real con el token.
    log.error('[error]', req.method, req.route?.path ?? '(sin ruta)', err);
    res.status(500).json({ error: { code: 'INTERNAL', message: 'Error interno' } });
  };
}

module.exports = { buildRouter, errorHandler };
