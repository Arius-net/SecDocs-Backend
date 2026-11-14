'use strict';

const express = require('express');
const cookieParser = require('cookie-parser');
const { securityHeaders, limiters } = require('./middleware/security');
const { buildRouter, errorHandler } = require('./routes');

function createApp({ vault, config, log = console }) {
  const app = express();
  app.disable('x-powered-by');
  // Detrás de un proxy (Next.js / Railway) para que req.ip sea la IP real del cliente.
  const tp = config.trustProxy;
  app.set('trust proxy', /^\d+$/.test(String(tp)) ? Number(tp) : tp);

  app.use(securityHeaders());
  app.use(express.json({ limit: '16kb' }));
  app.use(cookieParser());

  app.get('/health', (_req, res) => res.json({ ok: true }));
  app.use('/api', limiters.api, buildRouter({ vault, config }));

  // 404 uniforme para cualquier ruta desconocida.
  app.use((_req, res) => res.status(404).json({ error: { code: 'NOT_FOUND', message: 'No encontrado' } }));
  app.use(errorHandler(log));
  return app;
}

module.exports = { createApp };
