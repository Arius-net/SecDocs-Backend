import express from 'express';
import cookieParser from 'cookie-parser';
import { config } from './config/env.js';
import {
  helmetMiddleware,
  corsMiddleware,
  globalLimiter,
} from './middlewares/security.middleware.js';
import { errorHandler, notFoundHandler } from './middlewares/error.middleware.js';
import { apiRouter } from './modules/index.js';

export function createApp() {
  const app = express();

  app.disable('x-powered-by');
  // Necesario para que rate-limit y logs vean la IP real detrás de un proxy/Cloudflare.
  if (config.isProd) app.set('trust proxy', 1);

  app.use(helmetMiddleware);
  app.use(corsMiddleware);
  app.use(globalLimiter);
  app.use(express.json({ limit: '100kb' }));
  app.use(cookieParser());

  app.use('/api/v1', apiRouter);

  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}
