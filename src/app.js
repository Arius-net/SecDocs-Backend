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
  // Necesario para que rate-limit, sesiones y logs vean la IP real detrás de Render/Railway/Cloudflare.
  if (config.trustProxy > 0) app.set('trust proxy', config.trustProxy);

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
