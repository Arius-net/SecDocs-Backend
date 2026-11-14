import multer from 'multer';
import { config } from '../config/env.js';

/** Error HTTP controlado: el mensaje es seguro para el cliente. */
export class HttpError extends Error {
  constructor(status, message, extra = {}) {
    super(message);
    this.status = status;
    this.extra = extra;
  }
}

export function notFoundHandler(req, res) {
  res.status(404).json({ error: 'Recurso no encontrado' });
}

// eslint-disable-next-line no-unused-vars
export function errorHandler(err, req, res, next) {
  if (res.headersSent) return next(err);

  if (err instanceof HttpError) {
    return res.status(err.status).json({ error: err.message, ...err.extra });
  }
  if (err instanceof multer.MulterError) {
    const status = err.code === 'LIMIT_FILE_SIZE' ? 413 : 400;
    const msg = err.code === 'LIMIT_FILE_SIZE' ? 'El archivo excede el tamaño máximo permitido' : 'Solicitud de subida inválida';
    return res.status(status).json({ error: msg });
  }
  if (err.type === 'entity.parse.failed') {
    return res.status(400).json({ error: 'JSON inválido' });
  }
  if (err.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Cuerpo de la solicitud demasiado grande' });
  }
  if (err.message === 'Origen no permitido por CORS') {
    return res.status(403).json({ error: 'Origen no permitido' });
  }

  // Error inesperado: se registra solo el mensaje/stack, nunca el cuerpo de la solicitud.
  console.error(`[error] ${req.method} ${req.path}:`, config.isProd ? err.message : err.stack);
  return res.status(500).json({ error: 'Error interno del servidor' });
}
