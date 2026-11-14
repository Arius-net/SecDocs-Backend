'use strict';

class HttpError extends Error {
  constructor(status, code, message, extra = {}) {
    super(message);
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

// Respuesta uniforme para cualquier enlace inexistente, vencido, revocado,
// agotado o bloqueado: no revela al atacante en qué estado está un token.
const notAvailable = () => new HttpError(404, 'NOT_AVAILABLE', 'Este enlace no existe o ya no está disponible');

const bad = (msg) => new HttpError(400, 'BAD_REQUEST', msg);

module.exports = { HttpError, notAvailable, bad };
