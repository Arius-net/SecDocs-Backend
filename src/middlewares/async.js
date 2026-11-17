/** Envuelve handlers async de Express 4 para propagar rechazos al manejador de errores. */
export const asyncHandler = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
