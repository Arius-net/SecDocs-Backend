import { fileTypeFromBuffer } from 'file-type';
import { HttpError } from '../middlewares/error.middleware.js';

// Allowlist de formatos seguros, determinados por MAGIC BYTES (nunca por extensión ni Content-Type del cliente).
const ALLOWED_BINARY = new Set([
  'application/pdf',
  'image/png',
  'image/jpeg',
  'image/webp',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document', // DOCX
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet', // XLSX
  'application/vnd.openxmlformats-officedocument.presentationml.presentation', // PPTX
  'application/zip',
]);

const CONTROL_CHARS_RE = /[\x00-\x08\x0B\x0E-\x1F\x7F]/; // permite \t \n \r \f
// Contenido activo que no se acepta ni como texto (HTML, SVG, XML, scripts).
const ACTIVE_START_RE = /^\s*(<!doctype|<html|<svg|<\?xml|<\?php|#!)/i;
const ACTIVE_TAG_RE = /<\s*(script|svg|html|iframe|object|embed)\b/i;

function looksLikeSafeText(buffer) {
  let text;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(buffer);
  } catch {
    return false; // no es UTF-8 válido
  }
  if (CONTROL_CHARS_RE.test(text)) return false; // incluye bytes nulos
  const head = text.slice(0, 65536);
  if (ACTIVE_START_RE.test(head) || ACTIVE_TAG_RE.test(head)) return false;
  return true;
}

/**
 * Determina el MIME real del buffer y lo valida contra la allowlist.
 * `clientMime` y la extensión se ignoran (solo la extensión .csv distingue text/csv de text/plain).
 */
export async function detectAllowedMime(buffer, filename = '') {
  if (!Buffer.isBuffer(buffer) || buffer.length === 0) throw new HttpError(400, 'El archivo está vacío');
  const ft = await fileTypeFromBuffer(buffer);
  if (ft) {
    if (ALLOWED_BINARY.has(ft.mime)) return ft.mime;
    throw new HttpError(415, 'Tipo de archivo no permitido');
  }
  if (looksLikeSafeText(buffer)) return /\.csv$/i.test(filename) ? 'text/csv' : 'text/plain';
  throw new HttpError(415, 'Tipo de archivo no permitido');
}

/** Sanitiza el nombre original: sin separadores de ruta, `..` ni caracteres de control. */
export function sanitizeFilename(raw) {
  let name = String(raw ?? '');
  // multer/busboy entrega el nombre como latin1: recuperar UTF-8 si corresponde.
  const asUtf8 = Buffer.from(name, 'latin1').toString('utf8');
  if (!asUtf8.includes('\uFFFD')) name = asUtf8;
  name = name
    .replace(/[\x00-\x1F\x7F-\x9F]/g, '')
    .replace(/[/\\]/g, '')
    .replace(/\.{2,}/g, '.')
    .replace(/^[.\s]+/, '')
    .trim()
    .slice(0, 255)
    .trim();
  return name || 'archivo';
}
