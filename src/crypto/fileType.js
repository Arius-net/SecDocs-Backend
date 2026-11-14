'use strict';

/**
 * Validación de tipo de archivo por "magic bytes".
 * El tipo MIME que manda el navegador lo controla el cliente y se puede falsificar,
 * así que el servidor revisa la extensión Y el contenido real del archivo.
 */

const SIG = {
  pdf: [0x25, 0x50, 0x44, 0x46, 0x2d], // %PDF-
  png: [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a],
  jpg: [0xff, 0xd8, 0xff],
  zip: [0x50, 0x4b, 0x03, 0x04], // también DOCX/XLSX/PPTX (son ZIP)
};

const ALLOWED = {
  pdf: { sig: 'pdf', mime: 'application/pdf' },
  png: { sig: 'png', mime: 'image/png' },
  jpg: { sig: 'jpg', mime: 'image/jpeg' },
  jpeg: { sig: 'jpg', mime: 'image/jpeg' },
  docx: { sig: 'zip', mime: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document' },
  xlsx: { sig: 'zip', mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
  pptx: { sig: 'zip', mime: 'application/vnd.openxmlformats-officedocument.presentationml.presentation' },
  zip: { sig: 'zip', mime: 'application/zip' },
  // Secretos en texto plano típicos (llaves SSH, .env, certificados).
  txt: { sig: 'text', mime: 'text/plain' },
  csv: { sig: 'text', mime: 'text/csv' },
  env: { sig: 'text', mime: 'text/plain' },
  pem: { sig: 'text', mime: 'application/x-pem-file' },
  key: { sig: 'text', mime: 'text/plain' },
  pub: { sig: 'text', mime: 'text/plain' },
  json: { sig: 'text', mime: 'application/json' },
};

function startsWith(buf, bytes) {
  if (buf.length < bytes.length) return false;
  return bytes.every((b, i) => buf[i] === b);
}

function looksLikeText(buf) {
  const sample = buf.subarray(0, 64 * 1024);
  if (sample.includes(0x00)) return false;
  // TextDecoder con fatal:true lanza error si no es UTF-8 válido.
  try {
    new TextDecoder('utf-8', { fatal: true }).decode(sample.length === buf.length ? sample : trimUtf8(sample));
    return true;
  } catch {
    return false;
  }
}

// Evita falsos negativos si la muestra corta un carácter multibyte a la mitad.
function trimUtf8(b) {
  let end = b.length;
  for (let i = 1; i <= 3 && end - i >= 0; i++) {
    const byte = b[end - i];
    if ((byte & 0xc0) === 0xc0) return b.subarray(0, end - i);
    if ((byte & 0x80) === 0) break;
  }
  return b;
}

function extensionOf(name) {
  const base = String(name).toLowerCase();
  if (base === '.env' || base.startsWith('.env.')) return 'env';
  const m = /\.([a-z0-9]{1,8})$/.exec(base);
  return m ? m[1] : '';
}

/** Devuelve { ext, mime } o lanza un error si el archivo no está permitido. */
function detect(originalName, buf) {
  const ext = extensionOf(originalName);
  const rule = ALLOWED[ext];
  if (!rule) throw Object.assign(new Error(`Extensión no permitida: .${ext || '?'}`), { status: 415 });
  const ok = rule.sig === 'text' ? looksLikeText(buf) : startsWith(buf, SIG[rule.sig]);
  if (!ok) {
    throw Object.assign(new Error('El contenido del archivo no corresponde a su extensión'), { status: 415 });
  }
  return { ext, mime: rule.mime };
}

/** Limpia el nombre original: sin rutas, sin caracteres de control, longitud acotada. */
function sanitizeFilename(name) {
  const base = String(name || 'archivo').split(/[\\/]/).pop();
  const clean = base
    .normalize('NFC')
    .replace(/[\u0000-\u001f\u007f"<>:|?*]/g, '_')
    .replace(/^\.{2,}/, '_')
    .trim()
    .slice(0, 200);
  return clean || 'archivo';
}

module.exports = { detect, sanitizeFilename, ALLOWED_EXTENSIONS: Object.keys(ALLOWED) };
