import nodemailer from 'nodemailer';
import { config } from '../config/env.js';

let transporter = null;

function getTransporter() {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.secure,
      auth: config.smtp.user ? { user: config.smtp.user, pass: config.smtp.pass } : undefined,
    });
  }
  return transporter;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

/**
 * Envío de correo. Sin SMTP: en desarrollo imprime el correo SOLO en consola;
 * en producción falla (nunca se enviaría la clave de Canal 2).
 * Nunca escribe el contenido en access_logs.
 */
export async function sendMail({ to, subject, text, html }) {
  if (!config.smtp.host) {
    if (config.isProd) throw new Error('SMTP no configurado: no se puede enviar correo en producción');
    console.log(
      [
        '┌── [mail:dev] SMTP no configurado, correo NO enviado (solo consola de desarrollo) ──',
        `│ Para:    ${to}`,
        `│ Asunto:  ${subject}`,
        '│',
        ...text.split('\n').map((l) => `│ ${l}`),
        '└──────────────────────────────────────────────────────────────────────',
      ].join('\n'),
    );
    return { delivered: false, mode: 'console' };
  }
  await getTransporter().sendMail({ from: config.smtp.from, to, subject, text, html });
  return { delivered: true, mode: 'smtp' };
}

/**
 * Canal 2: envía al invitado la contraseña de acceso a la bóveda compartida.
 * `password` viaja únicamente en el cuerpo del correo.
 */
export async function sendChannel2Password({ to, password, vaultName, ownerEmail }) {
  const subject = 'SecDocs: contraseña de acceso a la bóveda compartida';
  const text =
    `${ownerEmail} te compartió la bóveda "${vaultName}".\n\n` +
    `Tu contraseña de acceso (Canal 2) es:\n\n    ${password}\n\n` +
    'Úsala en la pantalla de desbloqueo después de abrir tu enlace de invitación.\n' +
    'No la compartas ni la reenvíes. Si no esperabas este correo, ignóralo.';
  const html =
    `<p>${escapeHtml(ownerEmail)} te compartió la bóveda "<b>${escapeHtml(vaultName)}</b>".</p>` +
    `<p>Tu contraseña de acceso (Canal 2) es:</p><pre style="font-size:18px">${escapeHtml(password)}</pre>` +
    '<p>Úsala en la pantalla de desbloqueo después de abrir tu enlace de invitación.<br>' +
    'No la compartas ni la reenvíes. Si no esperabas este correo, ignóralo.</p>';
  return sendMail({ to, subject, text, html });
}
