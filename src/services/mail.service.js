import nodemailer from 'nodemailer';
import { config } from '../config/env.js';

let transporter = null;

function resolveProvider() {
  if (config.mail.webhookUrl) return 'webhook-https';
  if (config.mail.host) return 'smtp';
  return 'console';
}

console.info(`[mail] proveedor activo: ${resolveProvider()}`);

function getTransporter() {
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: config.mail.host,
      port: config.mail.port,
      secure: config.mail.secure,
      connectionTimeout: 10_000,
      auth: config.mail.user ? { user: config.mail.user, pass: config.mail.pass } : undefined,
    });
  }
  return transporter;
}

function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

/**
 * Envío de correo con prioridad:
 *  1) Webhook HTTPS (puerto 443, ej. Google Apps Script) si MAIL_WEBHOOK_URL está definido.
 *  2) Nodemailer SMTP si SMTP_HOST está definido.
 *  3) Consola en desarrollo (en producción lanza error).
 * Nunca escribe el contenido en access_logs.
 */
export async function sendMail({ to, subject, text, html }) {
  if (config.mail.webhookUrl) {
    const res = await fetch(config.mail.webhookUrl, {
      method: 'POST',
      redirect: 'follow',
      signal: AbortSignal.timeout(15_000),
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        secret: config.mail.webhookSecret,
        to,
        subject,
        text,
        html,
      }),
    });

    let body = null;
    try {
      body = await res.json();
    } catch {
      // respuesta no JSON
    }

    if (!res.ok || body?.ok !== true) {
      const detail = body?.error || body?.message || `HTTP ${res.status}`;
      console.error(`[mail:webhook] fallo al enviar correo por HTTPS (${res.status}):`, detail);
      throw new Error(`Fallo en webhook de correo: ${detail}`);
    }
    return { delivered: true, mode: 'webhook-https' };
  }

  if (config.mail.host) {
    await getTransporter().sendMail({ from: config.mail.from, to, subject, text, html });
    return { delivered: true, mode: 'smtp' };
  }

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
