import './helpers/env.js';
import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { spawnSync } from 'node:child_process';
import { config } from '../src/config/env.js';
import { sendChannel2Password, sendMail } from '../src/services/mail.service.js';

test('sin SMTP en dev: imprime el correo solo en consola y no lo envía', async () => {
  const spy = mock.method(console, 'log', () => {});
  try {
    const r = await sendChannel2Password({
      to: 'invitado@example.com',
      password: 'Cl4ve-Ejemplo-123',
      vaultName: 'Contratos <2026>',
      ownerEmail: 'dueno@example.com',
    });
    assert.deepEqual(r, { delivered: false, mode: 'console' });
    const out = spy.mock.calls.map((c) => c.arguments.join(' ')).join('\n');
    assert.match(out, /invitado@example\.com/);
    assert.match(out, /Cl4ve-Ejemplo-123/);
    assert.match(out, /\[mail:dev\]/);
  } finally {
    spy.mock.restore();
  }
});

test('sendMail en producción sin SMTP falla y no imprime el contenido', () => {
  const code =
    "import('./src/services/mail.service.js').then(m => m.sendMail({to:'a@b.c',subject:'s',text:'SECRETO-123'}))" +
    ".then(() => process.exit(1), e => { console.error('ERR:' + e.message); process.exit(0); })";
  const r = spawnSync(process.execPath, ['-e', code], {
    env: { ...process.env, NODE_ENV: 'production', SMTP_HOST: '', MAIL_WEBHOOK_URL: '' },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /ERR:SMTP no configurado/);
  assert.ok(!r.stdout.includes('SECRETO-123'));
});

test('webhook-https: envía POST JSON con secret y valida respuesta body.ok === true', async () => {
  let received = null;
  let shouldFail = false;
  const server = http.createServer((req, res) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => {
      received = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(shouldFail ? { ok: false, error: 'secret inválido' } : { ok: true }));
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;

  try {
    config.mail.webhookUrl = `http://127.0.0.1:${port}/exec`;
    config.mail.webhookSecret = 'mi-secreto-webhook';

    const r = await sendMail({
      to: 'dest@example.com',
      subject: 'Asunto Webhook',
      text: 'Texto plano',
      html: '<b>HTML</b>',
    });
    assert.deepEqual(r, { delivered: true, mode: 'webhook-https' });
    assert.deepEqual(received, {
      secret: 'mi-secreto-webhook',
      to: 'dest@example.com',
      subject: 'Asunto Webhook',
      text: 'Texto plano',
      html: '<b>HTML</b>',
    });

    shouldFail = true;
    await assert.rejects(
      () => sendMail({ to: 'dest@example.com', subject: 's', text: 't', html: 'h' }),
      /Fallo en webhook de correo: secret inválido/,
    );
  } finally {
    config.mail.webhookUrl = '';
    config.mail.webhookSecret = '';
    await new Promise((r) => server.close(r));
  }
});
