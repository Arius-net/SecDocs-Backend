import './helpers/env.js';
import test, { mock } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { sendChannel2Password } from '../src/services/mail.service.js';

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
    env: { ...process.env, NODE_ENV: 'production', SMTP_HOST: '' },
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);
  assert.match(r.stderr, /ERR:SMTP no configurado/);
  assert.ok(!r.stdout.includes('SECRETO-123'));
});
