import './helpers/env.js';
import test, { before, after } from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import { config } from '../src/config/env.js';
import { pool, query } from '../src/db/pool.js';
import { runMigrations } from '../src/db/migrate.js';
import { startServer, createClient, uniqueEmail } from './helpers/http.js';

const PASSWORD = 'Contraseña-Segura-123';
let srv;
const createdEmails = [];

before(async () => {
  await runMigrations();
  srv = await startServer();
});

after(async () => {
  await query('DELETE FROM users WHERE lower(email) = ANY($1)', [createdEmails.map((e) => e.toLowerCase())]);
  await srv.close();
  await pool.end();
});

async function registerUser(tag = 'user') {
  const email = uniqueEmail(tag);
  createdEmails.push(email);
  const c = createClient(srv.base);
  const r = await c.post('/auth/register', { email: `  ${email}  `, password: PASSWORD });
  assert.equal(r.status, 201, JSON.stringify(r.json));
  return { email, c, user: r.json.user };
}

const jtiOf = (client) => jwt.decode(client.cookie.split('=')[1]).jti;

// ------------------------------- /auth -------------------------------

test('registro -> /auth/me -> logout -> la misma cookie devuelve 401', async () => {
  const { email, c, user } = await registerUser();
  assert.equal(user.email, email.toLowerCase());
  assert.equal(user.role, 'user');
  assert.ok(!('password_hash' in user));

  const me = await c.get('/auth/me');
  assert.equal(me.status, 200);
  assert.deepEqual(Object.keys(me.json.user).sort(), ['created_at', 'email', 'id', 'role']);
  assert.equal(me.json.user.id, user.id);

  const savedCookie = c.cookie;
  const out = await c.post('/auth/logout');
  assert.equal(out.status, 200);
  assert.ok(out.setCookie.some((s) => s.startsWith(`${config.cookieName}=;`)), 'debe limpiar la cookie');

  // Reutilizar exactamente la misma cookie robada/antigua
  const replay = createClient(srv.base);
  replay.cookie = savedCookie;
  const r = await replay.get('/auth/me');
  assert.equal(r.status, 401);
  assert.ok(r.setCookie.some((s) => s.startsWith(`${config.cookieName}=;`)), '401 por revocación limpia la cookie');

  const jti = jwt.decode(savedCookie.split('=')[1]).jti;
  assert.equal((await query('SELECT 1 FROM revoked_tokens WHERE jti = $1', [jti])).rowCount, 1);
  assert.equal((await query('SELECT 1 FROM user_sessions WHERE jti = $1', [jti])).rowCount, 0);
  const log = await query(`SELECT detail FROM access_logs WHERE owner_id = $1 AND event = 'SESSION_REVOKED'`, [user.id]);
  assert.equal(log.rowCount, 1);
});

test('registro: cookie HttpOnly + SameSite=Strict, user_metrics inicializado, hash bcrypt costo 12', async () => {
  const { c, user } = await registerUser();
  const sc = c.lastSetCookie[0];
  assert.match(sc, /HttpOnly/i);
  assert.match(sc, /SameSite=Strict/i);
  assert.match(sc, new RegExp(`^${config.cookieName}=`));
  assert.ok(!/Secure/i.test(sc), 'Secure solo en producción');

  assert.equal((await query('SELECT 1 FROM user_metrics WHERE owner_id = $1', [user.id])).rowCount, 1);
  assert.equal((await query('SELECT 1 FROM user_sessions WHERE user_id = $1', [user.id])).rowCount, 1);
  const { password_hash } = (await query('SELECT password_hash FROM users WHERE id = $1', [user.id])).rows[0];
  assert.match(password_hash, /^\$2[aby]\$12\$/);
  assert.ok(!password_hash.includes(PASSWORD));
  // Ningún log contiene la contraseña
  const logs = await query('SELECT detail::text AS d FROM access_logs WHERE owner_id = $1', [user.id]);
  assert.ok(logs.rows.every((r) => !r.d.includes(PASSWORD)));
});

test('registro: validaciones (correo, contraseña corta/larga, tipos) y duplicado 409 (sin importar mayúsculas)', async () => {
  const c = createClient(srv.base);
  for (const body of [
    { email: 'no-es-correo', password: PASSWORD },
    { email: '', password: PASSWORD },
    { email: 123, password: PASSWORD },
    { email: uniqueEmail(), password: '1234567' },
    { email: uniqueEmail(), password: 12345678 },
    { email: uniqueEmail(), password: 'x'.repeat(73) },
    { email: `${'a'.repeat(252)}@x.co`, password: PASSWORD },
    {},
  ]) {
    const r = await c.post('/auth/register', body);
    assert.equal(r.status, 400, JSON.stringify(body).slice(0, 80));
  }
  const { email } = await registerUser('dup');
  const dup = await c.post('/auth/register', { email: email.toUpperCase(), password: PASSWORD });
  assert.equal(dup.status, 409);
  assert.equal(c.cookie, null, 'no emite cookie en 409');
});

test('login: contraseña incorrecta y correo inexistente devuelven el mismo error genérico', async () => {
  const { email } = await registerUser();
  const c = createClient(srv.base);
  const wrongPass = await c.post('/auth/login', { email, password: 'otra-contraseña-1' });
  const noUser = await c.post('/auth/login', { email: uniqueEmail('ghost'), password: PASSWORD });
  const badShape = await c.post('/auth/login', { email: 5, password: null });
  for (const r of [wrongPass, noUser, badShape]) {
    assert.equal(r.status, 401);
    assert.deepEqual(r.json, { error: 'Credenciales inválidas' });
    assert.equal(r.setCookie.length, 0);
  }
});

test('login correcto: normaliza correo, registra sesión con IP y User-Agent, emite cookie', async () => {
  const { email, user } = await registerUser();
  const c = createClient(srv.base, 'Mozilla/5.0 (TestPhone)');
  const r = await c.post('/auth/login', { email: `  ${email.toUpperCase()} `, password: PASSWORD });
  assert.equal(r.status, 200);
  assert.equal(r.json.user.id, user.id);
  const s = await query('SELECT * FROM user_sessions WHERE jti = $1', [jtiOf(c)]);
  assert.equal(s.rows[0].user_agent, 'Mozilla/5.0 (TestPhone)');
  assert.ok(s.rows[0].ip);
  assert.ok(new Date(s.rows[0].expires_at) > new Date());
  assert.equal((await c.get('/auth/me')).status, 200);
});

test('middleware: sin cookie, JWT manipulado, otro algoritmo, expirado o usuario inexistente -> 401', async () => {
  const { user, c } = await registerUser();
  assert.equal((await createClient(srv.base).get('/auth/me')).status, 401);

  const good = c.cookie.split('=')[1];
  const mk = (cookie) => { const x = createClient(srv.base); x.cookie = `${config.cookieName}=${cookie}`; return x.get('/auth/me'); };

  assert.equal((await mk(good.slice(0, -2) + 'xx')).status, 401); // firma alterada
  assert.equal((await mk('no.es.jwt')).status, 401);
  const jti = 'forjado-' + Date.now();
  // Otro algoritmo (HS512) con el secreto correcto: debe rechazarse
  assert.equal((await mk(jwt.sign({ sub: user.id, jti }, config.jwt.secret, { algorithm: 'HS512' }))).status, 401);
  // alg=none
  const none = Buffer.from(JSON.stringify({ alg: 'none', typ: 'JWT' })).toString('base64url') + '.' +
    Buffer.from(JSON.stringify({ sub: user.id, jti })).toString('base64url') + '.';
  assert.equal((await mk(none)).status, 401);
  // Expirado
  assert.equal((await mk(jwt.sign({ sub: user.id, jti, exp: Math.floor(Date.now() / 1000) - 10 }, config.jwt.secret, { algorithm: 'HS256' }))).status, 401);
  // Firma válida pero usuario inexistente / sub no UUID
  assert.equal((await mk(jwt.sign({ sub: '00000000-0000-4000-8000-000000000000', jti }, config.jwt.secret, { algorithm: 'HS256', expiresIn: 60 }))).status, 401);
  assert.equal((await mk(jwt.sign({ sub: "1' OR '1'='1", jti }, config.jwt.secret, { algorithm: 'HS256', expiresIn: 60 }))).status, 401);
  // El JWT NO se acepta por header Authorization ni query
  const viaHeader = await fetch(`${srv.base}/auth/me`, { headers: { Authorization: `Bearer ${good}` } });
  assert.equal(viaHeader.status, 401);
  assert.equal((await fetch(`${srv.base}/auth/me?token=${good}`)).status, 401);
  // La cookie buena sigue funcionando
  assert.equal((await mk(good)).status, 200);
});

// ------------------------------ /security ------------------------------

test('dos dispositivos: sesiones listadas con current; revocar una invalida solo esa; kill-switch invalida todas', async () => {
  const { email, c: phone } = await registerUser('multi');
  const laptop = createClient(srv.base, 'Laptop-UA');
  assert.equal((await laptop.post('/auth/login', { email, password: PASSWORD })).status, 200);
  const tablet = createClient(srv.base, 'Tablet-UA');
  assert.equal((await tablet.post('/auth/login', { email, password: PASSWORD })).status, 200);

  const list = await phone.get('/security/sessions');
  assert.equal(list.status, 200);
  assert.equal(list.json.sessions.length, 3);
  const phoneJti = jtiOf(phone);
  const cur = list.json.sessions.filter((s) => s.current);
  assert.equal(cur.length, 1);
  assert.equal(cur[0].jti, phoneJti);
  const lap = (await laptop.get('/security/sessions')).json.sessions.find((s) => s.current);
  assert.equal(lap.jti, jtiOf(laptop));
  assert.equal(lap.user_agent, 'Laptop-UA');

  // Revocar solo la del laptop desde el teléfono
  const laptopJti = jtiOf(laptop);
  const del = await phone.del(`/security/sessions/${laptopJti}`);
  assert.equal(del.status, 200);
  assert.equal(del.json.current, false);
  assert.equal((await laptop.get('/auth/me')).status, 401);
  assert.equal((await phone.get('/auth/me')).status, 200);
  assert.equal((await tablet.get('/auth/me')).status, 200);
  assert.equal((await phone.get('/security/sessions')).json.sessions.length, 2);
  // revocar de nuevo -> 404
  assert.equal((await phone.del(`/security/sessions/${laptopJti}`)).status, 404);

  // Kill-switch desde la tablet: invalida todas inmediatamente (incluida la propia)
  const ks = await tablet.post('/security/kill-switch');
  assert.equal(ks.status, 200);
  assert.ok(ks.setCookie.some((s) => s.startsWith(`${config.cookieName}=;`)));
  const phoneCookie = phone.cookie;
  assert.equal((await phone.get('/auth/me')).status, 401);
  const tabletReplay = createClient(srv.base); // simula cookie robada de la tablet
  tabletReplay.cookie = `${config.cookieName}=${jwt.sign({ sub: 'x' }, 'x')}`; // basura: 401 igualmente
  assert.equal((await tabletReplay.get('/auth/me')).status, 401);
  const { rows } = await query('SELECT count(*)::int AS n FROM user_sessions WHERE user_id = (SELECT id FROM users WHERE lower(email)=$1)', [email.toLowerCase()]);
  assert.equal(rows[0].n, 0);
  assert.ok(phoneCookie);
  const ev = await query(`SELECT detail FROM access_logs WHERE event = 'SESSION_REVOKED' AND detail->>'scope' = 'all' AND owner_id = (SELECT id FROM users WHERE lower(email)=$1)`, [email.toLowerCase()]);
  assert.equal(ev.rowCount, 1);

  // Tras kill-switch se puede volver a iniciar sesión con sesión nueva
  const again = createClient(srv.base);
  assert.equal((await again.post('/auth/login', { email, password: PASSWORD })).status, 200);
  assert.equal((await again.get('/auth/me')).status, 200);
});

test('revocar la propia sesión actual limpia la cookie', async () => {
  const { c } = await registerUser();
  const old = c.cookie;
  const r = await c.del(`/security/sessions/${jtiOf(c)}`);
  assert.equal(r.status, 200);
  assert.equal(r.json.current, true);
  assert.ok(r.setCookie.some((s) => s.startsWith(`${config.cookieName}=;`)));
  const replay = createClient(srv.base);
  replay.cookie = old;
  assert.equal((await replay.get('/auth/me')).status, 401);
});

test('anti-IDOR: el usuario B no puede revocar la sesión (jti) del usuario A', async () => {
  const a = await registerUser('victim');
  const b = await registerUser('attacker');
  const jtiA = jtiOf(a.c);

  const r = await b.c.del(`/security/sessions/${jtiA}`);
  assert.equal(r.status, 404); // indistinguible de "no existe"
  assert.equal((await a.c.get('/auth/me')).status, 200, 'la sesión de A sigue viva');
  assert.equal((await query('SELECT 1 FROM revoked_tokens WHERE jti = $1', [jtiA])).rowCount, 0);
  assert.equal((await query('SELECT 1 FROM user_sessions WHERE jti = $1', [jtiA])).rowCount, 1);
  assert.equal((await b.c.get('/auth/me')).status, 200, 'B conserva su sesión');

  // B no ve sesiones de A en su listado y el kill-switch de B no afecta a A
  const listB = (await b.c.get('/security/sessions')).json.sessions;
  assert.ok(listB.every((s) => s.jti !== jtiA));
  assert.equal((await b.c.post('/security/kill-switch')).status, 200);
  assert.equal((await a.c.get('/auth/me')).status, 200);

  // Intentos con ids raros no producen 500
  const b2 = createClient(srv.base);
  await b2.post('/auth/login', { email: b.email, password: PASSWORD });
  for (const bad of ["x'; DROP TABLE user_sessions; --", 'a'.repeat(200), '%00']) {
    const x = await b2.del(`/security/sessions/${encodeURIComponent(bad)}`);
    assert.equal(x.status, 404);
  }
  assert.equal((await query('SELECT to_regclass($1) AS t', ['user_sessions'])).rows[0].t, 'user_sessions');
});

test('endpoints /security exigen autenticación', async () => {
  const c = createClient(srv.base);
  assert.equal((await c.get('/security/sessions')).status, 401);
  assert.equal((await c.del('/security/sessions/abc')).status, 401);
  assert.equal((await c.post('/security/kill-switch')).status, 401);
  assert.equal((await c.post('/auth/logout')).status, 401);
});

test('sesiones expiradas no aparecen en el listado', async () => {
  const { c, user } = await registerUser();
  await query(
    `INSERT INTO user_sessions (jti, user_id, expires_at) VALUES ($1, $2, now() - interval '1 hour')`,
    ['expirada-' + Date.now(), user.id],
  );
  const list = await c.get('/security/sessions');
  assert.equal(list.json.sessions.length, 1);
});
