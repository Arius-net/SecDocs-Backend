import './env.js';
import crypto from 'node:crypto';

/** Levanta la app en un puerto efímero. Devuelve { base, close }. */
export async function startServer() {
  const { createApp } = await import('../../src/app.js');
  const server = createApp().listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  return {
    base: `http://127.0.0.1:${server.address().port}/api/v1`,
    close: () => new Promise((r) => server.close(r)),
  };
}

/** Cliente HTTP con "cookie jar" propio (simula un dispositivo). */
export function createClient(base, userAgent = 'test-device') {
  let cookie = null; // "name=value"
  const client = {
    get cookie() { return cookie; },
    set cookie(v) { cookie = v; },
    lastSetCookie: [],
    async request(method, path, body, rawInit) {
      const headers = { 'User-Agent': userAgent };
      if (body !== undefined && !rawInit) headers['Content-Type'] = 'application/json';
      if (cookie) headers.Cookie = cookie;
      const res = await fetch(base + path, {
        method,
        headers,
        body: rawInit ? rawInit.body : body === undefined ? undefined : JSON.stringify(body),
        redirect: 'manual',
      });
      const set = res.headers.getSetCookie();
      client.lastSetCookie = set;
      for (const c of set) {
        const [pair] = c.split(';');
        const [name, value] = pair.split('=');
        if (value === '' ) { if (cookie?.startsWith(name + '=')) cookie = null; } else cookie = pair;
      }
      let json = null;
      try { json = await res.json(); } catch { /* sin cuerpo */ }
      return { status: res.status, json, headers: res.headers, setCookie: set };
    },
    get: (p) => client.request('GET', p),
    post: (p, b) => client.request('POST', p, b ?? {}),
    patch: (p, b) => client.request('PATCH', p, b ?? {}),
    del: (p) => client.request('DELETE', p),
    /** Sube un archivo multipart (campo `file`) declarando un Content-Type arbitrario. */
    upload(p, buffer, filename, declaredType = 'application/octet-stream') {
      const form = new FormData();
      form.append('file', new Blob([buffer], { type: declaredType }), filename);
      return client.request('POST', p, undefined, { body: form });
    },
  };
  return client;
}

export const uniqueEmail = (tag = 'u') => `${tag}-${crypto.randomUUID()}@Test.Local`;
