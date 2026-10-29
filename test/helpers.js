'use strict';
// Airtable simulado + servidor local que enruta /api/* a las mismas funciones
// que corren en Vercel. Así se prueba todo sin tocar datos reales.

const http = require('http');
const path = require('path');
const crypto = require('crypto');

const PAT = 'patTEST1234567890.fakefakefakefakefakefakefakefakefakefakefakefakefakefakefake';
const BASE = 'appTESTBASE12345';
const PRODUCTOS = 'tblVk5mf3H6GSSESU';
const rid = () => 'rec' + crypto.randomBytes(10).toString('hex').slice(0, 14);

function newDb() {
  const t = () => new Map();
  return { usuarios: t(), personal: t(), series: t(), categorias: t(), cargos: t(), roles: t(), [PRODUCTOS]: t() };
}

function startMockAirtable(db, { pageSize = 100 } = {}) {
  const calls = [];
  const server = http.createServer(async (req, res) => {
    const send = (status, obj) => { res.statusCode = status; res.setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(obj)); };
    if (req.headers.authorization !== `Bearer ${PAT}`) return send(401, { error: 'AUTHENTICATION_REQUIRED' });
    const url = new URL(req.url, 'http://x');
    const m = url.pathname.match(/^\/v0\/([^/]+)\/([^/]+)(?:\/([^/]+))?$/);
    if (!m || m[1] !== BASE) return send(404, { error: 'NOT_FOUND' });
    const table = decodeURIComponent(m[2]); const id = m[3] && decodeURIComponent(m[3]);
    const rows = db[table];
    if (!rows) return send(404, { error: 'TABLE_NOT_FOUND' });
    let body = '';
    for await (const c of req) body += c;
    const json = body ? JSON.parse(body) : {};
    calls.push({ method: req.method, table, id, body: json });

    if (req.method === 'GET' && !id) {
      let list = [...rows.values()];
      const formula = url.searchParams.get('filterByFormula');
      if (formula) {
        const f = formula.match(/^\{(\w+)\}="((?:[^"\\]|\\.)*)"$/);
        if (!f) return send(422, { error: 'INVALID_FILTER' });
        const want = f[2].replace(/\\(.)/g, '$1');
        list = list.filter((r) => r.fields[f[1]] === want);
      }
      const start = Number(url.searchParams.get('offset') || 0);
      const page = list.slice(start, start + pageSize);
      const out = { records: page };
      if (start + pageSize < list.length) out.offset = String(start + pageSize);
      return send(200, out);
    }
    if (req.method === 'GET') return rows.has(id) ? send(200, rows.get(id)) : send(404, { error: 'NOT_FOUND' });
    if (req.method === 'POST') { const r = { id: rid(), fields: json.fields || {} }; rows.set(r.id, r); return send(200, r); }
    if (req.method === 'PATCH') {
      if (!rows.has(id)) return send(404, { error: 'NOT_FOUND' });
      Object.assign(rows.get(id).fields, json.fields || {}); return send(200, rows.get(id));
    }
    if (req.method === 'DELETE') {
      if (!rows.has(id)) return send(404, { error: 'NOT_FOUND' });
      rows.delete(id); return send(200, { deleted: true, id });
    }
    return send(405, {});
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, calls, url: `http://127.0.0.1:${server.address().port}/v0` })));
}

function startApp() {
  const server = http.createServer((req, res) => {
    const name = new URL(req.url, 'http://x').pathname.replace(/^\/api\//, '');
    let handler;
    try { handler = require(path.join(__dirname, '..', 'api', `${name}.js`)); } catch (e) { res.statusCode = 404; return res.end('{}'); }
    handler(req, res);
  });
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => resolve({ server, url: `http://127.0.0.1:${server.address().port}` })));
}

async function setup(opts) {
  const db = newDb();
  const mock = await startMockAirtable(db, opts);
  process.env.AIRTABLE_PAT = PAT;
  process.env.AIRTABLE_BASE_ID = BASE;
  process.env.AIRTABLE_API_URL = mock.url;
  process.env.SESSION_SECRET = 'x'.repeat(48);
  process.env.COOKIE_INSECURE = '1';
  const app = await startApp();
  const S = require('../api/_lib/security');
  const A = require('../api/_lib/auth');
  S.resetAttempts(); A.forgetAll();

  const addUser = async (username, password, extra = {}) => {
    const r = { id: rid(), fields: { username, password: password === null ? undefined : (extra.hashed ? await S.hashPassword(password) : password), nombre: extra.nombre || username, rol: extra.rol || 'OPERADOR', permisos: JSON.stringify(extra.permisos || { asignar: true, productos: true, deshabilitados: true, personal: true }) } };
    db.usuarios.set(r.id, r);
    return r;
  };

  const call = async (method, p, { body, cookie, headers = {} } = {}) => {
    const res = await fetch(app.url + p, {
      method,
      headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}), ...headers },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    let json = null; const text = await res.text();
    try { json = JSON.parse(text); } catch (e) { /* vacío */ }
    return { status: res.status, json, text, headers: res.headers };
  };

  const login = async (username, password) => {
    const r = await call('POST', '/api/login', { body: { username, password } });
    const set = r.headers.get('set-cookie');
    return { ...r, cookie: set ? set.split(';')[0] : null };
  };

  const close = () => { mock.server.close(); app.server.close(); };
  return { db, mock, addUser, call, login, close, S, A, PAT, PRODUCTOS };
}

module.exports = { setup, PAT, PRODUCTOS };
