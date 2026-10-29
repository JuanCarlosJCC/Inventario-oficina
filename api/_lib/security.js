'use strict';
// Utilidades de seguridad: contraseñas con hash, sesión firmada, cookies,
// límite de intentos y comprobaciones de origen. Sin dependencias externas.

const crypto = require('crypto');
const { promisify } = require('util');

const scrypt = promisify(crypto.scrypt);

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };
const SESSION_COOKIE = 'sici_session';
const SESSION_SECONDS = 12 * 60 * 60; // 12 horas

// ── Contraseñas ──────────────────────────────────────────────────────────

async function hashPassword(plain) {
  const salt = crypto.randomBytes(16);
  const key = await scrypt(String(plain), salt, SCRYPT.keylen, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p });
  return ['scrypt', SCRYPT.N, SCRYPT.r, SCRYPT.p, salt.toString('base64'), key.toString('base64')].join('$');
}

function safeEqual(a, b) {
  const ba = Buffer.from(a);
  const bb = Buffer.from(b);
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

// Devuelve { ok, needsUpgrade }. Una contraseña guardada en texto plano (formato
// antiguo) todavía se acepta una vez, y el llamador la reemplaza por su hash.
async function verifyPassword(plain, stored) {
  plain = String(plain || '');
  if (typeof stored !== 'string' || !stored) return { ok: false, needsUpgrade: false };
  if (stored.startsWith('scrypt$')) {
    const parts = stored.split('$');
    if (parts.length !== 6) return { ok: false, needsUpgrade: false };
    const [, N, r, p, saltB64, hashB64] = parts;
    const expected = Buffer.from(hashB64, 'base64');
    let key;
    try {
      key = await scrypt(plain, Buffer.from(saltB64, 'base64'), expected.length,
        { N: Number(N), r: Number(r), p: Number(p) });
    } catch (e) {
      return { ok: false, needsUpgrade: false };
    }
    return { ok: key.length === expected.length && crypto.timingSafeEqual(key, expected), needsUpgrade: false };
  }
  // Texto plano heredado: se compara por resumen para no filtrar la longitud.
  const da = crypto.createHash('sha256').update(plain).digest('hex');
  const db = crypto.createHash('sha256').update(stored).digest('hex');
  const ok = safeEqual(da, db);
  return { ok, needsUpgrade: ok };
}

let dummyHash = null;
// Para que un usuario inexistente tarde lo mismo que uno existente.
async function burnTime(plain) {
  if (!dummyHash) dummyHash = await hashPassword('no-existe-' + crypto.randomBytes(8).toString('hex'));
  await verifyPassword(plain, dummyHash);
}

// ── Sesión firmada ───────────────────────────────────────────────────────

function secret() {
  const s = process.env.SESSION_SECRET || '';
  if (s.length < 32) throw new Error('SESSION_SECRET falta o es demasiado corto (mínimo 32 caracteres).');
  return s;
}

const b64u = (buf) => Buffer.from(buf).toString('base64url');

function signSession(userId, now = Date.now()) {
  const payload = b64u(JSON.stringify({ u: userId, e: Math.floor(now / 1000) + SESSION_SECONDS }));
  const mac = crypto.createHmac('sha256', secret()).update(payload).digest('base64url');
  return `${payload}.${mac}`;
}

// Devuelve el id del usuario o null.
function verifySession(token, now = Date.now()) {
  if (typeof token !== 'string' || token.length > 600) return null;
  const [payload, mac] = token.split('.');
  if (!payload || !mac) return null;
  const expected = crypto.createHmac('sha256', secret()).update(payload).digest('base64url');
  if (!safeEqual(mac, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
    if (!data || typeof data.u !== 'string' || typeof data.e !== 'number') return null;
    if (data.e * 1000 < now) return null;
    return data.u;
  } catch (e) {
    return null;
  }
}

// ── Cookies ──────────────────────────────────────────────────────────────

function parseCookies(header) {
  const out = {};
  String(header || '').split(';').forEach((part) => {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  });
  return out;
}

function sessionCookie(token, maxAge = SESSION_SECONDS) {
  const secure = process.env.COOKIE_INSECURE === '1' ? '' : '; Secure';
  return `${SESSION_COOKIE}=${token}; HttpOnly${secure}; SameSite=Strict; Path=/; Max-Age=${maxAge}`;
}

const clearCookie = () => sessionCookie('', 0);

// ── Límite de intentos (en memoria; frena fuerza bruta básica) ───────────

const attempts = new Map();
const WINDOW_MS = 15 * 60 * 1000;

function bucket(key, now) {
  const b = attempts.get(key);
  if (!b || now - b.first > WINDOW_MS) { const fresh = { count: 0, first: now }; attempts.set(key, fresh); return fresh; }
  return b;
}

function tooManyAttempts(ip, username, now = Date.now()) {
  if (attempts.size > 5000) attempts.clear();
  return bucket(`ip:${ip}`, now).count >= 30 || bucket(`iu:${ip}|${username}`, now).count >= 8;
}

function registerFailure(ip, username, now = Date.now()) {
  bucket(`ip:${ip}`, now).count++;
  bucket(`iu:${ip}|${username}`, now).count++;
}

function clearFailures(ip, username) {
  attempts.delete(`iu:${ip}|${username}`);
}

function resetAttempts() { attempts.clear(); }

// ── Peticiones ───────────────────────────────────────────────────────────

function clientIp(req) {
  const fwd = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return fwd || req.headers['x-real-ip'] || (req.socket && req.socket.remoteAddress) || 'desconocida';
}

function sendJson(res, status, obj, extraHeaders = {}) {
  const body = JSON.stringify(obj);
  res.statusCode = status;
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store');
  for (const [k, v] of Object.entries(extraHeaders)) res.setHeader(k, v);
  res.end(body);
}

async function readJson(req, limit = 40 * 1024) {
  if (req.body !== undefined && req.body !== null && typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return req.body;
  if (typeof req.body === 'string') return JSON.parse(req.body || '{}');
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limit) { const e = new Error('Cuerpo demasiado grande.'); e.status = 413; throw e; }
    chunks.push(chunk);
  }
  const text = Buffer.concat(chunks).toString('utf8');
  return text ? JSON.parse(text) : {};
}

// Defensa extra contra peticiones de otros sitios (además de SameSite=Strict).
function sameOrigin(req) {
  const origin = req.headers.origin;
  const host = req.headers['x-forwarded-host'] || req.headers.host;
  if (origin) {
    try { return new URL(origin).host === host; } catch (e) { return false; }
  }
  const site = req.headers['sec-fetch-site'];
  return !site || site === 'same-origin' || site === 'none';
}

function isJson(req) {
  return String(req.headers['content-type'] || '').split(';')[0].trim().toLowerCase() === 'application/json';
}

function audit(event, data) {
  // Un renglón JSON por acción: aparece en los registros de Vercel.
  console.log(JSON.stringify({ t: new Date().toISOString(), evento: event, ...data }));
}

module.exports = {
  SESSION_COOKIE, hashPassword, verifyPassword, burnTime, signSession, verifySession,
  parseCookies, sessionCookie, clearCookie, tooManyAttempts, registerFailure, clearFailures,
  resetAttempts, clientIp, sendJson, readJson, sameOrigin, isJson, audit,
};
