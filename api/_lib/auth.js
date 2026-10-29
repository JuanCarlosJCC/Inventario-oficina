'use strict';
// Quién hace la petición y qué puede hacer. Todo se decide aquí, en el servidor:
// el navegador solo muestra u oculta botones.

const { at, enc } = require('./airtable');
const S = require('./security');

const PRODUCTOS = 'tblVk5mf3H6GSSESU';
const ADMIN = 'ADMIN_PRINCIPAL';
const PERMISOS = ['asignar', 'productos', 'deshabilitados', 'personal'];

// Qué permiso hace falta para ESCRIBIR en cada tabla (leer lo puede todo usuario con sesión).
const TABLAS = {
  [PRODUCTOS]: { escribe: ['asignar', 'productos', 'deshabilitados', 'personal'] },
  personal: { escribe: ['personal'] },
  series: { escribe: ['productos'] },
  categorias: { escribe: ['productos'] },
  cargos: { escribe: ['personal'] },
  roles: { escribe: 'admin' },
};

const RECORD_ID = /^rec[A-Za-z0-9]{14}$/;

function parsePermisos(value) {
  if (value && typeof value === 'object') return value;
  if (typeof value === 'string') { try { const p = JSON.parse(value); return p && typeof p === 'object' ? p : {}; } catch (e) { return {}; } }
  return {};
}

// Registro de Airtable -> usuario SIN contraseña.
function publicUser(rec) {
  const f = rec.fields || {};
  return { id: rec.id, username: f.username || '', nombre: f.nombre || '', rol: f.rol || '', permisos: parsePermisos(f.permisos) };
}

// Caché corta: la interfaz pide 7 tablas a la vez y Airtable limita a 5 por segundo.
const cache = new Map();
const TTL_MS = 30 * 1000;

async function loadUser(id, now = Date.now()) {
  const hit = cache.get(id);
  if (hit && now - hit.at < TTL_MS) return hit.user;
  let user = null;
  try {
    user = publicUser(await at(`usuarios/${enc(id)}`));
  } catch (e) {
    if (!(e.status === 404 || e.status === 422)) throw e;
  }
  cache.set(id, { at: now, user });
  return user;
}

const forget = (id) => cache.delete(id);
const forgetAll = () => cache.clear();

function can(user, permission) {
  if (!user) return false;
  if (user.rol === ADMIN) return true;
  return !!(user.permisos && user.permisos[permission]);
}

function canWrite(user, table) {
  const rule = TABLAS[table];
  if (!rule) return false;
  if (rule.escribe === 'admin') return user.rol === ADMIN;
  return rule.escribe.some((p) => can(user, p));
}

// Devuelve el usuario con sesión válida, o responde 401 y devuelve null.
async function requireUser(req, res) {
  const token = S.parseCookies(req.headers.cookie)[S.SESSION_COOKIE];
  const id = S.verifySession(token);
  if (!id) { S.sendJson(res, 401, { error: 'Inicie sesión para continuar.' }); return null; }
  const user = await loadUser(id);
  if (!user) { S.sendJson(res, 401, { error: 'Su sesión ya no es válida. Inicie sesión de nuevo.' }, { 'Set-Cookie': S.clearCookie() }); return null; }
  return user;
}

// Pasos comunes de toda ruta que cambia datos: método, origen y tipo de contenido.
function guardMutation(req, res) {
  if (!S.sameOrigin(req)) { S.sendJson(res, 403, { error: 'Petición no permitida desde otro sitio.' }); return false; }
  // Un DELETE no lleva cuerpo; lo demás debe ser JSON.
  if (req.method !== 'DELETE' && !S.isJson(req)) { S.sendJson(res, 415, { error: 'El contenido debe ser JSON.' }); return false; }
  return true;
}

module.exports = {
  PRODUCTOS, ADMIN, PERMISOS, TABLAS, RECORD_ID, parsePermisos, publicUser,
  loadUser, forget, forgetAll, can, canWrite, requireUser, guardMutation,
};
