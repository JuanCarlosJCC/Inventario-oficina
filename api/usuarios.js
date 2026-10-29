'use strict';
// Gestión de usuarios: SOLO ADMIN_PRINCIPAL. Las contraseñas se guardan con hash
// y nunca se envían de vuelta al navegador.

const { at, formulaText, enc } = require('./_lib/airtable');
const A = require('./_lib/auth');
const S = require('./_lib/security');
const { handle, methodNotAllowed, query } = require('./_lib/http');

const USERNAME = /^[A-Za-z0-9._@-]{3,60}$/;
const ROL = /^[A-Za-z0-9ÁÉÍÓÚÑáéíóúñ_ -]{1,40}$/;
const MIN_PASSWORD = 8;

const bad = (res, msg, status = 400) => { S.sendJson(res, status, { error: msg }); return false; };

async function listAll() {
  let records = []; let offset = null;
  do {
    const page = await at(`usuarios${offset ? `?offset=${enc(offset)}` : ''}`);
    records = records.concat(page.records || []);
    offset = page.offset;
  } while (offset);
  return records;
}

// Forma que ya espera la interfaz (parecida a Airtable) pero sin contraseña.
const shape = (rec) => {
  const u = A.publicUser(rec);
  return { id: rec.id, fields: { username: u.username, nombre: u.nombre, rol: u.rol, permisos: JSON.stringify(u.permisos) } };
};

function cleanPermisos(value) {
  const src = A.parsePermisos(value);
  const out = {};
  A.PERMISOS.forEach((k) => { out[k] = !!src[k]; });
  return JSON.stringify(out);
}

async function usernameTaken(username, exceptId) {
  const found = await at(`usuarios?maxRecords=5&filterByFormula=${enc(`{username}="${formulaText(username)}"`)}`);
  return (found.records || []).some((r) => (r.fields || {}).username === username && r.id !== exceptId);
}

const countAdmins = (records) => records.filter((r) => (r.fields || {}).rol === A.ADMIN).length;

module.exports = handle(async (req, res) => {
  const method = req.method;
  if (!['GET', 'POST', 'PATCH', 'DELETE'].includes(method)) return methodNotAllowed(res, 'GET, POST, PATCH, DELETE');
  if (method !== 'GET' && !A.guardMutation(req, res)) return;

  const me = await A.requireUser(req, res);
  if (!me) return;

  // Quien no es administrador recibe una lista vacía: la pestaña de usuarios no existe para él.
  if (method === 'GET') {
    if (me.rol !== A.ADMIN) return S.sendJson(res, 200, { records: [] });
    return S.sendJson(res, 200, { records: (await listAll()).map(shape) });
  }

  if (me.rol !== A.ADMIN) {
    S.audit('usuarios_denegado', { usuario: me.username, metodo: method });
    return S.sendJson(res, 403, { error: 'Solo el administrador principal puede gestionar usuarios.' });
  }

  if (method === 'POST') {
    const f = ((await S.readJson(req)) || {}).fields || {};
    const username = String(f.username || '').trim();
    const password = String(f.password || '').trim();
    const nombre = String(f.nombre || '').trim().slice(0, 80);
    const rol = String(f.rol || '').trim();
    if (!USERNAME.test(username)) return bad(res, 'El usuario debe tener entre 3 y 60 caracteres (letras, números, punto, guion o @).');
    if (password.length < MIN_PASSWORD) return bad(res, `La contraseña debe tener al menos ${MIN_PASSWORD} caracteres.`);
    if (!nombre) return bad(res, 'Escriba el nombre de la persona.');
    if (!ROL.test(rol)) return bad(res, 'Rol inválido.');
    if (await usernameTaken(username)) return bad(res, 'Ese usuario ya existe.', 409);
    const created = await at('usuarios', { method: 'POST', body: { fields: {
      username, nombre, rol, password: await S.hashPassword(password), permisos: cleanPermisos(f.permisos),
    } } });
    S.audit('usuario_creado', { por: me.username, nuevo: username, rol, id: created.id });
    return S.sendJson(res, 200, shape(created));
  }

  if (method === 'PATCH') {
    const body = (await S.readJson(req)) || {};
    const id = String(body.id || '');
    const f = body.fields || {};
    if (!A.RECORD_ID.test(id)) return bad(res, 'Usuario inválido.');
    const all = await listAll();
    const target = all.find((r) => r.id === id);
    if (!target) return bad(res, 'Ese usuario ya no existe.', 404);

    const fields = {};
    if (f.nombre !== undefined) {
      const nombre = String(f.nombre).trim().slice(0, 80);
      if (!nombre) return bad(res, 'Escriba el nombre de la persona.');
      fields.nombre = nombre;
    }
    if (f.username !== undefined && String(f.username).trim() !== target.fields.username) {
      const username = String(f.username).trim();
      if (!USERNAME.test(username)) return bad(res, 'El usuario debe tener entre 3 y 60 caracteres (letras, números, punto, guion o @).');
      if (await usernameTaken(username, id)) return bad(res, 'Ese usuario ya existe.', 409);
      fields.username = username;
    }
    if (f.rol !== undefined) {
      const rol = String(f.rol).trim();
      if (!ROL.test(rol)) return bad(res, 'Rol inválido.');
      if (target.fields.rol === A.ADMIN && rol !== A.ADMIN && countAdmins(all) <= 1) {
        return bad(res, 'Debe quedar al menos un administrador principal.', 409);
      }
      fields.rol = rol;
    }
    if (f.permisos !== undefined) fields.permisos = cleanPermisos(f.permisos);
    // Contraseña vacía = no cambiarla.
    if (f.password !== undefined && String(f.password).trim() !== '') {
      const password = String(f.password).trim();
      if (password.length < MIN_PASSWORD) return bad(res, `La contraseña debe tener al menos ${MIN_PASSWORD} caracteres.`);
      fields.password = await S.hashPassword(password);
    }
    if (!Object.keys(fields).length) return S.sendJson(res, 200, shape(target));

    const updated = await at(`usuarios/${enc(id)}`, { method: 'PATCH', body: { fields } });
    A.forget(id);
    S.audit('usuario_editado', { por: me.username, usuario: target.fields.username, id, campos: Object.keys(fields) });
    return S.sendJson(res, 200, shape(updated));
  }

  // DELETE
  const id = query(req).get('id') || '';
  if (!A.RECORD_ID.test(id)) return bad(res, 'Usuario inválido.');
  if (id === me.id) return bad(res, 'No puede eliminar su propio usuario.', 400);
  const all = await listAll();
  const target = all.find((r) => r.id === id);
  if (!target) return bad(res, 'Ese usuario ya no existe.', 404);
  if (target.fields.rol === A.ADMIN && countAdmins(all) <= 1) return bad(res, 'Debe quedar al menos un administrador principal.', 409);
  await at(`usuarios/${enc(id)}`, { method: 'DELETE' });
  A.forget(id);
  S.audit('usuario_eliminado', { por: me.username, usuario: target.fields.username, id });
  return S.sendJson(res, 200, { deleted: true, id });
});
