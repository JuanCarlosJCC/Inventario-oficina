'use strict';
// Lectura y escritura de las tablas del inventario. La tabla de usuarios NO pasa
// por aquí: tiene su propia ruta, solo para administradores.

const { at, enc } = require('./_lib/airtable');
const A = require('./_lib/auth');
const S = require('./_lib/security');
const { handle, methodNotAllowed, query } = require('./_lib/http');

const OFFSET = /^[A-Za-z0-9/_-]{1,100}$/;

function validTable(res, table) {
  if (!Object.prototype.hasOwnProperty.call(A.TABLAS, table)) {
    S.sendJson(res, 400, { error: 'Tabla no permitida.' });
    return false;
  }
  return true;
}

function validFields(res, fields) {
  const ok = fields && typeof fields === 'object' && !Array.isArray(fields)
    && Object.keys(fields).length > 0 && Object.keys(fields).length <= 40
    && Object.keys(fields).every((k) => k.length > 0 && k.length <= 60);
  if (!ok) S.sendJson(res, 400, { error: 'Datos inválidos.' });
  return ok;
}

module.exports = handle(async (req, res) => {
  const method = req.method;
  if (!['GET', 'POST', 'PATCH', 'DELETE'].includes(method)) return methodNotAllowed(res, 'GET, POST, PATCH, DELETE');
  if (method !== 'GET' && !A.guardMutation(req, res)) return;

  const user = await A.requireUser(req, res);
  if (!user) return;

  if (method === 'GET') {
    const q = query(req);
    const table = q.get('table') || '';
    if (!validTable(res, table)) return;
    const offset = q.get('offset');
    if (offset && !OFFSET.test(offset)) return S.sendJson(res, 400, { error: 'Desplazamiento inválido.' });
    const data = await at(`${enc(table)}${offset ? `?offset=${enc(offset)}` : ''}`);
    return S.sendJson(res, 200, data);
  }

  let table; let id; let fields;
  if (method === 'DELETE') {
    const q = query(req);
    table = q.get('table') || '';
    id = q.get('id') || '';
  } else {
    const body = await S.readJson(req);
    table = (body && body.table) || '';
    id = (body && body.id) || '';
    fields = body && body.fields;
  }

  if (!validTable(res, table)) return;
  if (!A.canWrite(user, table)) {
    S.audit('escritura_denegada', { usuario: user.username, tabla: table, metodo: method });
    return S.sendJson(res, 403, { error: 'No tiene permiso para esta acción.' });
  }
  if (method !== 'POST' && !A.RECORD_ID.test(id)) return S.sendJson(res, 400, { error: 'Registro inválido.' });

  let result;
  if (method === 'POST') {
    if (!validFields(res, fields)) return;
    result = await at(enc(table), { method: 'POST', body: { fields } });
    id = result.id;
  } else if (method === 'PATCH') {
    if (!validFields(res, fields)) return;
    result = await at(`${enc(table)}/${enc(id)}`, { method: 'PATCH', body: { fields } });
  } else {
    result = await at(`${enc(table)}/${enc(id)}`, { method: 'DELETE' });
  }

  S.audit('escritura', { usuario: user.username, tabla: table, metodo: method, registro: id,
    campos: fields ? Object.keys(fields) : undefined });
  return S.sendJson(res, 200, result);
});
