'use strict';
// Envoltorio común: errores inesperados se registran en el servidor y el cliente
// recibe un mensaje genérico (nunca detalles de Airtable ni de la configuración).

const S = require('./security');

function handle(fn) {
  return async (req, res) => {
    try {
      await fn(req, res);
    } catch (e) {
      if (e && e.status === 413) return S.sendJson(res, 413, { error: 'La petición es demasiado grande.' });
      if (e instanceof SyntaxError) return S.sendJson(res, 400, { error: 'JSON inválido.' });
      S.audit('error', { ruta: req.url, mensaje: String(e && e.message), detalle: e && e.detail });
      if (!res.headersSent) S.sendJson(res, 500, { error: 'Error del servidor. Intente de nuevo en un momento.' });
    }
  };
}

const methodNotAllowed = (res, allow) =>
  S.sendJson(res, 405, { error: 'Método no permitido.' }, { Allow: allow });

function query(req) {
  return new URL(req.url, 'http://local').searchParams;
}

module.exports = { handle, methodNotAllowed, query };
