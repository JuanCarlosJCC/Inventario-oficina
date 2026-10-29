'use strict';

const A = require('./_lib/auth');
const S = require('./_lib/security');
const { handle, methodNotAllowed } = require('./_lib/http');

module.exports = handle(async (req, res) => {
  if (req.method !== 'POST') return methodNotAllowed(res, 'POST');
  if (!S.sameOrigin(req)) return S.sendJson(res, 403, { error: 'Petición no permitida desde otro sitio.' });
  const id = S.verifySession(S.parseCookies(req.headers.cookie)[S.SESSION_COOKIE]);
  if (id) A.forget(id);
  return S.sendJson(res, 200, { ok: true }, { 'Set-Cookie': S.clearCookie() });
});
