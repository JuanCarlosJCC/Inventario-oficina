'use strict';

const A = require('./_lib/auth');
const S = require('./_lib/security');
const { handle, methodNotAllowed } = require('./_lib/http');

module.exports = handle(async (req, res) => {
  if (req.method !== 'GET') return methodNotAllowed(res, 'GET');
  const user = await A.requireUser(req, res);
  if (!user) return;
  return S.sendJson(res, 200, { user });
});
