'use strict';

const { at, formulaText, enc } = require('./_lib/airtable');
const A = require('./_lib/auth');
const S = require('./_lib/security');
const { handle, methodNotAllowed } = require('./_lib/http');

const FALLO = 'Usuario o contraseña incorrectos.';

module.exports = handle(async (req, res) => {
  if (req.method !== 'POST') return methodNotAllowed(res, 'POST');
  if (!A.guardMutation(req, res)) return;

  const body = await S.readJson(req, 4 * 1024);
  const username = String((body && body.username) || '').trim();
  const password = String((body && body.password) || '').trim();
  if (!username || !password || username.length > 100 || password.length > 200) {
    return S.sendJson(res, 400, { error: 'Escriba usuario y contraseña.' });
  }

  const ip = S.clientIp(req);
  if (S.tooManyAttempts(ip, username)) {
    S.audit('login_bloqueado', { ip, usuario: username });
    return S.sendJson(res, 429, { error: 'Demasiados intentos. Espere unos minutos e intente de nuevo.' });
  }

  const found = await at(`usuarios?maxRecords=2&filterByFormula=${enc(`{username}="${formulaText(username)}"`)}`);
  const matches = (found.records || []).filter((r) => (r.fields || {}).username === username);

  // Si no existe (o hay dos iguales, algo raro) se gasta el mismo tiempo y se responde igual.
  if (matches.length !== 1) {
    await S.burnTime(password);
    S.registerFailure(ip, username);
    S.audit('login_fallido', { ip, usuario: username, motivo: matches.length ? 'duplicado' : 'no_existe' });
    return S.sendJson(res, 401, { error: FALLO });
  }

  const rec = matches[0];
  const check = await S.verifyPassword(password, rec.fields.password);
  if (!check.ok) {
    S.registerFailure(ip, username);
    S.audit('login_fallido', { ip, usuario: username, motivo: 'clave' });
    return S.sendJson(res, 401, { error: FALLO });
  }

  if (check.needsUpgrade) {
    // Primera vez que entra tras la migración: su clave en texto plano pasa a hash.
    try {
      await at(`usuarios/${enc(rec.id)}`, { method: 'PATCH', body: { fields: { password: await S.hashPassword(password) } } });
      S.audit('clave_migrada', { usuario: username });
    } catch (e) {
      S.audit('clave_no_migrada', { usuario: username, mensaje: String(e.message) });
    }
  }

  S.clearFailures(ip, username);
  A.forget(rec.id);
  const user = A.publicUser(rec);
  S.audit('login_ok', { ip, usuario: username, id: rec.id });
  return S.sendJson(res, 200, { user }, { 'Set-Cookie': S.sessionCookie(S.signSession(rec.id)) });
});
