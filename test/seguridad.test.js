'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const { setup, PAT, PRODUCTOS } = require('./helpers');

// ── Contraseñas y sesión ─────────────────────────────────────────────────

test('hash de contraseña: verifica, rechaza y no repite sal', async () => {
  process.env.SESSION_SECRET = 'x'.repeat(48);
  const S = require('../api/_lib/security');
  const h1 = await S.hashPassword('clave-correcta-1');
  const h2 = await S.hashPassword('clave-correcta-1');
  assert.notEqual(h1, h2);
  assert.ok(h1.startsWith('scrypt$'));
  assert.equal((await S.verifyPassword('clave-correcta-1', h1)).ok, true);
  assert.equal((await S.verifyPassword('otra', h1)).ok, false);
  // formato antiguo: texto plano se acepta UNA vez y pide migrar
  const legacy = await S.verifyPassword('abc12345', 'abc12345');
  assert.deepEqual(legacy, { ok: true, needsUpgrade: true });
  assert.equal((await S.verifyPassword('mala', 'abc12345')).ok, false);
  assert.equal((await S.verifyPassword('x', undefined)).ok, false);
});

test('sesión firmada: se rechaza si se altera, expira o no hay secreto', () => {
  process.env.SESSION_SECRET = 'x'.repeat(48);
  const S = require('../api/_lib/security');
  const tok = S.signSession('recAAAAAAAAAAAAAA');
  assert.equal(S.verifySession(tok), 'recAAAAAAAAAAAAAA');
  const [p, m] = tok.split('.');
  const forged = Buffer.from(JSON.stringify({ u: 'recBBBBBBBBBBBBBB', e: 9999999999 })).toString('base64url');
  assert.equal(S.verifySession(`${forged}.${m}`), null);
  assert.equal(S.verifySession(`${p}.${m.slice(0, -2)}xx`), null);
  assert.equal(S.verifySession(tok, Date.now() + 13 * 3600 * 1000), null);
  assert.equal(S.verifySession('basura'), null);
  assert.equal(S.verifySession(undefined), null);
  delete process.env.SESSION_SECRET;
  assert.throws(() => S.signSession('x'), /SESSION_SECRET/);
  process.env.SESSION_SECRET = 'x'.repeat(48);
});

// ── Inicio de sesión ─────────────────────────────────────────────────────

test('login correcto: cookie HttpOnly, sin contraseña en la respuesta, y migra el texto plano a hash', async () => {
  const t = await setup();
  try {
    const u = await t.addUser('andy', 'andy-clave-1', { nombre: 'Andy Vilca', rol: 'ADMIN_PRINCIPAL' });
    const r = await t.login('andy', 'andy-clave-1');
    assert.equal(r.status, 200);
    assert.equal(r.json.user.username, 'andy');
    assert.ok(!('password' in r.json.user));
    assert.ok(!r.text.includes('andy-clave-1'));
    const raw = r.headers.get('set-cookie');
    assert.match(raw, /HttpOnly/); assert.match(raw, /SameSite=Strict/);
    // la clave guardada ya es un hash
    assert.ok(t.db.usuarios.get(u.id).fields.password.startsWith('scrypt$'));
    // y sigue entrando con el hash
    assert.equal((await t.login('andy', 'andy-clave-1')).status, 200);
  } finally { t.close(); }
});

test('login fallido: mismo mensaje exista o no el usuario; sin cookie', async () => {
  const t = await setup();
  try {
    await t.addUser('andy', 'andy-clave-1', { hashed: true });
    const a = await t.login('andy', 'mala');
    const b = await t.login('fantasma', 'mala');
    assert.equal(a.status, 401); assert.equal(b.status, 401);
    assert.equal(a.json.error, b.json.error);
    assert.equal(a.cookie, null);
  } finally { t.close(); }
});

test('login: se bloquea tras demasiados intentos fallidos', async () => {
  const t = await setup();
  try {
    await t.addUser('andy', 'andy-clave-1', { hashed: true });
    for (let i = 0; i < 8; i++) assert.equal((await t.login('andy', 'mala' + i)).status, 401);
    const blocked = await t.login('andy', 'andy-clave-1'); // incluso con la clave buena
    assert.equal(blocked.status, 429);
  } finally { t.close(); }
});

test('login: usuario duplicado no entra; una fórmula maliciosa no devuelve a otro', async () => {
  const t = await setup();
  try {
    await t.addUser('andy', 'uno-12345', { hashed: true });
    await t.addUser('andy', 'dos-12345', { hashed: true });
    assert.equal((await t.login('andy', 'uno-12345')).status, 401);
    await t.addUser('leandro', 'leandro-123', { hashed: true });
    assert.equal((await t.login('x" OR 1=1 OR "', 'lo-que-sea')).status, 401);
    assert.equal((await t.login('leandro" OR {username}="andy', 'leandro-123')).status, 401);
  } finally { t.close(); }
});

// ── Acceso a los datos ───────────────────────────────────────────────────

test('sin sesión no se lee nada; cookie falsa o de usuario borrado tampoco', async () => {
  const t = await setup();
  try {
    const u = await t.addUser('andy', 'andy-clave-1', { hashed: true });
    assert.equal((await t.call('GET', `/api/records?table=${PRODUCTOS}`)).status, 401);
    assert.equal((await t.call('GET', '/api/usuarios')).status, 401);
    assert.equal((await t.call('GET', '/api/session')).status, 401);
    assert.equal((await t.call('GET', `/api/records?table=${PRODUCTOS}`, { cookie: 'sici_session=abc.def' })).status, 401);
    const { cookie } = await t.login('andy', 'andy-clave-1');
    assert.equal((await t.call('GET', '/api/session', { cookie })).status, 200);
    t.db.usuarios.delete(u.id); t.A.forgetAll();
    assert.equal((await t.call('GET', '/api/session', { cookie })).status, 401);
  } finally { t.close(); }
});

test('la tabla de usuarios no se alcanza por la ruta general', async () => {
  const t = await setup();
  try {
    await t.addUser('andy', 'andy-clave-1', { hashed: true, rol: 'ADMIN_PRINCIPAL' });
    const { cookie } = await t.login('andy', 'andy-clave-1');
    assert.equal((await t.call('GET', '/api/records?table=usuarios', { cookie })).status, 400);
    assert.equal((await t.call('GET', '/api/records?table=../usuarios', { cookie })).status, 400);
    assert.equal((await t.call('POST', '/api/records', { cookie, body: { table: 'usuarios', fields: { username: 'x' } } })).status, 400);
  } finally { t.close(); }
});

test('permisos por tabla se aplican en el servidor', async () => {
  const t = await setup();
  try {
    await t.addUser('operador', 'operador-12', { hashed: true, rol: 'OPERADOR', permisos: { personal: true } });
    await t.addUser('sinpermisos', 'sinpermisos-1', { hashed: true, rol: 'OPERADOR', permisos: {} });
    const op = (await t.login('operador', 'operador-12')).cookie;
    const sp = (await t.login('sinpermisos', 'sinpermisos-1')).cookie;

    // puede leer todo
    assert.equal((await t.call('GET', '/api/records?table=series', { cookie: op })).status, 200);
    // puede escribir personal y productos (el permiso 'personal' devuelve stock)
    const nuevo = await t.call('POST', '/api/records', { cookie: op, body: { table: 'personal', fields: { nombre: 'Leandro Zamora' } } });
    assert.equal(nuevo.status, 200);
    assert.equal((await t.call('POST', '/api/records', { cookie: op, body: { table: PRODUCTOS, fields: { producto: 'Mouse' } } })).status, 200);
    // pero no series/categorias (permiso 'productos') ni roles (solo admin)
    assert.equal((await t.call('POST', '/api/records', { cookie: op, body: { table: 'series', fields: { nombre: 'X' } } })).status, 403);
    assert.equal((await t.call('POST', '/api/records', { cookie: op, body: { table: 'roles', fields: { nombre: 'JEFE' } } })).status, 403);
    // sin permisos: puede mirar pero no escribir nada
    assert.equal((await t.call('GET', `/api/records?table=${PRODUCTOS}`, { cookie: sp })).status, 200);
    assert.equal((await t.call('POST', '/api/records', { cookie: sp, body: { table: 'personal', fields: { nombre: 'Z' } } })).status, 403);
    assert.equal((await t.call('DELETE', `/api/records?table=personal&id=${nuevo.json.id}`, { cookie: sp })).status, 403);
    // borrar con permiso sí
    assert.equal((await t.call('DELETE', `/api/records?table=personal&id=${nuevo.json.id}`, { cookie: op })).status, 200);
  } finally { t.close(); }
});

test('un registro mal formado o campos raros se rechazan', async () => {
  const t = await setup();
  try {
    await t.addUser('andy', 'andy-clave-1', { hashed: true, rol: 'ADMIN_PRINCIPAL' });
    const { cookie } = await t.login('andy', 'andy-clave-1');
    assert.equal((await t.call('PATCH', '/api/records', { cookie, body: { table: 'personal', id: '../x', fields: { a: 1 } } })).status, 400);
    assert.equal((await t.call('POST', '/api/records', { cookie, body: { table: 'personal', fields: [] } })).status, 400);
    assert.equal((await t.call('POST', '/api/records', { cookie, body: { table: 'personal', fields: {} } })).status, 400);
    assert.equal((await t.call('GET', '/api/records?table=personal&offset=../../x', { cookie })).status, 400);
  } finally { t.close(); }
});

test('la paginación de Airtable llega completa', async () => {
  const t = await setup({ pageSize: 3 });
  try {
    await t.addUser('andy', 'andy-clave-1', { hashed: true });
    const { cookie } = await t.login('andy', 'andy-clave-1');
    for (let i = 0; i < 7; i++) t.db.series.set('r' + i, { id: 'r' + i, fields: { nombre: 'S' + i } });
    let all = []; let offset = null;
    do {
      const r = await t.call('GET', `/api/records?table=series${offset ? `&offset=${offset}` : ''}`, { cookie });
      all = all.concat(r.json.records); offset = r.json.offset;
    } while (offset);
    assert.equal(all.length, 7);
  } finally { t.close(); }
});

// ── Cambios desde otros sitios ───────────────────────────────────────────

test('petición desde otro origen o sin JSON se rechaza', async () => {
  const t = await setup();
  try {
    await t.addUser('andy', 'andy-clave-1', { hashed: true, rol: 'ADMIN_PRINCIPAL' });
    const { cookie } = await t.login('andy', 'andy-clave-1');
    const body = { table: 'personal', fields: { nombre: 'X' } };
    assert.equal((await t.call('POST', '/api/records', { cookie, body, headers: { Origin: 'https://sitio-malo.example' } })).status, 403);
    assert.equal((await t.call('POST', '/api/records', { cookie, body, headers: { 'Content-Type': 'text/plain' } })).status, 415);
    assert.equal((await t.call('POST', '/api/records', { cookie, body, headers: { 'Sec-Fetch-Site': 'cross-site' } })).status, 403);
    assert.equal((await t.call('POST', '/api/login', { body: { username: 'andy', password: 'andy-clave-1' }, headers: { Origin: 'https://sitio-malo.example' } })).status, 403);
  } finally { t.close(); }
});

// ── Usuarios ─────────────────────────────────────────────────────────────

test('solo el administrador gestiona usuarios; los demás ven una lista vacía', async () => {
  const t = await setup();
  try {
    await t.addUser('andy', 'andy-clave-1', { hashed: true, rol: 'ADMIN_PRINCIPAL' });
    await t.addUser('leandro', 'leandro-123', { hashed: true, rol: 'OPERADOR' });
    const leandro = (await t.login('leandro', 'leandro-123')).cookie;
    assert.deepEqual((await t.call('GET', '/api/usuarios', { cookie: leandro })).json, { records: [] });
    const crear = await t.call('POST', '/api/usuarios', { cookie: leandro, body: { fields: { username: 'intruso', password: 'intruso-123', nombre: 'I', rol: 'ADMIN_PRINCIPAL' } } });
    assert.equal(crear.status, 403);
    assert.equal(t.db.usuarios.size, 2);
    // un operador no puede hacerse administrador editándose
    const mid = [...t.db.usuarios.values()].find((r) => r.fields.username === 'leandro').id;
    assert.equal((await t.call('PATCH', '/api/usuarios', { cookie: leandro, body: { id: mid, fields: { rol: 'ADMIN_PRINCIPAL' } } })).status, 403);
    assert.equal(t.db.usuarios.get(mid).fields.rol, 'OPERADOR');
  } finally { t.close(); }
});

test('el administrador crea, edita y borra; las contraseñas nunca salen', async () => {
  const t = await setup();
  try {
    const andy = await t.addUser('andy', 'andy-clave-1', { hashed: true, rol: 'ADMIN_PRINCIPAL' });
    const { cookie } = await t.login('andy', 'andy-clave-1');

    const lista0 = await t.call('GET', '/api/usuarios', { cookie });
    assert.equal(lista0.json.records.length, 1);
    assert.ok(!lista0.text.includes('scrypt')); assert.ok(!lista0.text.includes('password'));

    assert.equal((await t.call('POST', '/api/usuarios', { cookie, body: { fields: { username: 'ab', password: 'larga-12345', nombre: 'X', rol: 'OPERADOR' } } })).status, 400);
    assert.equal((await t.call('POST', '/api/usuarios', { cookie, body: { fields: { username: 'nuevo', password: 'corta', nombre: 'X', rol: 'OPERADOR' } } })).status, 400);
    const ok = await t.call('POST', '/api/usuarios', { cookie, body: { fields: { username: 'nuevo', password: 'larga-12345', nombre: 'Nuevo', rol: 'OPERADOR', permisos: JSON.stringify({ personal: true, hackeo: true }) } } });
    assert.equal(ok.status, 200);
    assert.ok(!ok.text.includes('larga-12345'));
    const guardado = t.db.usuarios.get(ok.json.id).fields;
    assert.ok(guardado.password.startsWith('scrypt$'));
    assert.deepEqual(JSON.parse(guardado.permisos), { asignar: false, productos: false, deshabilitados: false, personal: true });
    assert.equal((await t.call('POST', '/api/usuarios', { cookie, body: { fields: { username: 'nuevo', password: 'larga-12345', nombre: 'Otro', rol: 'OPERADOR' } } })).status, 409);

    // editar sin contraseña la conserva; con contraseña la cambia
    const antes = guardado.password;
    assert.equal((await t.call('PATCH', '/api/usuarios', { cookie, body: { id: ok.json.id, fields: { nombre: 'Nuevo 2', password: '' } } })).status, 200);
    assert.equal(t.db.usuarios.get(ok.json.id).fields.password, antes);
    assert.equal((await t.call('PATCH', '/api/usuarios', { cookie, body: { id: ok.json.id, fields: { password: 'otra-clave-99' } } })).status, 200);
    assert.notEqual(t.db.usuarios.get(ok.json.id).fields.password, antes);
    assert.equal((await t.login('nuevo', 'otra-clave-99')).status, 200);
    assert.equal((await t.login('nuevo', 'larga-12345')).status, 401);

    // protecciones
    assert.equal((await t.call('DELETE', `/api/usuarios?id=${andy.id}`, { cookie })).status, 400);
    assert.equal((await t.call('PATCH', '/api/usuarios', { cookie, body: { id: andy.id, fields: { rol: 'OPERADOR' } } })).status, 409);
    assert.equal((await t.call('DELETE', `/api/usuarios?id=${ok.json.id}`, { cookie })).status, 200);
    assert.equal(t.db.usuarios.size, 1);
  } finally { t.close(); }
});

test('al borrar a un usuario su sesión deja de valer', async () => {
  const t = await setup();
  try {
    await t.addUser('andy', 'andy-clave-1', { hashed: true, rol: 'ADMIN_PRINCIPAL' });
    const u2 = await t.addUser('leandro', 'leandro-123', { hashed: true });
    const admin = (await t.login('andy', 'andy-clave-1')).cookie;
    const leandro = (await t.login('leandro', 'leandro-123')).cookie;
    assert.equal((await t.call('GET', '/api/session', { cookie: leandro })).status, 200);
    assert.equal((await t.call('DELETE', `/api/usuarios?id=${u2.id}`, { cookie: admin })).status, 200);
    assert.equal((await t.call('GET', '/api/session', { cookie: leandro })).status, 401);
  } finally { t.close(); }
});

test('la clave de Airtable no aparece en ninguna respuesta', async () => {
  const t = await setup();
  try {
    await t.addUser('andy', 'andy-clave-1', { hashed: true, rol: 'ADMIN_PRINCIPAL' });
    const r1 = await t.login('andy', 'andy-clave-1');
    const rutas = ['/api/session', `/api/records?table=${PRODUCTOS}`, '/api/usuarios', '/api/records?table=zzz', '/api/nada'];
    const todo = [r1.text, JSON.stringify([...r1.headers])];
    for (const p of rutas) { const r = await t.call('GET', p, { cookie: r1.cookie }); todo.push(r.text, JSON.stringify([...r.headers])); }
    assert.ok(!todo.join('\n').includes(PAT));
    assert.ok(!todo.join('\n').includes('patTEST'));
  } finally { t.close(); }
});

test('un fallo de Airtable no filtra detalles al cliente', async () => {
  const t = await setup();
  try {
    await t.addUser('andy', 'andy-clave-1', { hashed: true, rol: 'ADMIN_PRINCIPAL' });
    const { cookie } = await t.login('andy', 'andy-clave-1');
    process.env.AIRTABLE_PAT = 'clave-mala'; // simula clave revocada
    const r = await t.call('GET', `/api/records?table=${PRODUCTOS}`, { cookie });
    assert.equal(r.status, 500);
    assert.ok(!r.text.includes('AUTHENTICATION'));
    assert.ok(!r.text.includes('clave-mala'));
    process.env.AIRTABLE_PAT = PAT;
  } finally { t.close(); }
});
