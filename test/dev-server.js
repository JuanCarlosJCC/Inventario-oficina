'use strict';
// Servidor LOCAL de pruebas: sirve index.html y /api/* con un Airtable simulado y
// datos de mentira. Aplica las mismas cabeceras que vercel.json. No se despliega.
//   node test/dev-server.js        (puerto 4173)

const http = require('http');
const fs = require('fs');
const path = require('path');
const { setup, PRODUCTOS } = require('./helpers');

const root = path.join(__dirname, '..');
const vercel = JSON.parse(fs.readFileSync(path.join(root, 'vercel.json'), 'utf8'));
const globalHeaders = vercel.headers[0].headers;

(async () => {
  const t = await setup();
  await t.addUser('andy', 'andy-clave-123', { nombre: 'Andy Vilca', rol: 'ADMIN_PRINCIPAL' }); // texto plano heredado
  await t.addUser('operador', 'operador-123', { hashed: true, nombre: 'Operador Prueba', rol: 'OPERADOR', permisos: { personal: true } });
  const seed = (table, fields) => { const id = 'rec' + Math.random().toString(36).slice(2, 16).padEnd(14, '0').slice(0, 14); t.db[table].set(id, { id, fields }); return id; };
  ['OPERADOR', 'ADMINISTRADOR', 'ADMIN_PRINCIPAL'].forEach((n) => seed('roles', { nombre: n }));
  seed('categorias', { nombre: 'Equipos' }); seed('cargos', { nombre: 'Analista' }); seed('series', { nombre: 'SN-A' });
  seed('personal', { nombre: 'Persona de Prueba', cargo: 'Analista' });
  seed(PRODUCTOS, { sku: 'EQ-001', categoria: 'Equipos', producto: 'Mouse', cantidad: 5, activo: true });

  const port = Number(process.env.PORT || 4173);
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    if (url.pathname.startsWith('/api/')) {
      const name = url.pathname.replace(/^\/api\//, '');
      let handler;
      try { handler = require(path.join(root, 'api', `${name}.js`)); } catch (e) { res.statusCode = 404; return res.end('{}'); }
      return handler(req, res);
    }
    for (const h of globalHeaders) res.setHeader(h.key, h.value);
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.end(fs.readFileSync(path.join(root, 'index.html')));
  });
  server.listen(port, '127.0.0.1', () => console.log(`LISTO http://127.0.0.1:${port}`));
  process.on('SIGTERM', () => { server.close(); t.close(); process.exit(0); });
  global.__db = t.db; global.__calls = t.mock.calls;
  // Para inspección desde las pruebas del navegador:
  http.createServer((req, res) => {
    res.setHeader('Content-Type', 'application/json');
    const u = [...t.db.usuarios.values()].map((r) => ({ username: r.fields.username, hashed: String(r.fields.password).startsWith('scrypt$') }));
    res.end(JSON.stringify({ usuarios: u, llamadasAirtable: t.mock.calls.length }));
  }).listen(port + 1, '127.0.0.1');
})();
