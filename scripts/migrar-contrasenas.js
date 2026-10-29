'use strict';
// Cifra (hash) las contraseñas que todavía estén en texto plano en la tabla "usuarios".
// Es OPCIONAL: cada usuario se migra solo la primera vez que inicia sesión.
// Úselo si quiere dejar todo cifrado de una vez.
//
//   Simulacro (no cambia nada):  node scripts/migrar-contrasenas.js
//   Aplicar de verdad:           node scripts/migrar-contrasenas.js --aplicar
//
// Necesita AIRTABLE_PAT y AIRTABLE_BASE_ID en el entorno (la clave NUEVA).
// Nunca imprime contraseñas: solo cuántos usuarios tocó.

const { at, enc } = require('../api/_lib/airtable');
const S = require('../api/_lib/security');

(async () => {
  const aplicar = process.argv.includes('--aplicar');
  let records = []; let offset = null;
  do {
    const page = await at(`usuarios${offset ? `?offset=${enc(offset)}` : ''}`);
    records = records.concat(page.records || []); offset = page.offset;
  } while (offset);

  const pendientes = records.filter((r) => typeof r.fields.password === 'string' && r.fields.password && !r.fields.password.startsWith('scrypt$'));
  console.log(`Usuarios: ${records.length}. Con contraseña en texto plano: ${pendientes.length}.`);
  if (!aplicar) { console.log('Simulacro: no se cambió nada. Use --aplicar para cifrarlas.'); return; }

  for (const r of pendientes) {
    await at(`usuarios/${enc(r.id)}`, { method: 'PATCH', body: { fields: { password: await S.hashPassword(r.fields.password) } } });
    await new Promise((ok) => setTimeout(ok, 250)); // Airtable permite 5 peticiones por segundo
  }
  console.log(`Listo: ${pendientes.length} contraseñas cifradas.`);
})().catch((e) => { console.error('Error:', e.message); process.exit(1); });
