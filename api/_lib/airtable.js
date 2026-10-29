'use strict';
// Único lugar que habla con Airtable. La clave vive solo en variables de entorno
// del servidor; el navegador nunca la ve.

class AirtableError extends Error {
  constructor(status, detail) {
    super(`Airtable respondió ${status}`);
    this.status = status;
    this.detail = detail; // solo para los registros del servidor, nunca para el cliente
  }
}

function base() {
  const pat = process.env.AIRTABLE_PAT;
  const baseId = process.env.AIRTABLE_BASE_ID;
  if (!pat || !baseId) throw new Error('Faltan AIRTABLE_PAT o AIRTABLE_BASE_ID en el servidor.');
  return { pat, url: `${process.env.AIRTABLE_API_URL || 'https://api.airtable.com/v0'}/${baseId}` };
}

async function at(path, { method = 'GET', body } = {}) {
  const { pat, url } = base();
  const res = await fetch(`${url}/${path}`, {
    method,
    headers: { Authorization: `Bearer ${pat}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new AirtableError(res.status, (await res.text()).slice(0, 300));
  return res.json();
}

// Escapa un texto para usarlo dentro de comillas en filterByFormula.
const formulaText = (s) => String(s).replace(/\\/g, '\\\\').replace(/"/g, '\\"');

const enc = encodeURIComponent;

module.exports = { at, AirtableError, formulaText, enc };
