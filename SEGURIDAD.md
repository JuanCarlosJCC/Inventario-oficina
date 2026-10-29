# SICI — Seguridad y puesta en marcha

## Qué cambió

Antes, la página hablaba directamente con Airtable usando una clave escrita en el
código. Como el código es público, **cualquiera podía leer, cambiar o borrar todo**,
incluida la lista de usuarios con sus contraseñas, y entrar como quien quisiera.

Ahora:

| | Antes | Ahora |
|---|---|---|
| Clave de Airtable | En `index.html`, visible para todos | Solo en el servidor (variable privada de Vercel) |
| Quién comprueba la contraseña | El navegador de quien entra | El servidor |
| Contraseñas en Airtable | Texto plano | Cifradas (scrypt) |
| Contraseñas descargadas al navegador | Todas, antes de entrar | Nunca |
| Sesión | Texto editable en el navegador | Cookie firmada, `HttpOnly`, 12 horas |
| Permisos por pestaña | Solo ocultaban botones | Los verifica el servidor en cada acción |
| Quién hizo qué | No quedaba registro | Registro de auditoría en Vercel |

La interfaz se ve y funciona igual.

## Qué hace cada archivo

- `index.html` — la pantalla (sin ninguna clave).
- `api/login.js`, `logout.js`, `session.js` — entrar, salir y saber quién soy.
- `api/records.js` — lee y escribe productos, personal, series, categorías, cargos y roles, según permisos.
- `api/usuarios.js` — crear, editar y borrar usuarios (solo `ADMIN_PRINCIPAL`).
- `api/_lib/` — contraseñas, sesión, permisos y conexión con Airtable.
- `vercel.json` — cabeceras de seguridad del navegador.
- `test/` — 17 pruebas del servidor con un Airtable simulado (`npm test`).

## Permisos (los aplica el servidor)

| Tabla | Quién puede escribir |
|---|---|
| productos | quien tenga *asignar*, *productos*, *deshabilitados* o *personal* |
| personal, cargos | permiso *personal* |
| series, categorías | permiso *productos* |
| roles, usuarios | solo `ADMIN_PRINCIPAL` |

Todos los usuarios con sesión pueden **leer** el inventario. Solo el administrador
ve la lista de usuarios, y nunca recibe contraseñas. Siempre debe quedar al menos un
`ADMIN_PRINCIPAL`; nadie puede borrarse a sí mismo.

## Puesta en marcha (en este orden)

### 1. Revocar la clave vieja (si no lo hizo ya)
Airtable → *Developer hub* → *Personal access tokens* → borre el token que estaba en
el código. Mientras exista, cualquiera puede tocar sus datos.

### 2. Crear una clave nueva con permisos mínimos
En la misma pantalla → *Create token*:
- **Scopes:** solo `data.records:read` y `data.records:write`. **Nada más** (ni `schema`, ni `webhook`).
- **Access:** únicamente la base del inventario.

Copie el token. **No lo pegue en el chat ni lo suba a GitHub.**

### 3. Cargar las variables en Vercel
Vercel → proyecto → *Settings* → *Environment Variables*, para *Production* y *Preview*:

| Nombre | Valor |
|---|---|
| `AIRTABLE_PAT` | el token nuevo |
| `AIRTABLE_BASE_ID` | el id de la base (empieza con `app`) |
| `SESSION_SECRET` | un texto largo aleatorio |

Para generar `SESSION_SECRET`:

```bash
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

### 4. Publicar
Suba esta versión. Vercel la despliega sola. Pruebe primero la dirección de
*Preview* (rama `seguridad-servidor`) y, si entra bien, únala a `main`.

### 5. Contraseñas
- Cada usuario se migra solo: la **primera vez que entre**, su contraseña vieja pasa a cifrada.
- Como las contraseñas antiguas estuvieron expuestas, **cámbielas todas**: entre como
  administrador → *Usuarios y Permisos* → editar → escriba una nueva (mínimo 8 caracteres).
  Dejar el campo vacío conserva la actual.
- Revise la tabla `usuarios` y **borre los que no reconozca**.
- Opcional: `node scripts/migrar-contrasenas.js --aplicar` cifra todas de una vez
  (necesita las variables del paso 3 en su terminal).

## Cómo ver quién hizo qué

Vercel → proyecto → *Logs*. Cada acción deja un renglón con fecha y usuario:

```
{"evento":"login_ok","usuario":"andy",...}
{"evento":"login_fallido","usuario":"leandro","motivo":"no_existe",...}
{"evento":"escritura","usuario":"andy","tabla":"personal","metodo":"POST",...}
{"evento":"usuario_creado","por":"andy","nuevo":"x","rol":"OPERADOR"}
{"evento":"escritura_denegada",...}
```

## Límites que conviene conocer

- El freno de intentos de contraseña es por instancia del servidor: reduce la fuerza
  bruta pero no la elimina. Use contraseñas largas.
- Los cambios de permisos o el borrado de un usuario pueden tardar hasta 30 segundos
  en hacerse efectivos en una sesión que ya estaba abierta.
- El Airtable gratuito limita a 5 peticiones por segundo; el servidor guarda en memoria
  al usuario 30 segundos para no gastarlas.
- La página sigue cargando React, Babel y Tailwind desde internet (por eso la política de
  seguridad admite `unsafe-eval`). Un paso futuro sería empaquetarlos con la propia página.
