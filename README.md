# SecDocs · Backend

API REST de **SecDocs**, una bóveda digital para guardar y compartir documentos confidenciales con cifrado en reposo y acceso por doble canal.

<p align="center">
  <img src="logo.png" alt="Logo de SecDocs" width="160">
</p>

![Captura de la interfaz de SecDocs](preview.png)

![Node.js](https://img.shields.io/badge/Node.js-20+-339933?logo=nodedotjs&logoColor=white)
![Express](https://img.shields.io/badge/Express-4.21-000000?logo=express&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![Cloudflare R2](https://img.shields.io/badge/Almacenamiento-Cloudflare_R2-F38020?logo=cloudflare&logoColor=white)
![Licencia MIT](https://img.shields.io/badge/licencia-MIT-green)

## Qué es SecDocs

SecDocs permite que una persona cree **bóvedas** con fecha de expiración, suba documentos a ellas e invite a otras personas a descargarlos de forma controlada. Este repositorio es la API: cifrado, almacenamiento, sesiones y reglas de acceso. La interfaz vive en [SecDocs-Frontend](https://github.com/JILAJ06/SecDocs-Frontend) y el esquema relacional en [SecDocs-DB](https://github.com/JILAJ06/SecDocs-DB).

Lo que hace el backend:

- **Cifrado AES-256-GCM en reposo con tres niveles de llave.** La llave maestra (`MEK`) solo existe en las variables de entorno. Cada bóveda tiene su propia `KEK`, guardada envuelta con la MEK, y cada archivo su propia `DEK`, envuelta con la KEK de su bóveda. Los archivos se cifran en memoria y se guardan como binarios `.enc`.
- **Un enlace por receptor.** Cada invitación genera un token aleatorio; en la base solo se guarda su hash SHA-256. El enlace (`FRONTEND_URL/invitacion/<token>`) está ligado al correo invitado, vence con la bóveda y tiene un límite de descargas (de 1 a 10). Cada descarga exige un **ticket de un solo uso** que vence a los 60 segundos.
- **Contraseña por un canal distinto.** El dueño entrega el enlace (Canal 1) y el backend envía la clave de acceso por correo (Canal 2). Entre un reenvío y otro hay una espera mínima configurable.
- **Bloqueo tras 5 intentos.** Cada clave incorrecta aumenta la espera (2^n segundos). Al quinto intento la invitación pasa a `TEMP_LOCKED` durante 15 minutos.
- **Límite de peticiones por IP**, en ventanas de 15 minutos:
  - 600 peticiones en total;
  - `AUTH_RATE_LIMIT_MAX` en registro e inicio de sesión;
  - `INVITATION_RATE_LIMIT_MAX` en `/invitations` y `/shared`.

  Detrás de un proxy, `TRUST_PROXY` permite obtener la IP real.
- **Validación por *magic bytes*.** El tipo de archivo se decide por sus bytes reales, nunca por la extensión ni por el `Content-Type`. Se aceptan PDF, PNG, JPEG, WEBP, DOCX, XLSX, PPTX, ZIP y texto o CSV; HTML, SVG, XML y scripts se rechazan con `415`.
- **Sesiones revocables y *kill-switch*.**
  - Las contraseñas se guardan con bcrypt (costo 12).
  - La sesión es un JWT en una cookie `HttpOnly`; su `jti` queda registrado en la base.
  - Revocar una sesión o activar el *kill-switch* invalida esos tokens al instante.
- **Crypto-shredding.** Al destruir un archivo o una bóveda se borra el binario cifrado y la llave envuelta queda en `NULL`, así que el contenido es irrecuperable. Lo mismo ocurre cuando una bóveda expira.
- **Bitácora de auditoría.**
  - Cada evento queda en `access_logs` con IP, *User-Agent* y detalle, sin tokens ni claves.
  - Los registros con más de 6 meses se purgan.
  - Las métricas diarias se conservan aparte.

## Endpoints

Todas las rutas usan el prefijo `/api/v1`. Las marcadas con "sí" requieren la cookie de sesión.

| Módulo | Método y ruta | Sesión | Qué hace |
|---|---|---|---|
| Salud | `GET /health` | no | Responde `{ status: 'ok' }` si hay conexión con PostgreSQL |
| Autenticación | `POST /auth/register` | no | Crea la cuenta e inicia sesión |
| | `POST /auth/login` | no | Inicia sesión (cookie `HttpOnly`) |
| | `POST /auth/logout` | sí | Cierra y revoca la sesión actual |
| | `GET /auth/me` | sí | Usuario de la sesión |
| Bóvedas | `GET /vaults`, `POST /vaults` | sí | Listar y crear bóvedas |
| | `GET /vaults/:vaultId` | sí | Detalle con archivos, miembros y estado de las llaves |
| | `PATCH /vaults/:vaultId/status` | sí | Bloquear o reactivar |
| | `DELETE /vaults/:vaultId` | sí | Destruir la bóveda (*crypto-shredding*) |
| Archivos | `POST /vaults/:vaultId/files` | sí | Validar, cifrar y subir un archivo (campo `file`) |
| | `DELETE /vaults/:vaultId/files/:fileId` | sí | Destruir un archivo |
| Miembros | `POST /vaults/:vaultId/members` | sí | Invitar por correo; el enlace se devuelve una sola vez |
| | `DELETE /vaults/:vaultId/members/:memberId` | sí | Revocar una invitación |
| Invitaciones | `GET /invitations/:token` | no | Datos públicos de la invitación |
| | `POST /invitations/:token/verify-identity` | sí | Verifica que la sesión sea del correo invitado y envía la clave (Canal 2) |
| | `POST /invitations/:token/unlock` | sí | Valida la clave y entrega un ticket de 60 s |
| Compartidas | `GET /shared` | sí | Bóvedas a las que me invitaron |
| | `GET /shared/:vaultId/files/:fileId/download` | sí | Descarga descifrada con el ticket en la cabecera `X-Download-Ticket` |
| Auditoría | `GET /audit/logs` | sí | Bitácora paginada con filtros por evento y fechas |
| | `GET /audit/stats` | sí | Métricas por día |
| Seguridad | `GET /security/sessions` | sí | Sesiones activas |
| | `DELETE /security/sessions/:jti` | sí | Revocar una sesión |
| | `POST /security/kill-switch` | sí | Cerrar todas las sesiones |

## Tareas programadas

Se ejecutan con `node-cron` (hora UTC) al arrancar el servidor, salvo con `NODE_ENV=test`:

| Tarea | Frecuencia | Qué hace |
|---|---|---|
| `expireVaults` | cada 5 minutos | Expira las bóvedas vencidas y destruye sus llaves |
| `cleanupExpiredTokens` | cada hora | Borra las sesiones y los tokens revocados que ya vencieron |
| `purgeOldAuditLogs` | diario, 03:15 | Borra `access_logs` con más de 6 meses |

## Stack tecnológico

| Herramienta | Versión (`package.json`) | Uso |
|---|---|---|
| Node.js | >= 20 | Entorno de ejecución (módulos ES) |
| Express | ^4.21.2 | API REST |
| pg | ^8.13.1 | Cliente de PostgreSQL |
| `crypto` (nativo) | — | AES-256-GCM, tokens aleatorios y SHA-256 |
| bcrypt | ^6.0.0 | Hash de contraseñas |
| jsonwebtoken | ^9.0.2 | Tokens de sesión |
| helmet, cors, express-rate-limit | ^8.0.0, ^2.8.5, ^7.5.0 | Cabeceras de seguridad, CORS y límite de peticiones |
| multer, file-type | ^2.0.2, ^19.6.0 | Subida en memoria y detección por *magic bytes* |
| @aws-sdk/client-s3 | ^3.700.0 | Cloudflare R2 (compatible con S3) |
| nodemailer | ^6.9.16 | Correo del Canal 2 por SMTP |
| node-cron | ^3.0.3 | Tareas programadas |

## Requisitos previos

- Node.js 20 o superior y npm. La imagen de Docker usa Node 22.
- PostgreSQL: local, con el `docker-compose.yml` de este repositorio, o en Supabase.
- Un bucket de Cloudflare R2. Para pruebas locales sirve `STORAGE_DRIVER=local`, que se rechaza con `NODE_ENV=production`.
- Para enviar el correo del Canal 2: un webhook HTTPS o una cuenta SMTP. En desarrollo, sin ninguno de los dos, el correo se imprime en la consola.

## Ejecución en local

```bash
# 1. Variables de entorno (completa MASTER_ENCRYPTION_KEY y JWT_SECRET)
cp .env.example .env            # en PowerShell: Copy-Item .env.example .env

# 2. Dependencias
npm install

# 3. Migraciones (también se aplican solas al arrancar)
npm run migrate

# 4. Desarrollo, con recarga al guardar
npm run dev
```

El servidor escucha en `0.0.0.0` y en el puerto `PORT`; si no se define, usa el `3000`. Puedes comprobar que responde con `GET /api/v1/health`.

Para generar la llave maestra:

```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

## Ejecución con Docker

`docker-compose.yml` levanta dos servicios:

- `db`: PostgreSQL 16, publicado solo en `127.0.0.1:5432`.
- `api`: la imagen del `Dockerfile`, en el puerto 3000, con las variables de `.env`.

```bash
cp .env.example .env            # completa MASTER_ENCRYPTION_KEY y JWT_SECRET
docker compose up --build
```

La API aplica las migraciones al arrancar.

## Pruebas

```bash
npm test
```

Usan el *test runner* nativo de Node (`node --test`) y necesitan un PostgreSQL disponible en `TEST_DATABASE_URL`. Si esa variable no se define, se conectan a la base local de `docker-compose.yml`. Nunca envían correo real.

Cubren:

- autenticación y su límite de peticiones;
- bóvedas e invitaciones, incluido su límite;
- auditoría;
- tareas programadas;
- los servicios de cifrado, almacenamiento y correo;
- un flujo de punta a punta (`tests/e2e.test.js`).

## Variables de entorno

Se definen en `.env` (a partir de `.env.example`) y nunca se suben al repositorio. Los ejemplos son ficticios.

| Variable | Descripción | Ejemplo |
|---|---|---|
| `NODE_ENV` | `development`, `production` o `test` | `development` |
| `PORT` | Puerto HTTP (por defecto `3000`) | `3000` |
| `TRUST_PROXY` | Saltos de proxy confiables, para obtener la IP real | `1` |
| `CORS_ORIGINS` | Orígenes permitidos, separados por coma | `http://localhost:3000` |
| `FRONTEND_URL` | URL pública del frontend, sin diagonal final; con ella se arma el enlace de invitación | `https://frontend.ejemplo.com` |
| `DATABASE_URL` | Conexión a PostgreSQL (obligatoria) | `postgresql://usuario:contraseña@host:5432/secdocs` |
| `DATABASE_SSL` | TLS hacia la base (`true` en Supabase) | `false` |
| `POSTGRES_PASSWORD` | Contraseña del PostgreSQL de `docker-compose.yml` | *(solo local)* |
| `MASTER_ENCRYPTION_KEY` | Llave maestra (MEK) de 32 bytes, en hex (64 caracteres) o base64 (obligatoria) | *(generada con el comando de arriba)* |
| `JWT_SECRET` | Secreto para firmar los JWT, de 32 caracteres o más (obligatoria) | *(cadena aleatoria)* |
| `JWT_EXPIRES_HOURS` | Duración de la sesión en horas | `8` |
| `COOKIE_NAME` | Nombre de la cookie de sesión | `secdocs_session` |
| `AUTH_RATE_LIMIT_MAX` | Intentos por IP cada 15 min en registro e inicio de sesión | `20` |
| `INVITATION_RATE_LIMIT_MAX` | Peticiones por IP cada 15 min en `/invitations` y `/shared` | `60` |
| `PASSWORD_RESEND_COOLDOWN_SECONDS` | Espera mínima entre reenvíos de la clave del Canal 2 | `60` |
| `STORAGE_DRIVER` | `r2` o `local` (`local` solo para pruebas) | `r2` |
| `STORAGE_LOCAL_DIR` | Carpeta del almacenamiento `local` | `.storage-local` |
| `R2_ACCOUNT_ID`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY`, `R2_BUCKET`, `R2_ENDPOINT` | Credenciales y bucket de Cloudflare R2; `R2_ENDPOINT` es opcional | *(valores de tu cuenta)* |
| `MAX_FILE_SIZE_MB` | Tamaño máximo por archivo (`413` si se excede) | `15` |
| `VAULT_MAX_DAYS` | Vigencia máxima de una bóveda, en días | `365` |
| `MAIL_WEBHOOK_URL`, `MAIL_WEBHOOK_SECRET` | Webhook HTTPS para el correo del Canal 2. Tiene prioridad sobre SMTP | *(URL y secreto del webhook)* |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | SMTP directo, si no hay webhook | `smtp.ejemplo.com`, `465`, `true` |

## Despliegue

- **Puerto:** el servidor escucha en `0.0.0.0` y toma el puerto de `PORT`, como lo inyectan plataformas tipo Railway o Render.
- **IP real:** con `TRUST_PROXY=1` el *rate limit* y la bitácora usan la IP del cliente detrás del proxy.
- **Supabase:** usa el *Session Pooler* (puerto `5432`) con `DATABASE_SSL=true`.
- **Correo:** si la plataforma bloquea los puertos SMTP, el correo del Canal 2 puede salir por el webhook HTTPS (`MAIL_WEBHOOK_URL`).

## Conexión con el frontend

El frontend reenvía `/api/v1/*` a esta API, así que el navegador las ve en el mismo origen. La cookie de sesión es `HttpOnly` y `SameSite=Strict`, y lleva `Secure` en producción.

- Agrega la URL del frontend a `CORS_ORIGINS`.
- Define `FRONTEND_URL` para que los enlaces de invitación apunten a él.

Repositorios del proyecto:

- [SecDocs-Frontend](https://github.com/JILAJ06/SecDocs-Frontend): interfaz web en Next.js.
- **SecDocs-Backend**: este repositorio.
- [SecDocs-DB](https://github.com/JILAJ06/SecDocs-DB): esquema, migraciones y políticas de auditoría en PostgreSQL.

## Estructura de carpetas

```text
src/
  server.js                 arranque: migraciones, servidor y tareas programadas
  app.js                    middlewares globales y montaje de /api/v1
  config/env.js             lectura y validación de variables de entorno
  db/                       pool de PostgreSQL, migrador y migraciones SQL
  middlewares/              sesión, errores, helmet, CORS y límites de peticiones
  modules/                  rutas por módulo: auth, vaults (y archivos), members,
                            invitations, shared, audit, security
  services/                 cifrado, almacenamiento, validación de archivos,
                            correo, sesiones y auditoría
  jobs/                     tareas programadas
tests/                      pruebas con node --test
legacy/                     backend v1 archivado (no se incluye en la imagen de Docker)
Dockerfile                  imagen de producción
docker-compose.yml          PostgreSQL + API para desarrollo local
```

## Seguridad

Lo que hace el servidor:

- **Secretos fuera del código.** MEK, `JWT_SECRET`, credenciales de R2, de la base y del correo solo llegan por variables de entorno. El servidor no arranca si faltan las obligatorias.
- **Nada en claro en disco.** Los archivos se validan y cifran en memoria antes de guardarse.
- **Consultas parametrizadas** contra PostgreSQL.
- **Ni tokens ni claves en claro.** De los tokens de invitación y los tickets solo se guarda su hash SHA-256. Ni la bitácora ni la consola imprimen contraseñas, tokens ni llaves.
- **Mismo tiempo de respuesta al iniciar sesión.** Se compara siempre contra un hash de bcrypt, exista o no el usuario, para no revelar qué correos están registrados.
- **Cabeceras:**
  - `helmet`, con CSP `default-src 'none'`.
  - `Referrer-Policy: no-referrer`.
  - En `/invitations` y `/shared`, además, `Cache-Control: no-store` y `X-Robots-Tag`.

Qué **no** subir al repositorio:

- `.env` ni ninguna copia con valores reales. El `.gitignore` y el `.dockerignore` ya lo excluyen.
- La llave maestra, el `JWT_SECRET`, las credenciales de R2, de la base o del correo, ni la URL del webhook.
- Volcados de la base, binarios `.enc` o la carpeta `.storage-local`.
- Capturas o registros con correos, tokens de invitación o claves reales.

## Autores

- Alexander Jiménez
- Sayd Quevedo

Proyecto de la materia **Seguridad Informática**, Universidad Politécnica de Chiapas.

## Licencia

Distribuido bajo la licencia MIT. Consulta [LICENSE](LICENSE).
