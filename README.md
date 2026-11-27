# SecDocs · Backend

API REST de **SecDocs**, el motor de seguridad, cifrado y control de acceso para bóvedas digitales con cifrado en reposo y entrega de credenciales por doble canal.

<p align="center">
  <img src="logo.png" alt="Logo de SecDocs" width="160">
</p>

![Captura de la interfaz de SecDocs](preview.png)

![Node.js](https://img.shields.io/badge/Node.js-20+-339933?logo=nodedotjs&logoColor=white)
![Express](https://img.shields.io/badge/Express-4.x-000000?logo=express&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-Supabase-4169E1?logo=postgresql&logoColor=white)
![Cloudflare R2](https://img.shields.io/badge/Storage-Cloudflare_R2-F38020?logo=cloudflare&logoColor=white)
![Licencia MIT](https://img.shields.io/badge/licencia-MIT-green)

## Qué es SecDocs

SecDocs permite crear **bóvedas digitales** con fecha de expiración, almacenar documentos cifrados y compartirlos con invitados específicos bajo control estricto. Este repositorio implementa la lógica de negocio, la criptografía, la gestión de sesiones y el almacenamiento; la interfaz vive en [SecDocs-Frontend](https://github.com/JILAJ06/SecDocs-Frontend) y el esquema relacional en [SecDocs-DB](https://github.com/JILAJ06/SecDocs-DB).

Capacidades principales del backend:

- **Envelope Encryption (AES-256-GCM).** Jerarquía de tres llaves (`MEK → KEK → DEK`). La llave maestra (`MEK`) vive solo en variables de entorno; cada bóveda genera su propia `KEK` envuelta y cada archivo su propia `DEK` única con `iv` y `auth_tag` para garantizar confidencialidad e integridad.
- **Validación por *magic bytes* en RAM.** Antes de cifrar o subir un archivo, el servidor inspecciona sus bytes reales en memoria. Archivos renombrados o maliciosos (como HTML/XSS o ejecutables disfrazados de `.pdf`) se rechazan de inmediato con `415 Unsupported Media Type`.
- **Enlaces dinámicos nativos.** Genera tokens criptográficos únicos con `crypto` y ensambla las URLs dinámicamente según `FRONTEND_URL`. En PostgreSQL solo se guarda el hash `SHA-256` (`token_hash`), ligado al correo invitado, expiración y límite de descargas.
- **Doble canal (Canal 1 y Canal 2).** El dueño entrega el enlace (Canal 1) y el backend envía la clave de un solo uso por correo (Canal 2) mediante un webhook HTTPS hacia Google Apps Script (evitando bloqueos SMTP en producción).
- **Sesiones auditadas y *Kill-Switch*.** Autenticación con contraseñas en `bcrypt` (costo 12) y cookies `HttpOnly` con JWT + `jti` registrado en `user_sessions`. Revocar una sesión o activar el *Kill-Switch* inserta el `jti` en `revoked_tokens` y bloquea el acceso al instante (`401`).
- **Crypto-shredding.** Al purgar un archivo o bóveda, se elimina el binario `.enc` de Cloudflare R2 y se sobreescriben `wrapped_dek` / `wrapped_kek` con `NULL`, dejando cualquier copia residual matemáticamente irrecuperable.
- **Auditoría y protección contra abuso.** *Rate limiting* con soporte de proxy (`TRUST_PROXY=1`), bloqueo temporal (`TEMP_LOCKED`) tras 5 intentos fallidos y bitácora forense en `access_logs` (IP real, User-Agent y evento).

## Endpoints principales

Todas las rutas de negocio se sirven bajo el prefijo `/api/v1`.

| Módulo | Rutas principales | Qué hace |
|---|---|---|
| **Salud** | `GET /health` | Verifica estado del servidor y conexión activa con PostgreSQL. |
| **Autenticación** | `POST /auth/register`, `POST /auth/login`, `POST /auth/logout`, `GET /auth/me` | Registro, inicio de sesión con cookie `HttpOnly`, cierre de sesión y perfil activo. |
| **Bóvedas** | `GET/POST /vaults`, `GET/DELETE /vaults/:vaultId`, `PATCH /vaults/:vaultId/status` | Crear, listar, bloquear/reactivar y purgar bóvedas (*crypto-shredding*). |
| **Archivos** | `POST /vaults/:vaultId/files`, `DELETE /vaults/:vaultId/files/:fileId` | Validación por *magic bytes*, cifrado AES-256-GCM en RAM, subida a R2 y borrado seguro. |
| **Invitaciones** | `POST /vaults/:vaultId/members`, `GET /invitations/:token`, `POST /invitations/:token/verify-identity`, `POST /invitations/:token/unlock`, `POST /invitations/:token/download` | Emisión de enlaces dinámicos, envío de clave por Canal 2, validación de intentos, tickets de 60 s y descarga descifrada en memoria. |
| **Auditoría** | `GET /audit/logs`, `GET /audit/stats` | Consulta paginada de `access_logs` y métricas diarias (`daily_stats_rollup`). |
| **Seguridad** | `GET /security/sessions`, `DELETE /security/sessions/:jti`, `POST /security/kill-switch` | Listado de sesiones activas, revocación individual y cierre global inmediato. |

## Stack tecnológico

| Herramienta | Uso |
|---|---|
| **Node.js + Express** | Runtime, enrutamiento REST, middlewares de seguridad y motor propio de enlaces dinámicos |
| **PostgreSQL (Supabase)** | Metadatos, llaves envueltas, sesiones, lista negra de tokens y bitácora de auditoría |
| **Cloudflare R2** | Almacenamiento de objetos compatible con S3 para binarios cifrados (`<uuid>.enc`) |
| **Módulo `crypto` nativo** | Cifrado autenticado AES-256-GCM, generación de tokens y hashing SHA-256 |
| **bcrypt** | Hashing de contraseñas de usuarios (costo 12) |
| **Google Apps Script (Webhook HTTPS)** | Puente por puerto `443` para envío de claves del Canal 2 sin depender de puertos SMTP |

## Requisitos previos

- Node.js 20 o superior y npm.
- Instancia de PostgreSQL (local o Supabase mediante *Session Pooler* en el puerto `5432`).
- Bucket en Cloudflare R2 (para producción) o almacenamiento local (`STORAGE_DRIVER=local` para desarrollo).
- Webhook HTTPS de Google Apps Script (o credenciales SMTP en local) para el envío del Canal 2.

## Ejecución en local

```bash
# 1. Variables de entorno
cp .env.example .env            # en PowerShell: Copy-Item .env.example .env

# 2. Dependencias
npm install

# 3. Migraciones de base de datos
npm run migrate

# 4. Desarrollo (http://localhost:4000)
npm run dev
```

Pruebas automatizadas:

```bash
npm test
```

## Despliegue en producción

El backend está preparado para plataformas PaaS como **Railway** o **Render**:

- Escucha en `0.0.0.0` usando el puerto inyectado por `PORT`.
- Usa `TRUST_PROXY=1` para resolver correctamente la IP real del cliente detrás del proxy inverso (necesario para *rate limiting* y `access_logs`).
- Se conecta a **Supabase** mediante el **Session Pooler (puerto `5432`)** con `DATABASE_SSL=true` para soportar `pg_advisory_lock` en migraciones.
- Guarda los binarios cifrados en **Cloudflare R2** (`STORAGE_DRIVER=r2`).
- Envía los correos del Canal 2 por **HTTPS (`443`)** usando `MAIL_WEBHOOK_URL` y `MAIL_WEBHOOK_SECRET`, evitando el bloqueo de puertos SMTP (`465`/`587`) de Railway.

## Variables de entorno

Se definen en `.env` (a partir de `.env.example`) y nunca se suben al repositorio.

| Variable | Descripción | Ejemplo |
|---|---|---|
| `PORT` | Puerto HTTP del servidor | `4000` |
| `TRUST_PROXY` | Confianza en proxy inverso (`1` en Railway/Render) | `1` |
| `FRONTEND_URL` | URL base para generar los enlaces dinámicos | `https://sec-docs-frontend.vercel.app` |
| `CORS_ORIGINS` | Orígenes permitidos separados por coma | `https://sec-docs-frontend.vercel.app` |
| `DATABASE_URL` | Cadena de conexión PostgreSQL (Session Pooler `:5432`) | `postgresql://user:pass@host:5432/postgres` |
| `DATABASE_SSL` | Habilita TLS hacia la base de datos | `true` |
| `JWT_SECRET` | Secreto para firmar tokens de sesión | *(cadena aleatoria larga)* |
| `MASTER_ENCRYPTION_KEY` | Llave maestra (MEK) de 32 bytes en hex (64 caracteres) | *(64 caracteres hex)* |
| `MAX_FILE_SIZE_MB` | Tamaño máximo permitido por archivo en RAM | `15` |
| `STORAGE_DRIVER` | Driver de almacenamiento (`r2` o `local`) | `r2` |
| `R2_ENDPOINT`, `R2_BUCKET`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` | Credenciales del bucket en Cloudflare R2 | *(valores de Cloudflare)* |
| `MAIL_WEBHOOK_URL` | URL `/exec` del puente HTTPS en Google Apps Script | `https://script.google.com/macros/s/.../exec` |
| `MAIL_WEBHOOK_SECRET` | Secreto compartido para autenticar el webhook de correo | *(clave secreta)* |

## Seguridad

Controles aplicados en el servidor:

- **Cero secretos en Git:** `.env` está excluido en `.gitignore`; las llaves (`MEK`, `JWT_SECRET`, credenciales de R2 y BD) se inyectan únicamente por entorno.
- **Sin archivos en claro en disco:** Los archivos se validan y cifran en memoria RAM antes de salir hacia Cloudflare R2.
- **Consultas parametrizadas:** Prevención de inyección SQL en todas las operaciones contra PostgreSQL.
- **Sin fuga de secretos en logs:** Los registros de consola y `access_logs` nunca imprimen contraseñas, tokens en claro ni llaves criptográficas.

Repositorios del proyecto:

- [SecDocs-Frontend](https://github.com/JILAJ06/SecDocs-Frontend): interfaz web en Next.js y proxy de cookies.
- **SecDocs-Backend**: este repositorio.
- [SecDocs-DB](https://github.com/JILAJ06/SecDocs-DB): esquema, migraciones y políticas de auditoría en PostgreSQL.

## Autores

- Alexander Jiménez
- Sayd Quevedo

Proyecto de la materia **Seguridad Informática**, Universidad Politécnica de Chiapas.

## Licencia

Distribuido bajo la licencia MIT. Consulta [LICENSE](LICENSE).
