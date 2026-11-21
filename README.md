# SecDocs v2 · Backend

API RESTful para bóvedas digitales seguras con cifrado en reposo mediante **Envelope Encryption**, compartición por correo electrónico verificado con autenticación fuera de banda (Canal 1: enlace de invitación / Canal 2: contraseña enviada por correo) y bitácora de auditoría con retención legal (LFPDPPP).

---

## Arquitectura de Seguridad

- **Envelope Encryption (AES-256-GCM):**
  - **Master Key (MEK):** clave maestra de 32 bytes (256 bits) configurada por variable de entorno (`MASTER_ENCRYPTION_KEY`).
  - **KEK por bóveda (`vaults.wrapped_kek`):** al crear una bóveda se genera una KEK aleatoria de 32 bytes y se envuelve con la MEK (`iv:authTag:ciphertext` en base64).
  - **DEK por archivo (`vault_files.wrapped_dek`):** cada archivo cifrado en RAM genera una DEK aleatoria de 32 bytes. El binario se cifra con AES-256-GCM (IV aleatorio de 12 bytes y AuthTag de 16 bytes) y se sube como `<uuid>.enc` a Cloudflare R2. La DEK se envuelve con la KEK de la bóveda.
  - **Crypto-Shredding:** al purgar un archivo, eliminar una bóveda o vencer su fecha de expiración, se establecen `wrapped_dek = NULL` (y `wrapped_kek = NULL` para la bóveda), dejando los binarios cifrados irrecuperables, además de solicitar su borrado en el almacenamiento.
- **Validación de archivos:** subida en memoria (`multer.memoryStorage`), límite configurable (`MAX_FILE_SIZE_MB=15`) y detección de MIME real mediante *magic bytes* (`file-type`) contra una lista blanca de formatos seguros (PDF, PNG, JPEG, WEBP, DOCX, XLSX, PPTX, ZIP, TXT/CSV UTF-8 sin bytes nulos). Rechaza ejecutables, scripts, HTML y SVG con `415`.
- **Autenticación y Sesiones:**
  - Contraseñas de usuarios y claves de Canal 2 hasheadas con `bcrypt` (costo 12).
  - Tokens de invitación y tickets de descarga de un solo uso (TTL 60s) almacenados únicamente como `SHA-256`.
  - Sesiones JWT (`HS256` explícito) en cookies `HttpOnly`, `SameSite=Strict` y `Secure` en producción, con `jti` registrado en `user_sessions` y lista negra `revoked_tokens` (con soporte de **Kill-Switch** para revocar todas las sesiones activas).
- **Protección contra fuerza bruta y fugas:**
  - Bloqueo exponencial en el desbloqueo de invitaciones (`2^n` segundos, bloqueo de 15 min y estado `TEMP_LOCKED` al 5.º intento fallido).
  - Cabeceras estrictas en rutas compartidas y descargas (`X-Robots-Tag: noindex, nofollow, noarchive`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`, `X-Content-Type-Options: nosniff`).
  - Consultas SQL 100% parametrizadas (`pg`) y saneamiento automático de `access_logs` para evitar el registro de secretos.
- **Retención LFPDPPP y Tareas Programadas (`node-cron`):**
  - Purga diaria de `access_logs` mayores a 6 meses (`daily_stats_rollup` anónimo se conserva indefinidamente).
  - Expiración automática y crypto-shredding de bóvedas vencidas.
  - Limpieza periódica de `revoked_tokens` y `user_sessions` expirados.

---

## Variables de Entorno

Copia `.env.example` a `.env` y configura los valores necesarios:

| Variable | Descripción | Default |
|---|---|---|
| `NODE_ENV` | Entorno (`development`, `production`, `test`) | `development` |
| `PORT` | Puerto HTTP de la API | `3000` |
| `CORS_ORIGINS` | Orígenes permitidos separados por coma | `http://localhost:5173` |
| `FRONTEND_URL` | URL base del frontend para enlaces `/invitacion/<token>` | `http://localhost:5173` |
| `DATABASE_URL` | Cadena de conexión PostgreSQL 15+ | — |
| `DATABASE_SSL` | Habilitar SSL para PostgreSQL (`true`/`false`) | `false` |
| `MASTER_ENCRYPTION_KEY` | Clave maestra de 32 bytes (64 hex o base64) | *(requerida)* |
| `JWT_SECRET` | Secreto para firma JWT (mín. 32 caracteres) | *(requerida)* |
| `JWT_EXPIRES_HOURS` | Duración de sesión JWT en horas | `8` |
| `COOKIE_NAME` | Nombre de la cookie de sesión | `secdocs_session` |
| `STORAGE_DRIVER` | `r2` (producción) o `local` (solo pruebas locales) | `r2` |
| `R2_ACCOUNT_ID` / `R2_ENDPOINT` | Cuenta o endpoint de Cloudflare R2 | — |
| `R2_ACCESS_KEY_ID` / `R2_SECRET_ACCESS_KEY` | Credenciales S3 de Cloudflare R2 | — |
| `R2_BUCKET` | Nombre del bucket R2 | `secdocs` |
| `MAX_FILE_SIZE_MB` | Tamaño máximo por archivo en MB | `15` |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` | Configuración SMTP para Canal 2 (en dev sin SMTP imprime en consola) | — |

---

## Levantar con Docker

1. Crea `.env` a partir de `.env.example` y genera `MASTER_ENCRYPTION_KEY` y `JWT_SECRET`:
   ```bash
   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
   ```
2. Construye y levanta PostgreSQL 16 + API:
   ```bash
   docker compose up --build -d
   ```
   Las migraciones SQL idempotentes (`src/db/migrations/`) se ejecutan automáticamente al arrancar el servidor.
3. Verifica el estado:
   ```bash
   curl http://localhost:3000/api/v1/health
   # {"status":"ok"}
   ```

---

## Pruebas

Requiere una instancia de PostgreSQL activa (por ejemplo `docker compose up -d db`):

```bash
npm install
npm test
```

Las pruebas usan el test runner nativo de Node.js (`node --test --test-concurrency=1`) e incluyen pruebas unitarias de servicios, pruebas de integración de cada módulo (auth, bóvedas, invitaciones, auditoría, cron jobs) y flujo E2E completo.

---

## Resumen de Endpoints (`/api/v1`)

### Salud
- `GET /health` — Verifica conectividad con PostgreSQL.

### Autenticación y Seguridad
- `POST /auth/register` — Registro de usuario, inicializa métricas y emite cookie `HttpOnly`.
- `POST /auth/login` — Inicio de sesión con protección timing-safe.
- `POST /auth/logout` — Revoca el `jti` actual y limpia la cookie.
- `GET /auth/me` — Perfil básico del usuario autenticado.
- `GET /security/sessions` — Lista sesiones activas del usuario.
- `DELETE /security/sessions/:jti` — Revoca una sesión específica.
- `POST /security/kill-switch` — Revoca todas las sesiones activas del usuario.

### Bóvedas y Archivos (Dueño)
- `GET /vaults` — Métricas y listado de bóvedas del usuario.
- `POST /vaults` — Crea una bóveda con su KEK envuelta por la MEK.
- `GET /vaults/:vaultId` — Detalle de bóveda, archivos activos y miembros.
- `PATCH /vaults/:vaultId/status` — Alterna estado entre `ACTIVE` y `LOCKED`.
- `DELETE /vaults/:vaultId` — Crypto-shredding total de bóveda, archivos y borrado en storage.
- `POST /vaults/:vaultId/files` — Sube archivo cifrado (magic bytes + DEK + AES-256-GCM).
- `DELETE /vaults/:vaultId/files/:fileId` — Crypto-shredding individual y borrado en storage.

### Miembros, Invitaciones y Bóveda Compartida
- `POST /vaults/:vaultId/members` — Crea invitación (devuelve enlace `/invitacion/<token>` una sola vez).
- `DELETE /vaults/:vaultId/members/:memberId` — Revoca acceso de un invitado.
- `GET /invitations/:token` — Info pública mínima con correo enmascarado.
- `POST /invitations/:token/verify-identity` — Verifica correo del invitado y envía clave Canal 2.
- `POST /invitations/:token/unlock` — Verifica clave Canal 2 (bloqueo exponencial) y emite ticket de 60s.
- `GET /shared` — Lista bóvedas compartidas aceptadas del usuario.
- `GET /shared/:vaultId/files/:fileId/download` — Consume ticket atómicamente, descifra al vuelo y descarga el archivo.

### Auditoría y Estadísticas
- `GET /audit/logs` — Bitácora paginada del dueño con filtros (`event`, `from`, `to`, `page`, `limit`) y política de retención.
- `GET /audit/stats` — Resumen y serie cronológica de `daily_stats_rollup` (`days=7` o `30`).
