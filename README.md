# SecDocs · Backend

API de **SecDocs**, bóveda digital para guardar y compartir documentos confidenciales.
Proyecto de Seguridad Informática, Universidad Politécnica de Chiapas.

## Qué hace
- **Cifrado en reposo:** AES-256-GCM con una llave única (DEK) por archivo, protegida por una llave maestra.
- **Un enlace por receptor:** cada enlace expira y puede ser de un solo uso; la contraseña se envía por un canal distinto (autenticación fuera de banda).
- **Protección contra ataques:** bloqueo tras 5 intentos fallidos, límite de intentos por IP y bitácora de auditoría.
- **Autodestrucción:** al agotarse los enlaces, el archivo se destruye borrando su llave (*crypto-shredding*).

## Stack
Node.js 22 · Express · módulo nativo `crypto` · Helmet · express-rate-limit · Multer · PostgreSQL.

## Repositorios del proyecto
- [SecDocs-Frontend](https://github.com/JILAJ06/SecDocs-Frontend): interfaz web (Next.js)
- **SecDocs-Backend** (este repositorio)
- [SecDocs-DB](https://github.com/JILAJ06/SecDocs-DB): esquema y migraciones de PostgreSQL

## Estructura
```
src/crypto/       cifrado de archivos y manejo de llaves
src/db/           conexión a PostgreSQL
src/middleware/   cabeceras y límites de seguridad
src/services/     lógica de la bóveda
src/storage/      almacenamiento de los binarios cifrados
test/             pruebas unitarias y de integración
scripts/          utilidades de demostración
```

## Configuración
Copia `.env.example` a `.env` y completa los valores (no subas `.env` a git).

## Desarrollo
```bash
npm install
npm run dev      # http://localhost:4000
npm test
```
