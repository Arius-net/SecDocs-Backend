import 'dotenv/config';

function required(name) {
  const v = process.env[name];
  if (!v || !v.trim()) {
    throw new Error(`Variable de entorno requerida no definida: ${name}`);
  }
  return v.trim();
}

function int(name, def) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  const n = Number.parseInt(raw, 10);
  if (!Number.isFinite(n)) throw new Error(`Variable ${name} debe ser un entero`);
  return n;
}

function bool(name, def = false) {
  const raw = process.env[name];
  if (raw === undefined || raw === '') return def;
  return ['1', 'true', 'yes'].includes(raw.toLowerCase());
}

/** Decodifica una llave de 32 bytes en hex (64 chars) o base64. */
export function parseKey32(value, name) {
  const v = value.trim();
  let buf;
  if (/^[0-9a-fA-F]{64}$/.test(v)) buf = Buffer.from(v, 'hex');
  else buf = Buffer.from(v, 'base64');
  if (buf.length !== 32) {
    throw new Error(`${name} debe ser de 32 bytes (64 hex o base64 equivalente)`);
  }
  return buf;
}

const nodeEnv = process.env.NODE_ENV || 'development';
const isProd = nodeEnv === 'production';

const jwtSecret = required('JWT_SECRET');
if (jwtSecret.length < 32) throw new Error('JWT_SECRET debe tener al menos 32 caracteres');

export const config = Object.freeze({
  nodeEnv,
  isProd,
  port: int('PORT', 3000),
  trustProxy: int('TRUST_PROXY', 1),
  corsOrigins: (process.env.CORS_ORIGINS || '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
  frontendUrl: (process.env.FRONTEND_URL || 'http://localhost:5173').replace(/\/+$/, ''),
  db: {
    url: required('DATABASE_URL'),
    ssl: bool('DATABASE_SSL', false),
  },
  masterKey: parseKey32(required('MASTER_ENCRYPTION_KEY'), 'MASTER_ENCRYPTION_KEY'),
  jwt: {
    secret: jwtSecret,
    expiresHours: int('JWT_EXPIRES_HOURS', 8),
  },
  cookieName: (process.env.COOKIE_NAME || 'secdocs_session').trim(),
  authRateLimitMax: int('AUTH_RATE_LIMIT_MAX', 20),
  invitationRateLimitMax: int('INVITATION_RATE_LIMIT_MAX', 60),
  invitation: {
    // Cooldown mínimo entre reenvíos de la clave del Canal 2 (verify-identity)
    resendCooldownSeconds: int('PASSWORD_RESEND_COOLDOWN_SECONDS', 60),
  },
  r2: {
    accountId: process.env.R2_ACCOUNT_ID || '',
    accessKeyId: process.env.R2_ACCESS_KEY_ID || '',
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || '',
    bucket: process.env.R2_BUCKET || 'secdocs',
    endpoint: process.env.R2_ENDPOINT || '',
  },
  storage: {
    // 'r2' (principal) | 'local' (solo pruebas locales; prohibido en producción)
    driver: (process.env.STORAGE_DRIVER || 'r2').toLowerCase(),
    localDir: process.env.STORAGE_LOCAL_DIR || '.storage-local',
  },
  maxFileBytes: int('MAX_FILE_SIZE_MB', 15) * 1024 * 1024,
  vaultMaxDays: int('VAULT_MAX_DAYS', 365),
  smtp: {
    host: process.env.SMTP_HOST || '',
    port: int('SMTP_PORT', 587),
    secure: bool('SMTP_SECURE', false),
    user: process.env.SMTP_USER || '',
    pass: process.env.SMTP_PASS || '',
    from: process.env.SMTP_FROM || process.env.MAIL_FROM || 'SecDocs <no-reply@secdocs.local>',
  },
});
