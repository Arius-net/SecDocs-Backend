// Variables de entorno por defecto para pruebas (no sobrescribe las existentes).
// Debe importarse ANTES que cualquier módulo de src/.
process.env.NODE_ENV ??= 'test';
process.env.JWT_SECRET ??= 'test-jwt-secret-test-jwt-secret-1234567890';
process.env.MASTER_ENCRYPTION_KEY ??= '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';
process.env.DATABASE_URL = process.env.TEST_DATABASE_URL || 'postgresql://secdocs:secdocs_dev_pass@localhost:5432/secdocs';
process.env.DATABASE_SSL = 'false';
process.env.MAIL_WEBHOOK_URL = '';
process.env.MAIL_WEBHOOK_SECRET = '';
process.env.SMTP_HOST = ''; // las pruebas nunca envían correo real
process.env.AUTH_RATE_LIMIT_MAX ??= '1000';
process.env.INVITATION_RATE_LIMIT_MAX ??= '5000';
