import { Router } from 'express';
import { query } from '../db/pool.js';
import { authRouter } from './auth/auth.routes.js';
import { securityRouter } from './security/security.routes.js';
import { vaultsRouter } from './vaults/vaults.routes.js';
import { invitationsRouter } from './invitations/invitations.routes.js';
import { sharedRouter } from './shared/shared.routes.js';
import { auditRouter } from './audit/audit.routes.js';
import { noStoreHeaders, invitationLimiter } from '../middlewares/security.middleware.js';

/** Router raíz de la API (/api/v1). Cada fase monta aquí sus módulos. */
export const apiRouter = Router();

apiRouter.get('/health', async (req, res, next) => {
  try {
    await query('SELECT 1');
    res.json({ status: 'ok' });
  } catch (err) {
    next(err);
  }
});

apiRouter.use('/auth', authRouter);
apiRouter.use('/security', securityRouter);
apiRouter.use('/vaults', vaultsRouter);
apiRouter.use('/audit', auditRouter);
// Rutas de invitación/compartidas: cabeceras anti-indexación/caché SIEMPRE (también en errores y 429).
apiRouter.use('/invitations', noStoreHeaders, invitationLimiter, invitationsRouter);
apiRouter.use('/shared', noStoreHeaders, invitationLimiter, sharedRouter);
