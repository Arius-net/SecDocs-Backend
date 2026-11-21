import { Router } from 'express';
import { query } from '../../db/pool.js';
import { HttpError } from '../../middlewares/error.middleware.js';
import { asyncHandler } from '../../middlewares/async.js';
import { requireAuth } from '../../middlewares/auth.middleware.js';

export const auditRouter = Router();
auditRouter.use(requireAuth);

const DATE_ONLY_RE = /^\d{4}-\d{2}-\d{2}$/;
const DAY_MS = 86_400_000;

function parsePositiveInt(value, name, def) {
  if (value === undefined) return def;
  if (typeof value !== 'string' || !/^\d+$/.test(value)) throw new HttpError(400, `${name} debe ser un entero positivo`);
  const n = Number.parseInt(value, 10);
  if (n < 1) throw new HttpError(400, `${name} debe ser un entero positivo`);
  return n;
}

/** `from`: inicio inclusivo. `to`: fecha (YYYY-MM-DD) inclusiva todo el día, o instante inclusivo. */
function parseDateParam(value, name, { endOfRange = false } = {}) {
  if (value === undefined) return null;
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) throw new HttpError(400, `${name} no es una fecha ISO válida`);
  const t = Date.parse(value);
  if (!endOfRange) return new Date(t);
  return new Date(DATE_ONLY_RE.test(value) ? t + DAY_MS : t + 1); // cota superior exclusiva
}

auditRouter.get(
  '/logs',
  asyncHandler(async (req, res) => {
    const page = parsePositiveInt(req.query.page, 'page', 1);
    const limit = Math.min(parsePositiveInt(req.query.limit, 'limit', 20), 100);
    const from = parseDateParam(req.query.from, 'from');
    const toExclusive = parseDateParam(req.query.to, 'to', { endOfRange: true });
    if (from && toExclusive && from >= toExclusive) throw new HttpError(400, 'from debe ser anterior a to');
    let event = null;
    if (req.query.event !== undefined) {
      if (typeof req.query.event !== 'string' || !req.query.event.trim() || req.query.event.length > 50) {
        throw new HttpError(400, 'event inválido');
      }
      event = req.query.event.trim();
    }

    // Filtro estricto por owner_id del usuario autenticado (nunca desde la query).
    const where = `owner_id = $1
      AND ($2::varchar IS NULL OR event = $2)
      AND ($3::timestamptz IS NULL OR created_at >= $3)
      AND ($4::timestamptz IS NULL OR created_at < $4)`;
    const params = [req.user.id, event, from, toExclusive];

    const total = (await query(`SELECT count(*)::int AS n FROM access_logs WHERE ${where}`, params)).rows[0].n;
    const { rows } = await query(
      `SELECT id, event, vault_id, file_id, member_id, ip, user_agent, detail, created_at
         FROM access_logs WHERE ${where}
        ORDER BY created_at DESC, id DESC
        LIMIT $5 OFFSET $6`,
      [...params, limit, (page - 1) * limit],
    );
    res.json({
      retentionPolicy: '6 months (LFPDPPP)',
      pagination: { page, limit, total, totalPages: Math.ceil(total / limit) },
      logs: rows,
    });
  }),
);

auditRouter.get(
  '/stats',
  asyncHandler(async (req, res) => {
    let days = 30;
    if (req.query.days !== undefined) {
      if (req.query.days !== '7' && req.query.days !== '30') throw new HttpError(400, 'days debe ser 7 o 30');
      days = Number(req.query.days);
    }
    // Serie continua (días sin actividad = 0), en orden cronológico.
    const { rows } = await query(
      `SELECT to_char(d::date, 'YYYY-MM-DD') AS date,
              COALESCE(r.total_downloads, 0)::int AS downloads,
              COALESCE(r.total_failed_attempts, 0)::int AS "failedAttempts",
              COALESCE(r.unique_visitors, 0)::int AS "uniqueVisitors"
         FROM generate_series(CURRENT_DATE - ($2::int - 1), CURRENT_DATE, interval '1 day') AS d
         LEFT JOIN daily_stats_rollup r ON r.owner_id = $1 AND r.stat_date = d::date
        ORDER BY d`,
      [req.user.id, days],
    );
    const totals = rows.reduce(
      (acc, r) => ({
        downloads: acc.downloads + r.downloads,
        failedAttempts: acc.failedAttempts + r.failedAttempts,
        uniqueVisitors: acc.uniqueVisitors + r.uniqueVisitors,
      }),
      { downloads: 0, failedAttempts: 0, uniqueVisitors: 0 },
    );
    res.json({ days, totals, series: rows });
  }),
);
