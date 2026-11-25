import { Router } from 'express';
import { requireAuth } from '../auth/middleware.ts';
import { getDatabase } from '../db/connection.ts';

const departmentsRouter = Router();

departmentsRouter.get('/', requireAuth, (_req, res) => {
  const db = getDatabase();
  const departments = db
    .prepare('SELECT id, name, code FROM departments ORDER BY name ASC')
    .all();
  res.status(200).json({ departments });
});

export { departmentsRouter };
