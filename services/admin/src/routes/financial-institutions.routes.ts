import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '@palisade/db';
import { validateBody, notFound, conflict } from '@palisade/core';

// CRUD for FinancialInstitution.  An FI is the BIN sponsor / card issuer
// (e.g. "InComm") that owns one or more Programs.  Mounted under
// /api/admin/financial-institutions behind the admin Cognito gate.

const router: Router = Router();

const slugRegex = /^[a-z0-9][a-z0-9-]{0,40}[a-z0-9]$/;

const createSchema = z.object({
  name: z.string().min(1).max(128),
  slug: z.string().regex(slugRegex, 'lowercase letters, digits, and hyphens only'),
  bin: z.string().regex(/^\d{6,8}$/).optional(),
  contactEmail: z.string().email().optional(),
  contactName: z.string().min(1).max(128).optional(),
}).strict();

const patchSchema = createSchema.partial().extend({
  status: z.enum(['ACTIVE', 'SUSPENDED']).optional(),
}).refine((v) => Object.keys(v).length > 0, { message: 'at least one field required' });

router.get('/', async (_req, res) => {
  const fis = await prisma.financialInstitution.findMany({
    orderBy: { name: 'asc' },
    include: { _count: { select: { programs: true } } },
  });
  res.json(fis);
});

router.get('/:id', async (req, res) => {
  const fi = await prisma.financialInstitution.findUnique({
    where: { id: req.params.id },
    include: { programs: { orderBy: { name: 'asc' } } },
  });
  if (!fi) throw notFound('fi_not_found', 'Financial institution not found');
  res.json(fi);
});

router.post('/', validateBody(createSchema), async (req, res) => {
  try {
    const fi = await prisma.financialInstitution.create({ data: req.body });
    res.status(201).json(fi);
  } catch (err: unknown) {
    if (err && typeof err === 'object' && 'code' in err && (err as { code?: string }).code === 'P2002') {
      throw conflict('slug_taken', 'Slug already in use');
    }
    throw err;
  }
});

router.patch('/:id', validateBody(patchSchema), async (req, res) => {
  try {
    const fi = await prisma.financialInstitution.update({
      where: { id: req.params.id },
      data: req.body,
    });
    res.json(fi);
  } catch (err: unknown) {
    const code = err && typeof err === 'object' && 'code' in err ? (err as { code?: string }).code : undefined;
    if (code === 'P2025') throw notFound('fi_not_found', 'Financial institution not found');
    if (code === 'P2002') throw conflict('slug_taken', 'Slug already in use');
    throw err;
  }
});

export default router;
