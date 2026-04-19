import { Router } from 'express';
import { z } from 'zod';
import { validateBody } from '@palisade/core';
import { programTypeSchema } from '@palisade/card-programs';
import {
  createProgram,
  getProgram,
  listPrograms,
  resolveNdefUrlsByCardRef,
  resolveNdefUrlsForCard,
  updateProgram,
} from '../programs/index.js';

// GET  /api/programs
// GET  /api/programs/:id
// POST /api/programs
// PATCH /api/programs/:id
// GET  /api/programs/cards/by-ref/:cardRef/ndef-urls
// GET  /api/programs/cards/:cardId/ndef-urls

const router: Router = Router();

const upsertBaseSchema = z.object({
  name: z.string().min(1).max(128),
  programType: programTypeSchema.optional(),
  preActivationNdefUrlTemplate: z.string().url().nullable().optional(),
  postActivationNdefUrlTemplate: z.string().url().nullable().optional(),
  financialInstitutionId: z.string().optional(),
  embossingTemplateId: z.string().nullable().optional(),
});

const createSchema = upsertBaseSchema.extend({
  id: z
    .string()
    .min(1)
    .max(64)
    .regex(/^[a-z0-9_-]+$/i, 'program id must be alphanumeric + _ -'),
});

const patchSchema = upsertBaseSchema
  .partial()
  .refine((v) => Object.keys(v).length > 0, {
    message: 'at least one field must be supplied',
  });

router.post('/', validateBody(createSchema), async (req, res) => {
  const program = await createProgram(req.body);
  res.status(201).json(program);
});

router.patch('/:id', validateBody(patchSchema), async (req, res) => {
  const program = await updateProgram(req.params.id, req.body);
  res.json(program);
});

router.get('/', async (req, res) => {
  const financialInstitutionId = typeof req.query.financialInstitutionId === 'string'
    ? req.query.financialInstitutionId
    : undefined;
  res.json(await listPrograms({ financialInstitutionId }));
});

// Static sub-routes before :id to prevent shadowing.
router.get('/cards/by-ref/:cardRef/ndef-urls', async (req, res) => {
  res.json(await resolveNdefUrlsByCardRef(req.params.cardRef));
});

router.get('/cards/:cardId/ndef-urls', async (req, res) => {
  res.json(await resolveNdefUrlsForCard(req.params.cardId));
});

router.get('/:id', async (req, res) => {
  res.json(await getProgram(req.params.id));
});

export default router;
