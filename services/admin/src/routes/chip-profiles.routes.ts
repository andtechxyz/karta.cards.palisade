import { Router } from 'express';
import { Prisma } from '@prisma/client';
import { z } from 'zod';
import { prisma } from '@palisade/db';
import { validateBody, badRequest, notFound } from '@palisade/core';

// CRUD for ChipProfile.  A ChipProfile describes how one scheme/vendor
// chip applet (Mastercard M/Chip Advance, Visa VSDC, …) lays out its
// DGIs and which tags live inside each one.  Used by the data-prep
// service when building a SAD for a card.
//
// Mounted under /api/chip-profiles behind the Cognito admin-group gate.
// No DELETE — once IssuerProfiles reference a ChipProfile, deletion
// would corrupt every provisioning record for that program.  Archival
// via a future status field is out of scope for this pass.
//
// POST accepts either JSON body or a multipart upload whose `file`
// part contains JSON.  The brief defers `.profile` ZIP and Visa VPA
// XML parsing — this pass is JSON only.  We validate via the shape
// that @palisade/emv's ChipProfile.fromJson consumes, but keep the
// storage format flexible (the DGI definition list is the only bit
// the app touches downstream).

const router: Router = Router();

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

// AID hex-string — empty allowed because some schemes leave paAid/fidoAid
// at the schema default.
const aidField = z
  .string()
  .regex(/^[0-9A-Fa-f]*$/, 'must be a hex string')
  .max(32);

// A single DGI definition entry.  Mirrors the shape ChipProfile.fromJson
// reads — integer dgi_number, tag array of ints, mandatory+source flags.
// We accept both snake_case (JSON profile convention) and camelCase
// (legacy uploads) and then convert to the on-disk shape (snake_case)
// before storing.
const dgiDefSchema = z
  .object({
    dgi_number: z.coerce.number().int().min(0).max(0xffff).optional(),
    dgiNumber: z.coerce.number().int().min(0).max(0xffff).optional(),
    name: z.string().min(1).max(128),
    tags: z.array(z.coerce.number().int().min(0).max(0xffffff)).optional(),
    mandatory: z.boolean().optional(),
    source: z
      .enum(['per_profile', 'per_card', 'pa_internal', 'per_provisioning'])
      .optional(),
  })
  .passthrough();

const createSchema = z
  .object({
    name: z.string().min(1).max(128),
    scheme: z.string().min(1).max(64),
    vendor: z.string().min(1).max(64),
    cvn: z.coerce.number().int().min(0).max(255),
    dgiDefinitions: z.array(dgiDefSchema).min(1),
    elfAid: aidField.optional(),
    moduleAid: aidField.optional(),
    paAid: aidField.optional(),
    fidoAid: aidField.optional(),
    iccPrivateKeyDgi: z.coerce.number().int().min(0).max(0xffff).optional(),
    iccPrivateKeyTag: z.coerce.number().int().min(0).max(0xffffff).optional(),
    mkAcDgi: z.coerce.number().int().min(0).max(0xffff).optional(),
    mkSmiDgi: z.coerce.number().int().min(0).max(0xffff).optional(),
    mkSmcDgi: z.coerce.number().int().min(0).max(0xffff).optional(),
    programId: z.string().max(64).nullable().optional(),
  })
  .strict();

const patchSchema = createSchema
  .partial()
  .strict()
  .refine((v) => Object.keys(v).length > 0, {
    message: 'at least one field must be supplied',
  });

// ---------------------------------------------------------------------------
// Multipart handling
// ---------------------------------------------------------------------------

// Minimal multipart parser — we only accept a single `file` part whose
// body is JSON.  Same inlined approach as provisioning.routes.ts batch
// ingestion so we don't pull in a new dep.
async function readMultipartFile(req: import('express').Request): Promise<string> {
  const contentType = req.headers['content-type'] ?? '';
  const match = contentType.match(/boundary=([^\s;]+)/);
  if (!match) {
    throw badRequest('missing_boundary', 'Content-Type must be multipart/form-data with a boundary');
  }
  const raw = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
  const boundary = '--' + match[1];
  const text = raw.toString('utf8');
  const parts = text.split(boundary).filter((p) => p.trim() && p.trim() !== '--');
  for (const part of parts) {
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd < 0) continue;
    const headers = part.slice(0, headerEnd);
    const body = part.slice(headerEnd + 4).replace(/\r\n$/, '');
    if (headers.includes('name="file"')) return body;
  }
  throw badRequest('missing_file', 'multipart upload must include a `file` part');
}

// Canonicalise to the shape ChipProfile.fromJson expects (snake_case
// tags on each DGI entry).  Accepts camelCase fallbacks from earlier
// manual entries.
function canonicaliseDgi(entry: Record<string, unknown>): Record<string, unknown> {
  const dgiNumber = entry.dgi_number ?? entry.dgiNumber;
  return {
    dgi_number: dgiNumber,
    name: entry.name,
    tags: entry.tags ?? [],
    mandatory: entry.mandatory ?? false,
    source: entry.source ?? 'per_profile',
  };
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

router.get('/', async (req, res) => {
  const programId = typeof req.query.programId === 'string' ? req.query.programId : undefined;
  const profiles = await prisma.chipProfile.findMany({
    where: programId
      ? { OR: [{ programId }, { programId: null }] }
      : undefined,
    orderBy: { createdAt: 'desc' },
    include: { program: { select: { id: true, name: true } } },
  });
  res.json(profiles);
});

router.get('/:id', async (req, res) => {
  const profile = await prisma.chipProfile.findUnique({
    where: { id: req.params.id },
    include: { program: { select: { id: true, name: true } } },
  });
  if (!profile) {
    throw notFound('chip_profile_not_found', `ChipProfile ${req.params.id} not found`);
  }
  res.json(profile);
});

// POST — accepts either application/json or multipart/form-data.
// Multipart path reads the single `file` part, parses it as JSON, then
// runs the same Zod schema.  Either way, we normalise the dgi
// definitions to the snake_case shape @palisade/emv consumes.
router.post('/', async (req, res) => {
  const contentType = req.headers['content-type'] ?? '';
  let payload: unknown;
  if (contentType.startsWith('multipart/form-data')) {
    const text = await readMultipartFile(req);
    try {
      payload = JSON.parse(text);
    } catch {
      throw badRequest('invalid_json', 'Uploaded file is not valid JSON');
    }
  } else {
    payload = req.body;
  }
  const parsed = createSchema.parse(payload);
  // Drop a null programId so Prisma treats it as "no relation" rather
  // than rejecting `null` on the CreateInput.  Use the Unchecked variant
  // so programId can live on the payload directly (checked mode demands
  // program: { connect: { id } }).
  const { programId, ...rest } = parsed;
  const data: Prisma.ChipProfileUncheckedCreateInput = {
    ...rest,
    ...(programId ? { programId } : {}),
    dgiDefinitions: parsed.dgiDefinitions.map((d) =>
      canonicaliseDgi(d as Record<string, unknown>),
    ) as Prisma.InputJsonValue,
  };
  try {
    const profile = await prisma.chipProfile.create({
      data,
      include: { program: { select: { id: true, name: true } } },
    });
    res.status(201).json(profile);
  } catch (err: unknown) {
    const code = err && typeof err === 'object' && 'code' in err
      ? (err as { code?: string }).code
      : undefined;
    if (code === 'P2003') {
      throw notFound('related_not_found', 'Referenced programId does not exist');
    }
    throw err;
  }
});

router.patch('/:id', validateBody(patchSchema), async (req, res) => {
  const data = { ...req.body };
  if (Array.isArray(data.dgiDefinitions)) {
    data.dgiDefinitions = data.dgiDefinitions.map((d: Record<string, unknown>) =>
      canonicaliseDgi(d),
    );
  }
  try {
    const profile = await prisma.chipProfile.update({
      where: { id: req.params.id },
      data,
      include: { program: { select: { id: true, name: true } } },
    });
    res.json(profile);
  } catch (err: unknown) {
    const code = err && typeof err === 'object' && 'code' in err
      ? (err as { code?: string }).code
      : undefined;
    if (code === 'P2025') {
      throw notFound('chip_profile_not_found', `ChipProfile ${req.params.id} not found`);
    }
    if (code === 'P2003') {
      throw notFound('related_not_found', 'Referenced programId does not exist');
    }
    throw err;
  }
});

export default router;
