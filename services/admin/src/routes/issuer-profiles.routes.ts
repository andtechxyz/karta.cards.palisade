import { Router } from 'express';
import { z } from 'zod';
import { prisma } from '@palisade/db';
import { validateBody, notFound, conflict } from '@palisade/core';

// CRUD for IssuerProfile.  An IssuerProfile ties a Program to its chip
// applet behaviour (ChipProfile), its AWS Payment Cryptography key ARNs
// and its full EMV application constants.
//
// Mounted under /api/issuer-profiles behind the Cognito admin-group gate
// (see services/admin/src/index.ts).  No DELETE — deleting an issuer
// profile mid-flight would brick every provisioned card under the
// program; the right way to retire one is a (future) status/archival
// field.  The brief explicitly keeps that out of scope.

const router: Router = Router();

// Hex-string validator.  Empty string is allowed for every hex field
// because the schema defaults them to "" and the UI should be able to
// PATCH with a partial body that leaves other hex fields untouched.
const hexField = z.string().regex(/^[0-9A-Fa-f]*$/, 'must be a hex string');

// ARN fields are opaque strings.  They may start with `arn:` or with
// the `arn:stub:` prefix used by the dev seed.  Empty string is valid
// (stub key slot, set later).  We don't validate the ARN shape harder
// than "is a string, <= 2048 chars" — AWS has hundreds of valid
// formats and this is a trust-the-operator input.
const arnField = z.string().max(2048);

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

// Every field on IssuerProfile that the UI is allowed to set.  Required
// fields match the schema's required columns (no @default); everything
// else is optional.
const createSchema = z
  .object({
    programId: z.string().min(1).max(64),
    chipProfileId: z.string().min(1).max(64),

    // Scheme + CVN.  Both are required to build a SAD; guard the
    // enum so a typo doesn't silently create a profile that fails
    // at provisioning time.
    scheme: z.enum(['mchip_advance', 'vsdc']),
    cvn: z.coerce.number().int().min(0).max(255),
    imkAlgorithm: z.string().min(1).max(64).optional(),
    derivationMethod: z.string().min(1).max(64).optional(),

    // AWS Payment Cryptography key ARNs
    tmkKeyArn: arnField.optional(),
    imkAcKeyArn: arnField.optional(),
    imkSmiKeyArn: arnField.optional(),
    imkSmcKeyArn: arnField.optional(),
    imkIdnKeyArn: arnField.optional(),
    issuerPkKeyArn: arnField.optional(),

    // CA / Issuer PK certificates
    caPkIndex: hexField.max(4).optional(),
    issuerPkCertificate: hexField.max(8192).optional(),
    issuerPkRemainder: hexField.max(8192).optional(),
    issuerPkExponent: hexField.max(64).optional(),

    // EMV application parameters.  String ids (appLabel, appPreferredName)
    // are free-form; everything else is hex.
    aid: hexField.max(32).optional(),
    appLabel: z.string().max(64).optional(),
    appPreferredName: z.string().max(32).optional(),
    appPriority: hexField.max(4).optional(),
    appVersionNumber: hexField.max(8).optional(),
    aip: hexField.max(8).optional(),
    afl: hexField.max(128).optional(),
    cvmList: hexField.max(128).optional(),
    pdol: hexField.max(128).optional(),
    cdol1: hexField.max(128).optional(),
    cdol2: hexField.max(128).optional(),
    iacDefault: hexField.max(32).optional(),
    iacDenial: hexField.max(32).optional(),
    iacOnline: hexField.max(32).optional(),
    appUsageControl: hexField.max(8).optional(),
    currencyCode: hexField.max(8).optional(),
    currencyExponent: hexField.max(4).optional(),
    countryCode: hexField.max(8).optional(),
    sdaTagList: hexField.max(32).optional(),
  })
  .strict(); // reject unknown fields — no silent drops

const patchSchema = createSchema
  // programId is @unique — forbid moving an IssuerProfile between Programs.
  .omit({ programId: true })
  .partial()
  .strict()
  .refine((v) => Object.keys(v).length > 0, {
    message: 'at least one field must be supplied',
  });

// ---------------------------------------------------------------------------
// ARN masking helper
// ---------------------------------------------------------------------------

// On the list endpoint we hide ARNs behind a last-4-chars mask.  The
// detail endpoint returns them unredacted (admin group already).  This
// mirrors the "show sensitive creds only when explicitly requested"
// pattern used by partner-credentials.routes.ts.
const ARN_FIELDS = [
  'tmkKeyArn',
  'imkAcKeyArn',
  'imkSmiKeyArn',
  'imkSmcKeyArn',
  'imkIdnKeyArn',
  'issuerPkKeyArn',
] as const;

type ArnField = (typeof ARN_FIELDS)[number];

function maskArn(arn: string): string {
  if (!arn) return '';
  if (arn.length <= 4) return '***';
  return '***' + arn.slice(-4);
}

function maskArns<T extends Record<string, unknown>>(profile: T): T {
  const masked = { ...profile } as T & Record<ArnField, string>;
  for (const field of ARN_FIELDS) {
    const raw = profile[field];
    if (typeof raw === 'string') {
      masked[field] = maskArn(raw);
    }
  }
  return masked;
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

router.get('/', async (_req, res) => {
  const profiles = await prisma.issuerProfile.findMany({
    orderBy: { createdAt: 'desc' },
    include: {
      program: { select: { id: true, name: true } },
      chipProfile: { select: { id: true, name: true, scheme: true } },
    },
  });
  res.json(profiles.map(maskArns));
});

router.get('/:id', async (req, res) => {
  const profile = await prisma.issuerProfile.findUnique({
    where: { id: req.params.id },
    include: {
      program: { select: { id: true, name: true } },
      chipProfile: { select: { id: true, name: true, scheme: true } },
    },
  });
  if (!profile) {
    throw notFound('issuer_profile_not_found', `IssuerProfile ${req.params.id} not found`);
  }
  res.json(profile);
});

router.post('/', validateBody(createSchema), async (req, res) => {
  try {
    const profile = await prisma.issuerProfile.create({
      data: req.body,
      include: {
        program: { select: { id: true, name: true } },
        chipProfile: { select: { id: true, name: true, scheme: true } },
      },
    });
    res.status(201).json(profile);
  } catch (err: unknown) {
    const code = err && typeof err === 'object' && 'code' in err
      ? (err as { code?: string }).code
      : undefined;
    if (code === 'P2002') {
      throw conflict(
        'issuer_profile_program_conflict',
        'An IssuerProfile already exists for that programId',
      );
    }
    if (code === 'P2003' || code === 'P2025') {
      throw notFound(
        'related_not_found',
        'Referenced programId or chipProfileId does not exist',
      );
    }
    throw err;
  }
});

router.patch('/:id', validateBody(patchSchema), async (req, res) => {
  try {
    const profile = await prisma.issuerProfile.update({
      where: { id: req.params.id },
      data: req.body,
      include: {
        program: { select: { id: true, name: true } },
        chipProfile: { select: { id: true, name: true, scheme: true } },
      },
    });
    res.json(profile);
  } catch (err: unknown) {
    const code = err && typeof err === 'object' && 'code' in err
      ? (err as { code?: string }).code
      : undefined;
    if (code === 'P2025') {
      throw notFound('issuer_profile_not_found', `IssuerProfile ${req.params.id} not found`);
    }
    if (code === 'P2003') {
      throw notFound('related_not_found', 'Referenced chipProfileId does not exist');
    }
    throw err;
  }
});

export default router;
