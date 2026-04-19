import { Router } from 'express';
import { z } from 'zod';
import { validateBody, notFound, badRequest } from '@palisade/core';
import { prisma } from '@palisade/db';
import { request as undiciRequest } from 'undici';
import { signRequest } from '@palisade/service-auth';
import { getAdminConfig } from '../env.js';

// CRUD for ChipProfile, IssuerProfile, and read-only provisioning monitor.
// Mounted under /api/admin behind the same HMAC gate as other admin routes.

const router: Router = Router();

// ---------------------------------------------------------------------------
// Chip Profiles
// ---------------------------------------------------------------------------

const createChipProfileSchema = z.object({
  name: z.string().min(1).max(128),
  scheme: z.string().min(1),
  vendor: z.string().min(1),
  cvn: z.coerce.number().int(),
  dgiDefinitions: z.any(),
  elfAid: z.string().optional(),
  moduleAid: z.string().optional(),
  paAid: z.string().optional(),
  fidoAid: z.string().optional(),
  programId: z.string().optional(), // null = global, string = program-scoped
});

router.get('/chip-profiles', async (req, res) => {
  const programId = typeof req.query.programId === 'string' ? req.query.programId : undefined;
  const profiles = await prisma.chipProfile.findMany({
    where: programId
      ? { OR: [{ programId }, { programId: null }] } // program-scoped + global
      : undefined, // admin sees everything when no filter
    orderBy: { createdAt: 'desc' },
    include: { program: { select: { id: true, name: true } } },
  });
  res.json(profiles);
});

router.post('/chip-profiles', validateBody(createChipProfileSchema), async (req, res) => {
  const profile = await prisma.chipProfile.create({ data: req.body });
  res.status(201).json(profile);
});

router.get('/chip-profiles/:id', async (req, res) => {
  const profile = await prisma.chipProfile.findUnique({ where: { id: req.params.id } });
  if (!profile) throw notFound('chip_profile_not_found', `ChipProfile ${req.params.id} not found`);
  res.json(profile);
});

router.delete('/chip-profiles/:id', async (req, res) => {
  try {
    await prisma.chipProfile.delete({ where: { id: req.params.id } });
  } catch {
    throw notFound('chip_profile_not_found', `ChipProfile ${req.params.id} not found`);
  }
  res.json({ deleted: true });
});

// ---------------------------------------------------------------------------
// Issuer Profiles
// ---------------------------------------------------------------------------

// Issuer profile creation/update via browser is LIMITED to non-sensitive
// metadata.  AWS Payment Cryptography key ARNs (TMK, IMK-AC/SMI/SMC/IDN,
// Issuer PK) are set ONLY via the scripts/import-issuer-keys.ts CLI which
// takes TR-31 wrapped key blocks (dual-control ceremony), calls AWS PC
// ImportKey, records the ARN + KCV + audit entry.
// Prevents a compromised browser session from setting arbitrary key ARNs.
const createIssuerProfileSchema = z.object({
  programId: z.string().min(1),
  chipProfileId: z.string().min(1),
  scheme: z.string().min(1),
  cvn: z.coerce.number().int(),
  imkAlgorithm: z.string().optional(),
  derivationMethod: z.string().optional(),
  aid: z.string().optional(),
  appLabel: z.string().optional(),
}).strict(); // reject unknown fields — no ARN injection

const patchIssuerProfileSchema = createIssuerProfileSchema
  .partial()
  .refine((v) => Object.keys(v).length > 0, {
    message: 'at least one field must be supplied',
  });

router.get('/issuer-profiles', async (_req, res) => {
  const profiles = await prisma.issuerProfile.findMany({
    include: { program: { select: { id: true, name: true } }, chipProfile: { select: { id: true, name: true } } },
    orderBy: { createdAt: 'desc' },
  });
  res.json(profiles);
});

router.post('/issuer-profiles', validateBody(createIssuerProfileSchema), async (req, res) => {
  const profile = await prisma.issuerProfile.create({ data: req.body });
  res.status(201).json(profile);
});

router.patch('/issuer-profiles/:id', validateBody(patchIssuerProfileSchema), async (req, res) => {
  try {
    const profile = await prisma.issuerProfile.update({
      where: { id: req.params.id },
      data: req.body,
    });
    res.json(profile);
  } catch {
    throw notFound('issuer_profile_not_found', `IssuerProfile ${req.params.id} not found`);
  }
});

// ---------------------------------------------------------------------------
// Provisioning Monitor
// ---------------------------------------------------------------------------

router.get('/provisioning/stats', async (_req, res) => {
  const now = new Date();
  const twentyFourHoursAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);

  const [activeSessions, provisioned24h, totalProvisioned, failedSessions24h] = await Promise.all([
    prisma.provisioningSession.count({
      where: { phase: { notIn: ['COMPLETE', 'FAILED'] } },
    }),
    prisma.provisioningSession.count({
      where: { phase: 'COMPLETE', completedAt: { gte: twentyFourHoursAgo } },
    }),
    prisma.provisioningSession.count({
      where: { phase: 'COMPLETE' },
    }),
    prisma.provisioningSession.count({
      where: { phase: 'FAILED', failedAt: { gte: twentyFourHoursAgo } },
    }),
  ]);

  res.json({ activeSessions, provisioned24h, totalProvisioned, failedSessions24h });
});

router.get('/provisioning/sessions', async (req, res) => {
  const limit = Math.min(Number(req.query.limit) || 50, 200);
  const offset = Number(req.query.offset) || 0;

  const sessions = await prisma.provisioningSession.findMany({
    take: limit,
    skip: offset,
    orderBy: { createdAt: 'desc' },
    include: {
      card: { select: { id: true, cardRef: true, status: true } },
      sadRecord: { select: { id: true, proxyCardId: true, status: true } },
    },
  });
  res.json(sessions);
});

// ---------------------------------------------------------------------------
// Batch CSV ingestion
// ---------------------------------------------------------------------------

// Expected CSV columns (header row required):
// card_ref, ntag_uid, chip_serial, sdm_meta_read_key, sdm_file_read_key,
// pan, expiry_month, expiry_year, cardholder_name, service_code,
// card_sequence_number

const REQUIRED_CSV_HEADERS = [
  'card_ref', 'ntag_uid', 'chip_serial', 'sdm_meta_read_key', 'sdm_file_read_key',
  'pan', 'expiry_month', 'expiry_year', 'cardholder_name',
] as const;

interface BatchRowError {
  row: number;
  cardRef: string;
  error: string;
}

/**
 * Parse a multipart/form-data request manually — no library dependency.
 * Returns the file content as a string and the programId form field.
 */
async function parseMultipart(req: import('express').Request): Promise<{ csv: string; programId: string }> {
  const contentType = req.headers['content-type'] ?? '';
  const match = contentType.match(/boundary=([^\s;]+)/);
  if (!match) throw badRequest('missing_boundary', 'Content-Type must be multipart/form-data with a boundary');

  const raw = await new Promise<Buffer>((resolve, reject) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });

  const boundary = '--' + match[1];
  const text = raw.toString('utf8');
  const parts = text.split(boundary).filter((p) => p.trim() && p.trim() !== '--');

  let csv: string | null = null;
  let programId: string | null = null;

  for (const part of parts) {
    const headerEnd = part.indexOf('\r\n\r\n');
    if (headerEnd < 0) continue;
    const headers = part.slice(0, headerEnd);
    const body = part.slice(headerEnd + 4).replace(/\r\n$/, '');

    if (headers.includes('name="programId"')) {
      programId = body.trim();
    } else if (headers.includes('name="file"')) {
      csv = body;
    }
  }

  if (!csv) throw badRequest('missing_csv', 'No CSV file found in the upload');
  if (!programId) throw badRequest('missing_program_id', 'programId form field is required');

  return { csv, programId };
}

/**
 * Parse CSV text using a simple line-by-line approach.
 * First row is headers, remaining rows are data.
 */
function parseCsv(text: string): Record<string, string>[] {
  const lines = text.split(/\r?\n/).filter((l) => l.trim());
  if (lines.length < 2) throw badRequest('csv_empty', 'CSV must have a header row and at least one data row');

  const headers = lines[0].split(',').map((h) => h.trim());
  const missing = REQUIRED_CSV_HEADERS.filter((h) => !headers.includes(h));
  if (missing.length > 0) {
    throw badRequest('csv_missing_headers', `Missing required CSV columns: ${missing.join(', ')}`);
  }

  return lines.slice(1).map((line) => {
    const values = line.split(',').map((v) => v.trim());
    const row: Record<string, string> = {};
    headers.forEach((h, i) => {
      row[h] = values[i] ?? '';
    });
    return row;
  });
}

router.post('/batches/ingest', async (req, res) => {
  const { csv, programId } = await parseMultipart(req);
  const rows = parseCsv(csv);

  const batchId = `batch_${Date.now()}`;
  const config = getAdminConfig();
  const activationUrl = config.ACTIVATION_SERVICE_URL.replace(/\/$/, '');

  const errors: BatchRowError[] = [];
  let succeeded = 0;

  for (let i = 0; i < rows.length; i++) {
    const row = rows[i];
    const cardRef = row.card_ref;

    try {
      const registerBody = {
        cardRef,
        uid: row.ntag_uid,
        chipSerial: row.chip_serial || undefined,
        sdmMetaReadKey: row.sdm_meta_read_key,
        sdmFileReadKey: row.sdm_file_read_key,
        programId,
        batchId,
        card: {
          pan: row.pan,
          expiryMonth: row.expiry_month.padStart(2, '0'),
          expiryYear: row.expiry_year,
          cardholderName: row.cardholder_name,
        },
      };

      const bodyBytes = Buffer.from(JSON.stringify(registerBody), 'utf8');
      const pathAndQuery = '/api/cards/register';
      const authorization = signRequest({
        method: 'POST',
        pathAndQuery,
        body: bodyBytes,
        keyId: 'admin',
        secret: config.SERVICE_AUTH_ADMIN_SECRET,
      });

      const { statusCode, body: respBody } = await undiciRequest(`${activationUrl}${pathAndQuery}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization,
        },
        body: bodyBytes,
      });

      if (statusCode >= 400) {
        const text = await respBody.text();
        let errorCode = `http_${statusCode}`;
        try {
          const parsed = JSON.parse(text) as { error?: { code?: string } };
          if (parsed.error?.code) errorCode = parsed.error.code;
        } catch { /* non-JSON response */ }
        errors.push({ row: i + 1, cardRef, error: errorCode });
      } else {
        // Drain the response body
        await respBody.text();
        succeeded++;
      }
    } catch (err) {
      errors.push({
        row: i + 1,
        cardRef,
        error: err instanceof Error ? err.message : 'unknown_error',
      });
    }
  }

  res.json({
    batchId,
    total: rows.length,
    succeeded,
    failed: errors.length,
    errors,
  });
});

export default router;
