import { Router } from 'express';
import { createHash } from 'node:crypto';
import { prisma } from '@palisade/db';
import { notFound, badRequest, encrypt, EnvKeyProvider } from '@palisade/core';

// ---------------------------------------------------------------------------
// Embossing Templates — per-FI schema definitions describing how to parse
// their embossing files.  The raw template payload is AES-256-GCM encrypted
// at rest (separate keyspace from the vault PAN DEK — these files aren't
// cardholder data but may contain proprietary layout info worth protecting).
//
// Mounted under /api/admin/financial-institutions — the FI is the scoping
// unit, so every route is nested under /:fiId.
// ---------------------------------------------------------------------------

const router: Router = Router();

// Template encryption key — separate from vault PAN DEK.  Templates are
// per-FI format specifications, not cardholder data, but we still encrypt
// at rest because they may contain proprietary layout info.
function getTemplateKeyProvider(): EnvKeyProvider {
  return new EnvKeyProvider({
    activeVersion: Number(process.env.EMBOSSING_KEY_ACTIVE_VERSION ?? '1'),
    keys: { 1: process.env.EMBOSSING_KEY_V1 ?? '' },
  });
}

const MAX_TEMPLATE_SIZE = 10 * 1024 * 1024; // 10 MB

// GET /api/admin/financial-institutions/:fiId/embossing-templates
router.get('/:fiId/embossing-templates', async (req, res) => {
  const templates = await prisma.embossingTemplate.findMany({
    where: { financialInstitutionId: req.params.fiId },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      name: true,
      description: true,
      supportsVisa: true,
      supportsMastercard: true,
      supportsAmex: true,
      formatType: true,
      recordLength: true,
      fieldCount: true,
      templateFileName: true,
      templateSha256: true,
      uploadedBy: true,
      createdAt: true,
      updatedAt: true,
    },
  });
  res.json(templates);
});

// POST /api/admin/financial-institutions/:fiId/embossing-templates
// Multipart: file (template file) + text fields (name, description, formatType,
// supportsVisa, supportsMastercard, supportsAmex).
router.post('/:fiId/embossing-templates', async (req, res) => {
  const { fiId } = req.params;
  const fi = await prisma.financialInstitution.findUnique({ where: { id: fiId } });
  if (!fi) throw notFound('fi_not_found', 'Financial institution not found');

  const contentType = req.headers['content-type'] ?? '';
  if (!contentType.startsWith('multipart/form-data')) {
    throw badRequest('invalid_content_type', 'Expected multipart/form-data');
  }
  const boundary = contentType.match(/boundary=([^\s;]+)/)?.[1];
  if (!boundary) throw badRequest('missing_boundary', 'No multipart boundary');

  // Read raw body (bounded)
  const chunks: Buffer[] = [];
  let totalSize = 0;
  for await (const chunk of req) {
    const buf = Buffer.from(chunk);
    totalSize += buf.length;
    if (totalSize > MAX_TEMPLATE_SIZE) {
      throw badRequest('file_too_large', 'Template exceeds 10MB limit');
    }
    chunks.push(buf);
  }
  const body = Buffer.concat(chunks);
  const parts = parseMultipart(body, boundary);

  const filePart = parts.find((p) => p.name === 'file' && p.filename);
  if (!filePart) throw badRequest('missing_file', 'No template file');

  const name =
    parts.find((p) => p.name === 'name')?.data.toString('utf-8').trim() ||
    filePart.filename ||
    'untitled';
  const description =
    parts.find((p) => p.name === 'description')?.data.toString('utf-8').trim() || null;
  const formatType =
    parts.find((p) => p.name === 'formatType')?.data.toString('utf-8').trim() || 'episode_six';
  const supportsVisa =
    parts.find((p) => p.name === 'supportsVisa')?.data.toString('utf-8') === 'true';
  const supportsMastercard =
    parts.find((p) => p.name === 'supportsMastercard')?.data.toString('utf-8') === 'true';
  const supportsAmex =
    parts.find((p) => p.name === 'supportsAmex')?.data.toString('utf-8') === 'true';

  // Hash for integrity (over the plaintext template).
  const sha256 = createHash('sha256').update(filePart.data).digest('hex');

  // Encrypt the template body at rest — base64 the binary so the AES-GCM
  // envelope sees a stable utf-8 string.
  const kp = getTemplateKeyProvider();
  const enc = encrypt(filePart.data.toString('base64'), kp);

  // Parse metadata (format-specific — extract field count, record length)
  const { recordLength, fieldCount, parserMeta } = await introspectTemplate(
    filePart.data,
    formatType,
  );

  const cognitoUser = req.cognitoUser;
  const template = await prisma.embossingTemplate.create({
    data: {
      financialInstitutionId: fiId,
      name,
      description,
      supportsVisa,
      supportsMastercard,
      supportsAmex,
      formatType,
      templateEncrypted: Buffer.from(enc.ciphertext, 'base64'),
      templateKeyVersion: enc.keyVersion,
      templateSha256: sha256,
      templateFileName: filePart.filename ?? 'template.bin',
      recordLength,
      fieldCount,
      parserMeta: (parserMeta ?? undefined) as never,
      uploadedBy: cognitoUser?.sub ?? 'unknown',
    },
    select: {
      id: true,
      name: true,
      description: true,
      supportsVisa: true,
      supportsMastercard: true,
      supportsAmex: true,
      formatType: true,
      templateFileName: true,
      templateSha256: true,
      recordLength: true,
      fieldCount: true,
      uploadedBy: true,
      createdAt: true,
      updatedAt: true,
    },
  });

  res.status(201).json(template);
});

// DELETE template (refuses if in use by any program or batch)
router.delete('/:fiId/embossing-templates/:templateId', async (req, res) => {
  const { templateId } = req.params;
  const [template, programsUsing, batchesUsing] = await Promise.all([
    prisma.embossingTemplate.findUnique({ where: { id: templateId } }),
    prisma.program.count({ where: { embossingTemplateId: templateId } }),
    prisma.embossingBatch.count({ where: { templateId } }),
  ]);
  if (!template) throw notFound('template_not_found', 'Template not found');
  if (programsUsing > 0 || batchesUsing > 0) {
    throw badRequest(
      'template_in_use',
      `Template is used by ${programsUsing} program(s) and ${batchesUsing} batch(es)`,
    );
  }
  await prisma.embossingTemplate.delete({ where: { id: templateId } });
  res.json({ deleted: templateId });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface ParsedPart {
  name: string;
  filename?: string;
  data: Buffer;
}

/**
 * Minimal multipart/form-data parser — binary-safe, same approach used by
 * microsites.routes.ts so we don't drag multer/busboy in for one route.
 */
function parseMultipart(body: Buffer, boundary: string): ParsedPart[] {
  const parts: ParsedPart[] = [];
  const boundaryBuf = Buffer.from(`--${boundary}`);
  let pos = 0;
  while (pos < body.length) {
    const bIdx = body.indexOf(boundaryBuf, pos);
    if (bIdx === -1) break;
    const headerStart = bIdx + boundaryBuf.length + 2;
    if (headerStart >= body.length) break;
    const headerEnd = body.indexOf('\r\n\r\n', headerStart);
    if (headerEnd === -1) break;
    const headers = body.slice(headerStart, headerEnd).toString('utf-8');
    const dataStart = headerEnd + 4;
    const nextBIdx = body.indexOf(boundaryBuf, dataStart);
    if (nextBIdx === -1) break;
    const data = body.slice(dataStart, nextBIdx - 2);

    const nameMatch = headers.match(/name="([^"]+)"/);
    const filenameMatch = headers.match(/filename="([^"]+)"/);
    if (nameMatch) {
      parts.push({ name: nameMatch[1], filename: filenameMatch?.[1], data });
    }
    pos = nextBIdx;
  }
  return parts;
}

async function introspectTemplate(
  data: Buffer,
  formatType: string,
): Promise<{
  recordLength: number | null;
  fieldCount: number | null;
  parserMeta: unknown;
}> {
  // Stub — a real introspector would parse the file format.  For now we
  // return a length heuristic so the UI has something to display.  Per-format
  // parser plugins (Episode Six, fixed-width, etc.) ship in a follow-up PR.
  if (formatType === 'csv') {
    const firstLine = data.toString('utf-8').split('\n')[0] ?? '';
    const fieldCount = firstLine.split(',').length;
    return {
      recordLength: firstLine.length,
      fieldCount,
      parserMeta: { headers: firstLine.split(',') },
    };
  }
  return { recordLength: null, fieldCount: null, parserMeta: { rawSize: data.length } };
}

export default router;
