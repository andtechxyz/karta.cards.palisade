import { Router } from 'express';
import { createHash, randomUUID } from 'node:crypto';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { prisma } from '@palisade/db';
import { badRequest, notFound, forbidden } from '@palisade/core';
import { userCanAccessProgram } from '@palisade/cognito-auth';
import { getAdminConfig } from '../env.js';

// ---------------------------------------------------------------------------
// Embossing Batches — actual card-data files uploaded by admins / partners.
//
// The raw file is stored encrypted in a dedicated S3 bucket (SSE-KMS) and
// retained for audit + reprocessing.  A background worker (separate PR)
// parses the records and routes each through the existing vault registerCard
// flow so PANs are never persisted in clear on this path.
// ---------------------------------------------------------------------------

const router: Router = Router();
const s3 = new S3Client({ region: 'ap-southeast-2' });
const MAX_BATCH_SIZE = 500 * 1024 * 1024; // 500 MB

// GET /api/admin/programs/:programId/embossing-batches
router.get('/:programId/embossing-batches', async (req, res) => {
  // Stage I.2 — program-scoped RBAC.  EmbossingBatch.programId is required,
  // and the programId is in the path, so the gate is direct.
  if (!userCanAccessProgram(req.cognitoUser!, req.params.programId)) {
    throw forbidden(
      'forbidden_program_scope',
      `You are not scoped to program ${req.params.programId}`,
    );
  }
  const batches = await prisma.embossingBatch.findMany({
    where: { programId: req.params.programId },
    orderBy: { uploadedAt: 'desc' },
    include: { template: { select: { id: true, name: true } } },
    take: 100,
  });
  res.json(batches);
});

// POST /api/admin/programs/:programId/embossing-batches
// Multipart: file, templateId
router.post('/:programId/embossing-batches', async (req, res) => {
  const { programId } = req.params;
  if (!userCanAccessProgram(req.cognitoUser!, programId)) {
    throw forbidden(
      'forbidden_program_scope',
      `You are not scoped to program ${programId}`,
    );
  }
  const program = await prisma.program.findUnique({ where: { id: programId } });
  if (!program) throw notFound('program_not_found', 'Program not found');

  const contentType = req.headers['content-type'] ?? '';
  if (!contentType.startsWith('multipart/form-data')) {
    throw badRequest('invalid_content_type', 'Expected multipart/form-data');
  }
  const boundary = contentType.match(/boundary=([^\s;]+)/)?.[1];
  if (!boundary) throw badRequest('missing_boundary', 'No multipart boundary');

  const chunks: Buffer[] = [];
  let totalSize = 0;
  for await (const chunk of req) {
    const buf = Buffer.from(chunk);
    totalSize += buf.length;
    if (totalSize > MAX_BATCH_SIZE) {
      throw badRequest('file_too_large', 'Batch exceeds 500MB limit');
    }
    chunks.push(buf);
  }
  const body = Buffer.concat(chunks);
  const parts = parseMultipart(body, boundary);

  const filePart = parts.find((p) => p.name === 'file' && p.filename);
  if (!filePart) throw badRequest('missing_file', 'No batch file');

  const templateId = parts.find((p) => p.name === 'templateId')?.data.toString('utf-8').trim();
  if (!templateId) throw badRequest('missing_template_id', 'templateId required');
  const template = await prisma.embossingTemplate.findUnique({ where: { id: templateId } });
  if (!template) throw notFound('template_not_found', 'Template not found');

  // Hash + upload encrypted to S3 (SSE-KMS)
  const sha256 = createHash('sha256').update(filePart.data).digest('hex');
  const config = getAdminConfig();
  const bucket = config.EMBOSSING_BUCKET;
  const s3Key = `batches/${programId}/${Date.now()}_${randomUUID()}/${filePart.filename}`;

  await s3.send(
    new PutObjectCommand({
      Bucket: bucket,
      Key: s3Key,
      Body: filePart.data,
      ServerSideEncryption: 'aws:kms',
      SSEKMSKeyId: config.EMBOSSING_KMS_KEY_ARN || undefined,
      ContentType: 'application/octet-stream',
      Metadata: { sha256, programId, templateId },
    }),
  );

  const cognitoUser = req.cognitoUser;
  const batch = await prisma.embossingBatch.create({
    data: {
      templateId,
      programId,
      fileName: filePart.filename ?? 'batch.bin',
      fileSize: filePart.data.length,
      sha256,
      s3Bucket: bucket,
      s3Key,
      status: 'RECEIVED',
      uploadedVia: 'UI',
      uploadedBy: cognitoUser?.sub ?? 'unknown',
    },
  });

  res.status(201).json({
    id: batch.id,
    status: batch.status,
    fileName: batch.fileName,
    fileSize: batch.fileSize,
    sha256: batch.sha256,
    uploadedAt: batch.uploadedAt,
  });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface ParsedPart {
  name: string;
  filename?: string;
  data: Buffer;
}

/** Minimal multipart/form-data parser — binary-safe; same shape as microsites. */
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

export default router;
