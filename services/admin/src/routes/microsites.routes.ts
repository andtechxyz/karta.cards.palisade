import { Router } from 'express';
import { S3Client, PutObjectCommand, DeleteObjectsCommand, ListObjectsV2Command, CopyObjectCommand } from '@aws-sdk/client-s3';
import type { Request, Response, NextFunction } from 'express';
import AdmZip from 'adm-zip';
import { prisma } from '@palisade/db';
import { badRequest, notFound, forbidden } from '@palisade/core';
import { userCanAccessProgram } from '@palisade/cognito-auth';
import { getAdminConfig } from '../env.js';

// Stage I.2 — program-scoped RBAC.  Every microsites route is nested
// under :programId, so a single param-extraction middleware does the
// gate.  Mounted as `router.param('programId', ...)`; runs once per
// request before the matching handler.
function requireProgramAccess(
  req: Request,
  _res: Response,
  next: NextFunction,
  programId: string,
): void {
  if (!userCanAccessProgram(req.cognitoUser!, programId)) {
    throw forbidden(
      'forbidden_program_scope',
      `You are not scoped to program ${programId}`,
    );
  }
  next();
}

// ---------------------------------------------------------------------------
// Microsites — per-program static websites served from S3+CloudFront.
//
// Admins upload a zip containing the site (HTML/CSS/JS/images).  The backend:
//   1. Validates the zip contains an index.html.
//   2. Uploads every entry under a unique prefix
//      `programs/<programId>/<versionId>/...`.
//   3. Creates a MicrositeVersion row as an immutable record of the upload.
//
// A separate "activate" call flips Program.micrositeEnabled + the active
// version pointer.  CloudFront (configured outside this service) reads the
// active pointer to rewrite request paths.
// ---------------------------------------------------------------------------

const router: Router = Router();
router.param('programId', requireProgramAccess);
const s3 = new S3Client({ region: 'ap-southeast-2' });

// Maximum upload size — 100 MB is plenty for a static site; any bigger is
// probably a mistake.  Enforced before we bother parsing the zip.
const MAX_UPLOAD_BYTES = 100 * 1024 * 1024;

// ---------------------------------------------------------------------------
// GET /api/admin/programs/:programId/microsites — list versions
// ---------------------------------------------------------------------------
router.get('/programs/:programId/microsites', async (req, res) => {
  const program = await prisma.program.findUnique({
    where: { id: req.params.programId },
    include: { micrositeVersions: { orderBy: { createdAt: 'desc' } } },
  });
  if (!program) throw notFound('program_not_found', `Program ${req.params.programId} not found`);

  res.json({
    programId: program.id,
    enabled: program.micrositeEnabled,
    activeVersion: program.micrositeActiveVersion,
    versions: program.micrositeVersions,
  });
});

// ---------------------------------------------------------------------------
// POST /api/admin/programs/:programId/microsites — upload zip
//
// Expects multipart/form-data with:
//   - file:    the zip archive (required, must contain index.html)
//   - version: human-readable version label (optional, defaults to timestamp)
//
// On success returns 201 with the created MicrositeVersion row.
// ---------------------------------------------------------------------------
router.post('/programs/:programId/microsites', async (req, res) => {
  const { programId } = req.params;
  const program = await prisma.program.findUnique({ where: { id: programId } });
  if (!program) throw notFound('program_not_found', `Program ${programId} not found`);

  const contentType = req.headers['content-type'] ?? '';
  if (!contentType.startsWith('multipart/form-data')) {
    throw badRequest('invalid_content_type', 'Expected multipart/form-data');
  }
  const boundary = contentType.match(/boundary=([^\s;]+)/)?.[1];
  if (!boundary) throw badRequest('missing_boundary', 'No multipart boundary');

  // Read raw body up to MAX_UPLOAD_BYTES; abort if exceeded.
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    const buf = Buffer.from(chunk);
    total += buf.length;
    if (total > MAX_UPLOAD_BYTES) {
      throw badRequest('upload_too_large', `Upload exceeds ${MAX_UPLOAD_BYTES} bytes`);
    }
    chunks.push(buf);
  }
  const body = Buffer.concat(chunks);

  const parts = parseMultipart(body, boundary);
  const versionLabel = parts.find((p) => p.name === 'version')?.data.toString('utf-8').trim() || `v${Date.now()}`;
  const zipPart = parts.find((p) => p.name === 'file' && p.filename);
  if (!zipPart) throw badRequest('missing_file', 'No zip file uploaded');

  let zip: AdmZip;
  try {
    zip = new AdmZip(zipPart.data);
  } catch {
    throw badRequest('invalid_zip', 'Uploaded file is not a valid zip');
  }
  const entries = zip.getEntries().filter((e) => !e.isDirectory);
  if (entries.length === 0) throw badRequest('empty_zip', 'Zip contains no files');
  if (!entries.some((e) => e.entryName === 'index.html' || e.entryName.endsWith('/index.html'))) {
    throw badRequest('missing_index', 'Zip must contain index.html');
  }
  // Reject entries that try to escape the prefix via path traversal.
  if (entries.some((e) => e.entryName.includes('..') || e.entryName.startsWith('/'))) {
    throw badRequest('invalid_entry_name', 'Zip contains entries with unsafe paths');
  }

  const config = getAdminConfig();
  const cognitoUser = req.cognitoUser;
  const versionId = `v_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const prefix = `programs/${programId}/${versionId}/`;
  let totalBytes = 0;

  for (const entry of entries) {
    const key = `${prefix}${entry.entryName}`;
    const data = entry.getData();
    totalBytes += data.length;
    const contentTypeGuess = guessContentType(entry.entryName);
    await s3.send(new PutObjectCommand({
      Bucket: config.MICROSITE_BUCKET,
      Key: key,
      Body: data,
      ContentType: contentTypeGuess,
      CacheControl: contentTypeGuess.startsWith('text/html') ? 'no-cache' : 'public, max-age=86400',
    }));
  }

  const mv = await prisma.micrositeVersion.create({
    data: {
      programId,
      version: versionLabel,
      s3Prefix: prefix,
      uploadedBy: cognitoUser?.sub ?? 'unknown',
      fileCount: entries.length,
      totalBytes,
    },
  });

  res.status(201).json(mv);
});

// ---------------------------------------------------------------------------
// POST /api/admin/programs/:programId/microsites/:versionId/activate
// ---------------------------------------------------------------------------
router.post('/programs/:programId/microsites/:versionId/activate', async (req, res) => {
  const { programId, versionId } = req.params;
  const mv = await prisma.micrositeVersion.findFirst({ where: { id: versionId, programId } });
  if (!mv) throw notFound('version_not_found', `Microsite version ${versionId} not found`);

  const config = getAdminConfig();
  const bucket = config.MICROSITE_BUCKET;
  const currentPrefix = `programs/${programId}/current/`;

  // Clear the existing current/ prefix
  const existing = await s3.send(new ListObjectsV2Command({ Bucket: bucket, Prefix: currentPrefix }));
  if (existing.Contents && existing.Contents.length > 0) {
    await s3.send(new DeleteObjectsCommand({
      Bucket: bucket,
      Delete: { Objects: existing.Contents.map(o => ({ Key: o.Key! })) },
    }));
  }

  // Copy from versioned prefix to current/ so CloudFront serves the active
  // version directly at microsite.karta.cards/programs/<id>/... without needing
  // a CloudFront Function or KVS lookup.
  let continuationToken: string | undefined;
  do {
    const listResp = await s3.send(new ListObjectsV2Command({
      Bucket: bucket, Prefix: mv.s3Prefix, ContinuationToken: continuationToken,
    }));
    for (const obj of listResp.Contents ?? []) {
      if (!obj.Key) continue;
      const relKey = obj.Key.slice(mv.s3Prefix.length);
      await s3.send(new CopyObjectCommand({
        Bucket: bucket,
        CopySource: `${bucket}/${encodeURIComponent(obj.Key)}`,
        Key: `${currentPrefix}${relKey}`,
        MetadataDirective: 'COPY',
      }));
    }
    continuationToken = listResp.IsTruncated ? listResp.NextContinuationToken : undefined;
  } while (continuationToken);

  await prisma.program.update({
    where: { id: programId },
    data: { micrositeEnabled: true, micrositeActiveVersion: versionId },
  });

  res.json({ activated: versionId });
});

// ---------------------------------------------------------------------------
// POST /api/admin/programs/:programId/microsites/disable
// Clears the enabled flag but keeps versions + active pointer intact so
// re-enabling is a single flag flip.
// ---------------------------------------------------------------------------
router.post('/programs/:programId/microsites/disable', async (req, res) => {
  const program = await prisma.program.findUnique({ where: { id: req.params.programId } });
  if (!program) throw notFound('program_not_found', `Program ${req.params.programId} not found`);
  await prisma.program.update({
    where: { id: req.params.programId },
    data: { micrositeEnabled: false },
  });
  res.json({ disabled: true });
});

// ---------------------------------------------------------------------------
// DELETE /api/admin/programs/:programId/microsites/:versionId
// Wipes every S3 object under the version's prefix, then removes the row.
// Refuses to delete the currently active version.
// ---------------------------------------------------------------------------
router.delete('/programs/:programId/microsites/:versionId', async (req, res) => {
  const { programId, versionId } = req.params;
  const program = await prisma.program.findUnique({ where: { id: programId } });
  if (!program) throw notFound('program_not_found', `Program ${programId} not found`);
  if (program.micrositeActiveVersion === versionId) {
    throw badRequest('version_is_active', 'Cannot delete the currently active version');
  }
  const mv = await prisma.micrositeVersion.findFirst({ where: { id: versionId, programId } });
  if (!mv) throw notFound('version_not_found', `Microsite version ${versionId} not found`);

  const config = getAdminConfig();
  // List + delete in chunks of 1000 (S3 DeleteObjects limit).
  let continuationToken: string | undefined;
  do {
    const list = await s3.send(new ListObjectsV2Command({
      Bucket: config.MICROSITE_BUCKET,
      Prefix: mv.s3Prefix,
      ContinuationToken: continuationToken,
    }));
    if (list.Contents && list.Contents.length > 0) {
      await s3.send(new DeleteObjectsCommand({
        Bucket: config.MICROSITE_BUCKET,
        Delete: { Objects: list.Contents.map((o) => ({ Key: o.Key! })) },
      }));
    }
    continuationToken = list.IsTruncated ? list.NextContinuationToken : undefined;
  } while (continuationToken);

  await prisma.micrositeVersion.delete({ where: { id: versionId } });
  res.json({ deleted: versionId });
});

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

interface MultipartPart {
  name: string;
  filename?: string;
  data: Buffer;
}

/**
 * Minimal multipart/form-data parser — we avoid adding multer/busboy just for
 * this one route.  Works on the binary-safe Buffer directly so zip payloads
 * aren't corrupted by utf-8 roundtrips.
 */
function parseMultipart(body: Buffer, boundary: string): MultipartPart[] {
  const parts: MultipartPart[] = [];
  const boundaryBuf = Buffer.from(`--${boundary}`);
  let pos = 0;
  while (pos < body.length) {
    const bIdx = body.indexOf(boundaryBuf, pos);
    if (bIdx === -1) break;
    const headerStart = bIdx + boundaryBuf.length + 2; // skip CRLF after boundary
    if (headerStart >= body.length) break;
    const headerEnd = body.indexOf('\r\n\r\n', headerStart);
    if (headerEnd === -1) break;
    const headers = body.slice(headerStart, headerEnd).toString('utf-8');
    const dataStart = headerEnd + 4;
    const nextBIdx = body.indexOf(boundaryBuf, dataStart);
    if (nextBIdx === -1) break;
    const dataEnd = nextBIdx - 2; // strip trailing CRLF before next boundary
    const data = body.slice(dataStart, dataEnd);

    const nameMatch = headers.match(/name="([^"]+)"/);
    const filenameMatch = headers.match(/filename="([^"]+)"/);
    if (nameMatch) {
      parts.push({ name: nameMatch[1], filename: filenameMatch?.[1], data });
    }
    pos = nextBIdx;
  }
  return parts;
}

function guessContentType(path: string): string {
  const ext = path.split('.').pop()?.toLowerCase();
  const map: Record<string, string> = {
    html: 'text/html; charset=utf-8',
    htm: 'text/html; charset=utf-8',
    css: 'text/css; charset=utf-8',
    js: 'application/javascript; charset=utf-8',
    mjs: 'application/javascript; charset=utf-8',
    json: 'application/json',
    xml: 'application/xml',
    txt: 'text/plain; charset=utf-8',
    png: 'image/png',
    jpg: 'image/jpeg',
    jpeg: 'image/jpeg',
    gif: 'image/gif',
    svg: 'image/svg+xml',
    webp: 'image/webp',
    ico: 'image/x-icon',
    woff: 'font/woff',
    woff2: 'font/woff2',
    ttf: 'font/ttf',
    otf: 'font/otf',
    mp4: 'video/mp4',
    webm: 'video/webm',
    mp3: 'audio/mpeg',
    ogg: 'audio/ogg',
    pdf: 'application/pdf',
  };
  return (ext && map[ext]) ?? 'application/octet-stream';
}

export default router;
