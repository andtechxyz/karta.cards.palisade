/**
 * SFTP ingester — scans partner upload dirs for new files and ingests them
 * into the batch pipeline.
 *
 * Directory convention (per-user chroot):
 *
 *   /home/<fi-slug>/upload/<programId>/<templateId>/<filename>
 *
 * The SFTP username matches FinancialInstitution.slug — it's what we chroot
 * the user to and how we authorise the batch (the template and program
 * referenced in the path must both belong to that FI).
 *
 * Each file is only processed once it has been stable (size + mtime
 * unchanged) for SFTP_STABILITY_MS — avoids picking up partial uploads from
 * a still-running SFTP put.
 *
 * On success the file is moved to
 *   /home/<fi-slug>/processed/<yyyy-mm-dd>/<filename>
 * so the partner can confirm it was picked up.  On failure it goes to
 *   /home/<fi-slug>/failed/<yyyy-mm-dd>/<filename>
 * with an adjacent `.err` file containing the reason.
 */
import { createHash, randomUUID } from 'node:crypto';
import { promises as fs } from 'node:fs';
import path from 'node:path';
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3';
import { prisma } from '@palisade/db';

import { getSftpConfig } from './env.js';

interface StableCandidate {
  size: number;
  mtimeMs: number;
  /** First tick we observed this exact (size, mtime) — file is "stable"
   *  once `now - stableSince >= SFTP_STABILITY_MS`. */
  stableSince: number;
}

// Module-scoped so stability state persists across scan ticks.
const stableCache = new Map<string, StableCandidate>();

let s3Instance: S3Client | null = null;
function s3(region: string): S3Client {
  if (!s3Instance) s3Instance = new S3Client({ region });
  return s3Instance;
}

export async function scanOnce(): Promise<void> {
  const config = getSftpConfig();
  const base = config.SFTP_HOME_BASE;

  let fiDirs: string[];
  try {
    fiDirs = (await fs.readdir(base, { withFileTypes: true }))
      .filter((d) => d.isDirectory())
      .map((d) => d.name);
  } catch {
    return; // base dir missing — early startup or empty env
  }

  const now = Date.now();

  for (const fiSlug of fiDirs) {
    const uploadRoot = path.join(base, fiSlug, 'upload');
    const files = await walk(uploadRoot);

    for (const absPath of files) {
      try {
        const stat = await fs.stat(absPath);
        if (!stat.isFile()) continue;

        const cached = stableCache.get(absPath);
        if (!cached || cached.size !== stat.size || cached.mtimeMs !== stat.mtimeMs) {
          // First time we've seen it, OR it changed since last tick — reset
          // the stability timer.
          stableCache.set(absPath, {
            size: stat.size,
            mtimeMs: stat.mtimeMs,
            stableSince: now,
          });
          continue;
        }

        if (now - cached.stableSince < config.SFTP_STABILITY_MS) continue;

        // Stable — claim it out of the cache before processing so we don't
        // re-enter if ingestion is slow.
        stableCache.delete(absPath);
        await ingestOne(absPath, fiSlug, config);
      } catch (err) {
        console.error(
          `[sftp-ingester] unexpected error on ${absPath}:`,
          err instanceof Error ? err.message : err,
        );
      }
    }
  }
}

async function walk(dir: string): Promise<string[]> {
  const out: string[] = [];
  let entries;
  try {
    entries = await fs.readdir(dir, { withFileTypes: true });
  } catch {
    return out;
  }
  for (const entry of entries) {
    const abs = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await walk(abs)));
    } else if (entry.isFile()) {
      out.push(abs);
    }
  }
  return out;
}

async function ingestOne(
  absPath: string,
  fiSlug: string,
  config: ReturnType<typeof getSftpConfig>,
): Promise<void> {
  const home = path.join(config.SFTP_HOME_BASE, fiSlug);
  const uploadRoot = path.join(home, 'upload');
  const rel = path.relative(uploadRoot, absPath);
  const parts = rel.split(path.sep);

  if (parts.length !== 3) {
    await moveToFailed(
      absPath,
      home,
      `Unexpected path depth — expected upload/<programId>/<templateId>/<file>, got ${rel}`,
    );
    return;
  }
  const [programId, templateId, fileName] = parts;

  const [fi, template, program] = await Promise.all([
    prisma.financialInstitution.findUnique({ where: { slug: fiSlug } }),
    prisma.embossingTemplate.findUnique({ where: { id: templateId } }),
    prisma.program.findUnique({ where: { id: programId } }),
  ]);
  if (!fi) {
    await moveToFailed(absPath, home, `Unknown FI slug "${fiSlug}"`);
    return;
  }
  if (!template) {
    await moveToFailed(absPath, home, `Unknown templateId "${templateId}"`);
    return;
  }
  if (!program) {
    await moveToFailed(absPath, home, `Unknown programId "${programId}"`);
    return;
  }
  // FI scope — same checks as the HTTP partner ingestion route.  A partner
  // must not be able to upload against a template or program that doesn't
  // belong to their FI.
  if (template.financialInstitutionId !== fi.id) {
    await moveToFailed(absPath, home, 'Template does not belong to this FI');
    return;
  }
  if (program.financialInstitutionId && program.financialInstitutionId !== fi.id) {
    await moveToFailed(absPath, home, 'Program does not belong to this FI');
    return;
  }

  const body = await fs.readFile(absPath);
  if (body.length === 0) {
    await moveToFailed(absPath, home, 'File is empty');
    return;
  }

  const sha256 = createHash('sha256').update(body).digest('hex');
  const s3Key = `batches/${programId}/${Date.now()}_${randomUUID()}/${fileName}`;

  await s3(config.AWS_REGION).send(
    new PutObjectCommand({
      Bucket: config.EMBOSSING_BUCKET,
      Key: s3Key,
      Body: body,
      ServerSideEncryption: 'aws:kms',
      SSEKMSKeyId: config.EMBOSSING_KMS_KEY_ARN || undefined,
      ContentType: 'application/octet-stream',
      Metadata: { sha256, programId, templateId, sftpUser: fiSlug },
    }),
  );

  const batch = await prisma.embossingBatch.create({
    data: {
      templateId,
      programId,
      fileName,
      fileSize: body.length,
      sha256,
      s3Bucket: config.EMBOSSING_BUCKET,
      s3Key,
      status: 'RECEIVED',
      uploadedVia: 'SFTP',
      uploadedBy: fiSlug,
    },
    select: { id: true },
  });

  await moveToProcessed(absPath, home);
  console.log(
    `[sftp-ingester] ${fiSlug}: ${fileName} → batch ${batch.id} (${body.length} bytes, sha256=${sha256.slice(0, 12)}…)`,
  );
}

async function moveToProcessed(absPath: string, home: string): Promise<void> {
  const today = new Date().toISOString().slice(0, 10);
  const dest = path.join(home, 'processed', today, path.basename(absPath));
  await fs.mkdir(path.dirname(dest), { recursive: true });
  await fs.rename(absPath, dest);
}

async function moveToFailed(absPath: string, home: string, reason: string): Promise<void> {
  const today = new Date().toISOString().slice(0, 10);
  const dest = path.join(home, 'failed', today, path.basename(absPath));
  try {
    await fs.mkdir(path.dirname(dest), { recursive: true });
    await fs.rename(absPath, dest);
    await fs.writeFile(`${dest}.err`, `${reason}\n`, 'utf8');
  } catch (err) {
    console.error(
      `[sftp-ingester] could not move ${absPath} to failed/: ${err instanceof Error ? err.message : err}`,
    );
  }
  console.warn(`[sftp-ingester] rejected ${absPath}: ${reason}`);
}
