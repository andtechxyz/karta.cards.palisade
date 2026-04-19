/**
 * Batch processor — the core loop.
 *
 * Scans for EmbossingBatch rows with status=RECEIVED, processes each:
 *   1. Decrypt the linked EmbossingTemplate (AES-256-GCM).
 *   2. Download the batch file from S3 (SSE-KMS auto-decrypts).
 *   3. Pick the parser by template.formatType, call parse().
 *   4. For each successful record: HMAC-signed POST to
 *      activation's /api/cards/register.
 *   5. Update the batch with counts + status PROCESSED/FAILED.
 *
 * The raw batch file stays in S3 (encrypted) for audit/reprocessing.
 * PANs never live outside the vault after processing completes.
 */

import { createHash, randomBytes } from 'node:crypto';
import { S3Client, GetObjectCommand } from '@aws-sdk/client-s3';
import { prisma } from '@palisade/db';
import { decrypt, EnvKeyProvider } from '@palisade/core';
import { getParser, type EmbossingRecord } from '@palisade/emv';
import { signRequest } from '@palisade/service-auth';
import { request } from 'undici';

import { getBatchConfig } from './env.js';

const s3 = new S3Client({ region: process.env.AWS_REGION ?? 'ap-southeast-2' });

// Separate key provider for template decryption — matches admin service.
function getTemplateKeyProvider() {
  const config = getBatchConfig();
  return new EnvKeyProvider({
    activeVersion: config.EMBOSSING_KEY_ACTIVE_VERSION,
    keys: { [config.EMBOSSING_KEY_ACTIVE_VERSION]: config.EMBOSSING_KEY_V1 },
  });
}

export async function pollOnce(): Promise<void> {
  const batches = await prisma.embossingBatch.findMany({
    where: { status: 'RECEIVED' },
    orderBy: { uploadedAt: 'asc' },
    take: 5, // process a few per tick; heavy files are memory-bound
  });

  for (const batch of batches) {
    await processBatch(batch.id).catch((err) => {
      console.error(`[processor] batch ${batch.id} failed:`, err instanceof Error ? err.message : err);
    });
  }
}

async function processBatch(batchId: string): Promise<void> {
  console.log(`[processor] picking up batch ${batchId}`);

  // Claim the batch atomically — flip RECEIVED → PROCESSING.  updateMany
  // returns a count; if 0, another worker raced us and we skip.
  const claim = await prisma.embossingBatch.updateMany({
    where: { id: batchId, status: 'RECEIVED' },
    data: { status: 'PROCESSING' },
  });
  if (claim.count !== 1) {
    console.log(`[processor] batch ${batchId} claimed by another worker`);
    return;
  }

  const batch = await prisma.embossingBatch.findUnique({
    where: { id: batchId },
    include: { template: true, program: true },
  });
  if (!batch || !batch.template) {
    await markFailed(batchId, 'Batch or template row missing after claim');
    return;
  }

  try {
    // 1. Decrypt template body
    const templateBuf = decrypt(
      {
        ciphertext: batch.template.templateEncrypted.toString('base64'),
        keyVersion: batch.template.templateKeyVersion,
      },
      getTemplateKeyProvider(),
    );
    const templateBytes = Buffer.from(templateBuf, 'base64');

    // 2. Fetch batch file from S3
    const obj = await s3.send(
      new GetObjectCommand({ Bucket: batch.s3Bucket, Key: batch.s3Key }),
    );
    const bodyChunks: Buffer[] = [];
    for await (const chunk of obj.Body as AsyncIterable<Uint8Array>) {
      bodyChunks.push(Buffer.from(chunk));
    }
    const batchBytes = Buffer.concat(bodyChunks);

    // Integrity check
    const sha256 = createHash('sha256').update(batchBytes).digest('hex');
    if (sha256 !== batch.sha256) {
      throw new Error(
        `S3 file hash mismatch (stored=${batch.sha256}, computed=${sha256})`,
      );
    }

    // 3. Pick parser + parse
    const parser = getParser(batch.template.formatType);
    if (!parser) {
      throw new Error(`No parser for formatType="${batch.template.formatType}"`);
    }

    const parseResult = await parser.parse(
      templateBytes,
      batchBytes,
      batch.template.parserMeta,
    );

    console.log(
      `[processor] parsed ${parseResult.records.length} records, ` +
        `${parseResult.errors.length} parse errors`,
    );

    // 4. Route each record through registerCard (HMAC-signed)
    let succeeded = 0;
    let failed = parseResult.errors.length; // parser errors count as failures

    for (const record of parseResult.records) {
      try {
        await registerCard(record, batch.programId);
        succeeded++;
      } catch (err) {
        failed++;
        console.warn(
          `[processor] registerCard failed for batch=${batchId}: ` +
            (err instanceof Error ? err.message : String(err)),
        );
      }
    }

    // 5. Mark batch PROCESSED with counts
    await prisma.embossingBatch.update({
      where: { id: batchId },
      data: {
        status: 'PROCESSED',
        recordCount: parseResult.records.length,
        recordsSuccess: succeeded,
        recordsFailed: failed,
        processedAt: new Date(),
      },
    });
    console.log(`[processor] batch ${batchId} done: ${succeeded} ok, ${failed} failed`);
  } catch (err) {
    await markFailed(batchId, err instanceof Error ? err.message : String(err));
  }
}

async function markFailed(batchId: string, message: string): Promise<void> {
  console.error(`[processor] batch ${batchId} FAILED: ${message}`);
  await prisma.embossingBatch.update({
    where: { id: batchId },
    data: {
      status: 'FAILED',
      processingError: message.slice(0, 500),
      processedAt: new Date(),
    },
  });
}

async function registerCard(record: EmbossingRecord, programId: string): Promise<void> {
  const config = getBatchConfig();

  // If the record didn't come with a cardRef / UID, synthesize placeholders so
  // the activation service accepts the row.  Production batches from Episode
  // Six / pers bureaus always include both; the placeholders are a safety net
  // for test data that lacks them.  SDM read keys are NOT sent — activation
  // does not accept them on register (tap-service derives them per-tap from
  // UID via AES-CMAC(MASTER_<role>, UID)).
  const randomHex = (bytes: number): string => randomBytes(bytes).toString('hex');

  const body = JSON.stringify({
    cardRef: record.cardRef ?? `card_${Date.now()}_${randomHex(3)}`,
    uid: record.uid ?? randomHex(7),
    chipSerial: record.chipSerial,
    programId,
    batchId: undefined,
    card: {
      pan: record.pan,
      cvc: record.cvc,
      expiryMonth: record.expiryMonth,
      expiryYear: record.expiryYear,
      cardholderName: record.cardholderName,
    },
  });
  const bodyBuf = Buffer.from(body, 'utf-8');

  const path = '/api/cards/register';
  const authorization = signRequest({
    method: 'POST',
    pathAndQuery: path,
    body: bodyBuf,
    keyId: 'batch-processor',
    secret: config.SERVICE_AUTH_BATCH_PROCESSOR_SECRET,
  });

  const resp = await request(`${config.ACTIVATION_SERVICE_URL}${path}`, {
    method: 'POST',
    headers: {
      authorization,
      'content-type': 'application/json',
    },
    body: bodyBuf,
  });

  if (resp.statusCode >= 400) {
    const text = await resp.body.text();
    throw new Error(`registerCard HTTP ${resp.statusCode}: ${text.slice(0, 200)}`);
  }
  // Drain body to free the connection
  await resp.body.text();
}
