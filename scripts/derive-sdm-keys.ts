#!/usr/bin/env tsx
/**
 * derive-sdm-keys — print the per-card SDM meta/file read keys for a given
 * UID under the current dev root seed.
 *
 * Intended as a perso-time companion: since the tap-service derives per-card
 * SDM keys on every tap via `AES-CMAC(SDM_*_MASTER_KEY, UID)` and never
 * stores them, whoever programs the chip needs the same values out-of-band.
 * In dev (`SDM_KEY_BACKEND=local`) that's this script; in prod the perso
 * tool calls AWS Payment Cryptography `GenerateMac` against the real
 * `SDM_*_MASTER_KEY_ARN`.
 *
 * Usage:
 *   DEV_SDM_ROOT_SEED=<64-hex> tsx scripts/derive-sdm-keys.ts <uid-hex>
 *
 * Example:
 *   DEV_SDM_ROOT_SEED=00...ff tsx scripts/derive-sdm-keys.ts 04AABBCCDD1122
 *   sdmMetaReadKey=7a1b3c...     (16 bytes, AES-128)
 *   sdmFileReadKey=9f4e82...     (16 bytes, AES-128)
 *
 * The UID must be a 7-byte hex string (14 hex chars) — NTAG424 DNA UIDs.
 * 4-byte "random UID" mode is intentionally rejected; see
 * `packages/sdm-keys/src/sdm-deriver.ts` assertUid().
 */

import { LocalSdmDeriver } from '@palisade/sdm-keys';

const HEX_14 = /^[0-9a-fA-F]{14}$/;

async function main(): Promise<void> {
  const uidArg = process.argv[2];
  if (!uidArg) {
    console.error('usage: tsx scripts/derive-sdm-keys.ts <uid-hex>');
    console.error('       (uid is 7 bytes / 14 hex chars — NTAG424 DNA)');
    process.exit(2);
  }
  if (!HEX_14.test(uidArg)) {
    console.error(`error: uid "${uidArg}" is not 14 hex chars (got ${uidArg.length})`);
    process.exit(2);
  }

  const seed = process.env.DEV_SDM_ROOT_SEED;
  if (!seed || !/^[0-9a-fA-F]{64}$/.test(seed)) {
    console.error('error: DEV_SDM_ROOT_SEED must be 32-byte hex (64 chars)');
    console.error('       set it to the same value used by tap/activation services');
    process.exit(2);
  }

  const deriver = new LocalSdmDeriver({ rootSeedHex: seed });
  const uid = Buffer.from(uidArg, 'hex');

  const [metaKey, fileKey] = await Promise.all([
    deriver.deriveMetaReadKey(uid),
    deriver.deriveFileReadKey(uid),
  ]);

  console.log(`sdmMetaReadKey=${metaKey.toString('hex').toUpperCase()}`);
  console.log(`sdmFileReadKey=${fileKey.toString('hex').toUpperCase()}`);
}

main().catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
