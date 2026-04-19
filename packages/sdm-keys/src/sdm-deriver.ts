// -----------------------------------------------------------------------------
// SdmDeriver — per-card SDM key derivation behind a swappable backend.
//
// Every NTAG424 DNA card has two AES-128 keys that the reader side needs to
// read the SUN URL:
//
//   sdmMetaReadKey  → decrypts the PICCData block (UID + SDM read counter)
//   sdmFileReadKey  → keyed MAC (via session derivation) over the URL bytes
//
// Historically those keys were generated random per card at perso time and
// stored encrypted in the DB.  That couples long-term bearer key material to
// the DB and the env-wrapped field DEK.  The UDK pattern flips it: one master
// key per role lives inside the HSM, and per-card keys are derived
// deterministically from the chip UID via AES-CMAC:
//
//   sdmMetaReadKey = AES-CMAC(MASTER_META, UID)
//   sdmFileReadKey = AES-CMAC(MASTER_FILE, UID)
//
// Consequences:
//   - No per-card SDM key storage.  Zero bytes of key material live in the DB.
//   - Master keys can be rotated (new version → re-perso the fleet).
//   - Perso tool and tap server must share the same master-key material,
//     which in prod means they both call AWS PC against the same ARNs.
//
// Three backends:
//   - hsm    : AWS Payment Cryptography GenerateMac(Algorithm=CMAC).  Prod.
//   - local  : Real AES-CMAC in Node crypto.  Master keys HKDF'd from a
//              single dev root seed (DEV_SDM_ROOT_SEED); safe for dev only.
//   - mock   : Deterministic sha256 stand-ins.  For unit tests.
// -----------------------------------------------------------------------------

import { createHash, hkdfSync } from 'node:crypto';
import {
  PaymentCryptographyDataClient,
  GenerateMacCommand,
} from '@aws-sdk/client-payment-cryptography-data';
import { aesCmac } from '@palisade/core';

export interface SdmDeriver {
  /** Returns the 16-byte AES-128 key used to decrypt PICCData. */
  deriveMetaReadKey(uid: Buffer): Promise<Buffer>;
  /** Returns the 16-byte AES-128 key used to derive the SDMMAC session key. */
  deriveFileReadKey(uid: Buffer): Promise<Buffer>;
}

export type SdmRole = 'meta' | 'file';

// -----------------------------------------------------------------------------
// HsmSdmDeriver — AWS Payment Cryptography
// -----------------------------------------------------------------------------

export interface HsmSdmDeriverOptions {
  region: string;
  /** AWS PC key ARN for the MASTER_META AES-128 CMAC key. */
  metaMasterArn: string;
  /** AWS PC key ARN for the MASTER_FILE AES-128 CMAC key. */
  fileMasterArn: string;
}

/**
 * Production backend.  Each call issues one AWS PC GenerateMac.  The key
 * usage on the master ARN must permit CMAC generation (e.g. an AES-128 key
 * with TR31_M3 / TR31_M6 usage depending on the account setup).
 *
 * Latency: one round-trip (~20-50ms in-region).  If SDM tap QPS climbs, add
 * an in-memory LRU here keyed by UID — the output is a pure function of
 * (master, UID) so caching is safe as long as masters don't rotate under us.
 */
export class HsmSdmDeriver implements SdmDeriver {
  private readonly pcData: PaymentCryptographyDataClient;
  private readonly metaMasterArn: string;
  private readonly fileMasterArn: string;

  constructor(opts: HsmSdmDeriverOptions) {
    if (!opts.metaMasterArn) throw new Error('HsmSdmDeriver: metaMasterArn required');
    if (!opts.fileMasterArn) throw new Error('HsmSdmDeriver: fileMasterArn required');
    this.pcData = new PaymentCryptographyDataClient({ region: opts.region });
    this.metaMasterArn = opts.metaMasterArn;
    this.fileMasterArn = opts.fileMasterArn;
  }

  deriveMetaReadKey(uid: Buffer): Promise<Buffer> {
    return this.diversify(this.metaMasterArn, uid);
  }

  deriveFileReadKey(uid: Buffer): Promise<Buffer> {
    return this.diversify(this.fileMasterArn, uid);
  }

  private async diversify(masterArn: string, uid: Buffer): Promise<Buffer> {
    assertUid(uid);
    const resp = await this.pcData.send(
      new GenerateMacCommand({
        KeyIdentifier: masterArn,
        MessageData: uid.toString('hex').toUpperCase(),
        GenerationAttributes: { Algorithm: 'CMAC' },
      }),
    );
    if (!resp.Mac) {
      throw new Error(`AWS PC GenerateMac returned empty Mac for ${masterArn}`);
    }
    // CMAC output is 16 bytes; AWS returns it as hex.  Defensive slice in
    // case the SDK ever returns a truncated MAC.
    const mac = Buffer.from(resp.Mac, 'hex');
    if (mac.length < 16) {
      throw new Error(
        `AWS PC GenerateMac returned ${mac.length}-byte MAC (expected >=16)`,
      );
    }
    return mac.subarray(0, 16);
  }
}

// -----------------------------------------------------------------------------
// LocalSdmDeriver — real AES-CMAC in Node crypto, dev only
// -----------------------------------------------------------------------------

export interface LocalSdmDeriverOptions {
  /**
   * 32-byte hex root seed.  MASTER_META and MASTER_FILE are derived once in
   * the constructor via HKDF-SHA256 with role-specific info strings; rotating
   * the seed rotates every derived per-card key.
   */
  rootSeedHex: string;
}

export class LocalSdmDeriver implements SdmDeriver {
  private readonly metaMaster: Buffer;
  private readonly fileMaster: Buffer;

  constructor(opts: LocalSdmDeriverOptions) {
    const seed = Buffer.from(opts.rootSeedHex, 'hex');
    if (seed.length !== 32) {
      throw new Error(
        `LocalSdmDeriver: rootSeedHex must decode to 32 bytes (got ${seed.length})`,
      );
    }
    this.metaMaster = hkdfBytes(seed, 'palisade:sdm:v1:meta', 16);
    this.fileMaster = hkdfBytes(seed, 'palisade:sdm:v1:file', 16);
  }

  async deriveMetaReadKey(uid: Buffer): Promise<Buffer> {
    assertUid(uid);
    return aesCmac(this.metaMaster, uid);
  }

  async deriveFileReadKey(uid: Buffer): Promise<Buffer> {
    assertUid(uid);
    return aesCmac(this.fileMaster, uid);
  }
}

function hkdfBytes(seed: Buffer, info: string, length: number): Buffer {
  return Buffer.from(hkdfSync('sha256', seed, Buffer.alloc(0), info, length));
}

// -----------------------------------------------------------------------------
// MockSdmDeriver — sha256 fakes
// -----------------------------------------------------------------------------

/**
 * Fast, dependency-free stand-in for tests that don't care about crypto
 * correctness.  NEVER select this in any environment where the resulting
 * keys will be written to a real chip and tapped — PICC decrypt would
 * succeed (the mock key matches the mock-written chip), but these keys
 * have no cryptographic meaning.
 */
export class MockSdmDeriver implements SdmDeriver {
  async deriveMetaReadKey(uid: Buffer): Promise<Buffer> {
    assertUid(uid);
    return sha256Bytes(`sdm:meta:${uid.toString('hex')}`).subarray(0, 16);
  }

  async deriveFileReadKey(uid: Buffer): Promise<Buffer> {
    assertUid(uid);
    return sha256Bytes(`sdm:file:${uid.toString('hex')}`).subarray(0, 16);
  }
}

function sha256Bytes(s: string): Buffer {
  return createHash('sha256').update(s).digest();
}

// -----------------------------------------------------------------------------
// Shared
// -----------------------------------------------------------------------------

/**
 * NTAG424 DNA UIDs are 7 bytes.  Accepting 4-byte "random UID" (cloak mode)
 * or 10-byte extended UIDs would require chip-profile-specific handling that
 * this prototype doesn't need yet; fail loudly if something else shows up.
 */
function assertUid(uid: Buffer): void {
  if (uid.length !== 7) {
    throw new Error(
      `SDM UID must be 7 bytes (NTAG424 DNA); got ${uid.length}`,
    );
  }
}

// -----------------------------------------------------------------------------
// Factory
// -----------------------------------------------------------------------------

export type SdmBackend = 'hsm' | 'local' | 'mock';

export interface CreateSdmDeriverInput {
  backend: SdmBackend;
  awsRegion: string;
  /** Required when backend === 'hsm'. */
  metaMasterArn?: string;
  /** Required when backend === 'hsm'. */
  fileMasterArn?: string;
  /** Required when backend === 'local'. */
  localRootSeedHex?: string;
}

export function createSdmDeriver(input: CreateSdmDeriverInput): SdmDeriver {
  switch (input.backend) {
    case 'hsm':
      if (!input.metaMasterArn || !input.fileMasterArn) {
        throw new Error(
          "createSdmDeriver: backend='hsm' requires metaMasterArn + fileMasterArn " +
            '(set SDM_META_MASTER_KEY_ARN + SDM_FILE_MASTER_KEY_ARN)',
        );
      }
      return new HsmSdmDeriver({
        region: input.awsRegion,
        metaMasterArn: input.metaMasterArn,
        fileMasterArn: input.fileMasterArn,
      });
    case 'local':
      if (!input.localRootSeedHex) {
        throw new Error(
          "createSdmDeriver: backend='local' requires localRootSeedHex " +
            '(set DEV_SDM_ROOT_SEED to a 32-byte hex string)',
        );
      }
      return new LocalSdmDeriver({ rootSeedHex: input.localRootSeedHex });
    case 'mock':
      return new MockSdmDeriver();
  }
}
