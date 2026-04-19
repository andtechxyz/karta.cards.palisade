// -----------------------------------------------------------------------------
// UdkDeriver — per-card EMV key derivation behind a swappable backend.
//
// The interface is deliberately narrow: given an IMK identifier, a PAN, and a
// CSN, return the derived per-card master key.  All EMV Method A mechanics
// (derivation-data layout, left/right halves, KCV) live inside the backends;
// callers only see the result.
//
// Three backends:
//   - hsm    : AWS Payment Cryptography.  Prod.  Requires real IMK ARNs.
//   - local  : Real EMV Method A in Node crypto using dev IMKs derived from a
//              single root seed via HKDF.  Cryptographically valid, not HSM-
//              protected — safe for development, never production.
//   - mock   : Deterministic sha256-based stand-ins.  Structurally valid
//              outputs, no cryptographic meaning.  Only for tests where a
//              card won't actually be used against a real acquirer.
//
// Interface contract:
//   deriveIcvv       → 3-digit decimal string
//   deriveMasterKey  → { keyArn, kcv, keyBytes? }
//     - `keyArn`   opaque handle (real ARN for hsm; synthetic for local/mock)
//     - `kcv`      6-hex-char Key Check Value (AES/TDES-ECB of zeros, first 3)
//     - `keyBytes` plaintext MK for SAD embedding (absent for hsm when the
//                  derived key stays inside the HSM).  SAD personalisation
//                  needs the MK bytes on the card anyway; hsm backend returns
//                  them after per-call extraction.
// -----------------------------------------------------------------------------

import {
  createCipheriv,
  createHash,
  createHmac,
  hkdfSync,
} from 'node:crypto';
import {
  PaymentCryptographyDataClient,
  GenerateCardValidationDataCommand,
  EncryptDataCommand,
} from '@aws-sdk/client-payment-cryptography-data';

export interface DerivedMasterKey {
  /** Opaque handle for logging / audit.  Real ARN (hsm) or synthetic. */
  keyArn: string;
  /** First 3 bytes (6 hex chars) of encrypt(key, 0x00...0) — EMV KCV. */
  kcv: string;
  /** Plaintext MK material.  Needed for SAD personalisation. */
  keyBytes: Buffer;
}

export interface UdkDeriver {
  /** Derive iCVV (3-digit decimal) from TMK + PAN + expiry. */
  deriveIcvv(tmkKeyArn: string, pan: string, expiry: string): Promise<string>;
  /** Derive per-card master key from IMK + PAN + CSN via Method A. */
  deriveMasterKey(imkArn: string, pan: string, csn: string): Promise<DerivedMasterKey>;
}

// -----------------------------------------------------------------------------
// Shared helpers
// -----------------------------------------------------------------------------

/**
 * EMV Method A derivation data: right-most 16 hex chars of (PAN || CSN),
 * interpreted as 8 bytes of binary.  Used for both TDES-2KEY and AES-128
 * IMK variants.
 */
export function methodADerivationData(pan: string, csn: string): Buffer {
  const padded = (pan + csn).padEnd(16, '0').slice(-16);
  return Buffer.from(padded, 'hex');
}

/** First 3 bytes (6 hex chars, uppercase) of ECB-encrypting eight zero bytes. */
export function computeKcv(keyBytes: Buffer): string {
  const algo = pickEcbAlgo(keyBytes);
  const cipher = createCipheriv(algo, keyBytes, null);
  cipher.setAutoPadding(false);
  const out = Buffer.concat([cipher.update(Buffer.alloc(8)), cipher.final()]);
  return out.subarray(0, 3).toString('hex').toUpperCase();
}

/** TDES-2KEY is 16 bytes (K1||K2); Node exposes it as `des-ede-ecb`. */
function pickEcbAlgo(keyBytes: Buffer): 'des-ede-ecb' | 'aes-128-ecb' {
  if (keyBytes.length === 16) return 'des-ede-ecb';
  throw new Error(
    `unsupported IMK length ${keyBytes.length} bytes (expected 16 for TDES-2KEY)`,
  );
}

// -----------------------------------------------------------------------------
// HsmUdkDeriver — AWS Payment Cryptography
// -----------------------------------------------------------------------------

/**
 * Prod backend.  Calls AWS Payment Cryptography under a real IMK ARN.
 *
 * Method A is not a native AWS PC primitive; we synthesise it from two
 * EncryptData(Mode=ECB) calls, then derive KCV locally from the returned
 * key bytes.
 *
 * The previous port attempted to round-trip the derived key back into AWS PC
 * via ImportKey with `RootCertificatePublicKey` + `KeyClass: SYMMETRIC_KEY`.
 * That key-material parameter is the public-key import path and was rejected
 * in review — symmetric imports need TR-31 blocks or a KEK-wrapped cryptogram.
 * Since the derived MK is destined for the SAD payload (not long-term HSM
 * storage), we skip the round-trip: the plaintext MK is produced, used to
 * build the SAD, and discarded.  IMK material never leaves the HSM.
 */
export class HsmUdkDeriver implements UdkDeriver {
  private readonly pcData: PaymentCryptographyDataClient;

  constructor(region: string) {
    this.pcData = new PaymentCryptographyDataClient({ region });
  }

  async deriveIcvv(tmkKeyArn: string, pan: string, expiry: string): Promise<string> {
    const resp = await this.pcData.send(
      new GenerateCardValidationDataCommand({
        KeyIdentifier: tmkKeyArn,
        PrimaryAccountNumber: pan,
        GenerationAttributes: {
          CardVerificationValue2: { CardExpiryDate: expiry },
        },
      }),
    );
    return resp.ValidationData ?? '000';
  }

  async deriveMasterKey(
    imkArn: string,
    pan: string,
    csn: string,
  ): Promise<DerivedMasterKey> {
    const derivData = methodADerivationData(pan, csn);

    const leftHex = await this.encryptEcb(imkArn, derivData);
    const xored = Buffer.from(derivData.map((b) => b ^ 0xff));
    const rightHex = await this.encryptEcb(imkArn, xored);

    const keyBytes = Buffer.from(leftHex + rightHex, 'hex');
    return {
      keyArn: `derived:hsm:${imkArn.slice(-16)}:${pan.slice(-4)}:${csn}`,
      kcv: computeKcv(keyBytes),
      keyBytes,
    };
  }

  private async encryptEcb(keyArn: string, block: Buffer): Promise<string> {
    const resp = await this.pcData.send(
      new EncryptDataCommand({
        KeyIdentifier: keyArn,
        PlainText: block.toString('hex').toUpperCase(),
        EncryptionAttributes: {
          Symmetric: { Mode: 'ECB' },
        },
      }),
    );
    if (!resp.CipherText) {
      throw new Error(`AWS PC EncryptData returned empty CipherText for ${keyArn}`);
    }
    return resp.CipherText;
  }
}

// -----------------------------------------------------------------------------
// LocalUdkDeriver — real Method A in Node crypto, for development
// -----------------------------------------------------------------------------

export interface LocalUdkDeriverOptions {
  /**
   * 32-byte hex root seed.  Every IMK/TMK bytes used by this backend are
   * derived deterministically as HKDF(rootSeed, info = "palisade:udk:v1:" + arn).
   * Different ARNs get distinct keys; the same ARN always gets the same key
   * across restarts — so SADs regenerate identically.
   */
  rootSeedHex: string;
}

export class LocalUdkDeriver implements UdkDeriver {
  private readonly rootSeed: Buffer;

  constructor(opts: LocalUdkDeriverOptions) {
    const seed = Buffer.from(opts.rootSeedHex, 'hex');
    if (seed.length !== 32) {
      throw new Error(
        `LocalUdkDeriver: rootSeedHex must decode to 32 bytes (got ${seed.length})`,
      );
    }
    this.rootSeed = seed;
  }

  async deriveIcvv(tmkKeyArn: string, pan: string, expiry: string): Promise<string> {
    // iCVV is a 3-digit value issuers bind to (PAN, expiry).  The real
    // algorithm (CVC3 etc.) is scheme-specific; for local/dev we want a
    // value that's deterministic, bound to the same inputs as real CVC
    // generation, and uses a real MAC over the right data.
    const tmk = this.keyForArn(tmkKeyArn);
    const mac = createHmac('sha256', tmk)
      .update(`icvv:${pan}:${expiry}`)
      .digest();
    const n = mac.readUInt16BE(0) % 1000;
    return n.toString().padStart(3, '0');
  }

  async deriveMasterKey(
    imkArn: string,
    pan: string,
    csn: string,
  ): Promise<DerivedMasterKey> {
    const imk = this.keyForArn(imkArn);
    const derivData = methodADerivationData(pan, csn);

    const left = ecbEncryptBlock(imk, derivData);
    const xored = Buffer.from(derivData.map((b) => b ^ 0xff));
    const right = ecbEncryptBlock(imk, xored);

    const keyBytes = Buffer.concat([left, right]);
    return {
      keyArn: `derived:local:${shortHash(imkArn)}:${pan.slice(-4)}:${csn}`,
      kcv: computeKcv(keyBytes),
      keyBytes,
    };
  }

  /**
   * Per-ARN IMK/TMK bytes via HKDF.  The output is always 16 bytes — the
   * TDES-2KEY size expected by Method A.  Parity bits are not adjusted: Node's
   * des-ede-ecb ignores them.
   */
  private keyForArn(arn: string): Buffer {
    const out = hkdfSync('sha256', this.rootSeed, Buffer.alloc(0), `palisade:udk:v1:${arn}`, 16);
    return Buffer.from(out);
  }
}

function ecbEncryptBlock(key: Buffer, block: Buffer): Buffer {
  if (block.length !== 8) {
    throw new Error(`ecbEncryptBlock: expected 8-byte block, got ${block.length}`);
  }
  const cipher = createCipheriv('des-ede-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.concat([cipher.update(block), cipher.final()]);
}

function shortHash(s: string): string {
  return createHash('sha256').update(s).digest('hex').slice(0, 12);
}

// -----------------------------------------------------------------------------
// MockUdkDeriver — sha256-based fakes
// -----------------------------------------------------------------------------

/**
 * The original `mockMode` behaviour, preserved for tests that want a fast,
 * dependency-free UdkDeriver but don't care about crypto correctness.
 *
 * Output shape matches the real backends so downstream SAD / persist paths
 * don't care.  NEVER configure a real issuer profile to use this in any env
 * where the resulting card could be read by a terminal — iCVV + MKs won't
 * authorise against real acquirers.
 */
export class MockUdkDeriver implements UdkDeriver {
  async deriveIcvv(_tmkKeyArn: string, pan: string, expiry: string): Promise<string> {
    const h = createHash('sha256').update(`icvv:${pan}:${expiry}`).digest('hex');
    const n = parseInt(h.slice(0, 4), 16) % 1000;
    return n.toString().padStart(3, '0');
  }

  async deriveMasterKey(
    imkArn: string,
    pan: string,
    csn: string,
  ): Promise<DerivedMasterKey> {
    const label = imkArn.slice(-8) || 'imk';
    const seed = createHash('sha256').update(`${label}:${pan}:${csn}`).digest();
    const keyBytes = seed.subarray(0, 16); // 16 bytes = TDES-2KEY size
    return {
      keyArn: `mock:${label}:${seed.subarray(0, 8).toString('hex')}`,
      kcv: seed.subarray(0, 3).toString('hex').toUpperCase(),
      keyBytes,
    };
  }
}

// -----------------------------------------------------------------------------
// Factory
// -----------------------------------------------------------------------------

export type UdkBackend = 'hsm' | 'local' | 'mock';

export interface CreateUdkDeriverInput {
  backend: UdkBackend;
  awsRegion: string;
  /** Required when backend === 'local'. */
  localRootSeedHex?: string;
}

export function createUdkDeriver(input: CreateUdkDeriverInput): UdkDeriver {
  switch (input.backend) {
    case 'hsm':
      return new HsmUdkDeriver(input.awsRegion);
    case 'local':
      if (!input.localRootSeedHex) {
        throw new Error(
          "createUdkDeriver: backend='local' requires localRootSeedHex " +
            '(set DEV_UDK_ROOT_SEED to a 32-byte hex string)',
        );
      }
      return new LocalUdkDeriver({ rootSeedHex: input.localRootSeedHex });
    case 'mock':
      return new MockUdkDeriver();
  }
}
