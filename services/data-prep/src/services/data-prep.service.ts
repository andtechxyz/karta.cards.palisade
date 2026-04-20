/**
 * Data Prep orchestrator — validates, derives, builds, encrypts, stores.
 *
 * Coordinates the complete SAD preparation flow:
 * 1. Load issuer profile by programId
 * 2. Load chip profile
 * 3. Derive EMV keys (iCVV, MK-AC, MK-SMI, MK-SMC) via AWS Payment Cryptography
 * 4. Build SAD (TLV/DGI structures via @palisade/emv)
 * 5. Serialise and encrypt SAD blob
 * 6. Store SAD record in Postgres
 * 7. Return proxyCardId
 *
 * Ported from palisade-data-prep/app/services/data_prep.py.
 */

import { randomBytes } from 'node:crypto';
import { KMSClient, EncryptCommand, DecryptCommand } from '@aws-sdk/client-kms';
import { prisma } from '@palisade/db';
import {
  SADBuilder,
  ChipProfile,
  encryptSadDev,
  decryptSadDev,
  SAD_KEY_VERSION_DEV_AES_ECB,
} from '@palisade/emv';
import type { CardData, IssuerProfileForSad } from '@palisade/emv';
import { notFound } from '@palisade/core';

import { EmvDerivationService } from './emv-derivation.js';
import { getDataPrepConfig } from '../env.js';
import { metrics } from '../metrics.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PrepareInput {
  cardId: string;
  pan: string;
  expiryYymm: string;
  serviceCode?: string;
  cardSequenceNumber?: string;
  chipSerial?: string;
  programId: string;
}

export interface PrepareResult {
  proxyCardId: string;
  sadRecordId: string;
  status: string;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

/**
 * Module-level KMSClient singleton.  Constructing a fresh client on every
 * decrypt (latency audit opt #5) cost ~10-20 ms on TLS + DNS warm-up; the
 * persistent client reuses keep-alive connections for every call after
 * the first.  Region resolves lazily from AWS_REGION at first construction.
 */
let _moduleKms: KMSClient | null = null;
function kmsClient(): KMSClient {
  if (!_moduleKms) {
    const region = process.env.AWS_REGION ?? 'ap-southeast-2';
    _moduleKms = new KMSClient({ region });
  }
  return _moduleKms;
}

/** Test hook: reset the singleton so tests can swap regions / mocks. */
export function _resetKmsSingleton(): void {
  _moduleKms = null;
}

export class DataPrepService {
  private readonly emv: EmvDerivationService;

  constructor() {
    this.emv = EmvDerivationService.fromEnv();
  }

  async prepareCard(input: PrepareInput): Promise<PrepareResult> {
    const config = getDataPrepConfig();

    // Step 1: Load issuer profile (includes key ARNs and EMV constants)
    const issuerProfile = await prisma.issuerProfile.findUnique({
      where: { programId: input.programId },
      include: { chipProfile: true },
    });
    if (!issuerProfile) throw notFound('profile_not_found', `Unknown programId: ${input.programId}`);

    // Step 2: Load chip profile from the issuer profile's linked chip profile
    const chipProfile = this.buildChipProfile(issuerProfile.chipProfile);

    // Step 3: Derive EMV keys via AWS Payment Cryptography
    const derived = await this.emv.deriveAllKeys(
      issuerProfile.tmkKeyArn,
      issuerProfile.imkAcKeyArn,
      issuerProfile.imkSmiKeyArn,
      issuerProfile.imkSmcKeyArn,
      input.pan,
      input.expiryYymm,
      input.cardSequenceNumber ?? '01',
    );

    // Build and encrypt the SAD inside a try/finally so the plaintext
    // per-card EMV master keys (MK-AC, MK-SMI, MK-SMC) are zeroed on every
    // exit path — success, throw from SADBuilder, KMS failure, DB failure.
    // These three 16-byte buffers would otherwise linger on the V8 heap
    // until GC, readable via core dump or memory-scraping debugger.
    // PCI 3.5 / 3.6.2.
    let sadBytes: Buffer | null = null;
    let encrypted: Buffer;
    let keyVersion: number;
    try {
      // Step 4: Build SAD (TLV/DGI structures)
      const profileForSad = this.toSadProfile(issuerProfile);
      const cardData: CardData = {
        pan: input.pan,
        expiryDate: input.expiryYymm,
        effectiveDate: this.computeEffectiveDate(input.expiryYymm),
        serviceCode: input.serviceCode ?? '201',
        cardSequenceNumber: input.cardSequenceNumber ?? '01',
        icvv: derived.icvv,
      };

      const dgis = SADBuilder.buildSad(profileForSad, chipProfile, cardData);

      // Step 5: Serialise and encrypt
      sadBytes = SADBuilder.serialiseDgis(dgis);
      ({ encrypted, keyVersion } = await this.encryptSad(sadBytes, config.KMS_SAD_KEY_ARN));
    } finally {
      derived.mkAcKeyBytes.fill(0);
      derived.mkSmiKeyBytes.fill(0);
      derived.mkSmcKeyBytes.fill(0);
      sadBytes?.fill(0);
    }

    // Step 6: Store SAD record
    const sadRecord = await prisma.sadRecord.create({
      data: {
        cardId: input.cardId,
        proxyCardId: `pxy_${randomBytes(12).toString('hex')}`,
        sadEncrypted: encrypted,
        sadKeyVersion: keyVersion,
        chipSerial: input.chipSerial ?? null,
        status: 'READY',
        expiresAt: new Date(Date.now() + config.SAD_TTL_DAYS * 86400_000),
      },
    });

    // Step 7: Update card's proxyCardId
    await prisma.card.update({
      where: { id: input.cardId },
      data: { proxyCardId: sadRecord.proxyCardId },
    });

    return {
      proxyCardId: sadRecord.proxyCardId,
      sadRecordId: sadRecord.id,
      status: 'READY',
    };
  }

  // -----------------------------------------------------------------------
  // Internal helpers
  // -----------------------------------------------------------------------

  private buildChipProfile(
    dbProfile: {
      dgiDefinitions: unknown;
      scheme: string;
      vendor: string;
      cvn: number;
      elfAid: string | null;
      moduleAid: string | null;
      paAid: string;
      fidoAid: string;
      iccPrivateKeyDgi: number;
      iccPrivateKeyTag: number;
      mkAcDgi: number;
      mkSmiDgi: number;
      mkSmcDgi: number;
      id: string;
      name: string;
    },
  ): ChipProfile {
    return ChipProfile.fromJson({
      profile_id: dbProfile.id,
      profile_name: dbProfile.name,
      scheme: dbProfile.scheme,
      applet_vendor: dbProfile.vendor,
      cvn: dbProfile.cvn,
      dgi_definitions: dbProfile.dgiDefinitions,
      elf_aid: dbProfile.elfAid ?? '',
      module_aid: dbProfile.moduleAid ?? '',
      pa_aid: dbProfile.paAid,
      fido_aid: dbProfile.fidoAid,
      icc_private_key_dgi: dbProfile.iccPrivateKeyDgi,
      icc_private_key_tag: dbProfile.iccPrivateKeyTag,
      mk_ac_dgi: dbProfile.mkAcDgi,
      mk_smi_dgi: dbProfile.mkSmiDgi,
      mk_smc_dgi: dbProfile.mkSmcDgi,
    });
  }

  private toSadProfile(ip: {
    scheme: string;
    cvn: number;
    aip: string;
    afl: string;
    cvmList: string;
    pdol: string;
    cdol1: string;
    cdol2: string;
    iacDefault: string;
    iacDenial: string;
    iacOnline: string;
    appUsageControl: string;
    currencyCode: string;
    currencyExponent: string;
    countryCode: string;
    sdaTagList: string;
    appVersionNumber: string;
    appPriority: string;
    aid: string;
    appLabel: string;
    appPreferredName: string;
    issuerPkCertificate: string;
    issuerPkRemainder: string;
    issuerPkExponent: string;
    caPkIndex: string;
  }): IssuerProfileForSad {
    return {
      scheme: ip.scheme,
      cvn: ip.cvn,
      aip: ip.aip || undefined,
      afl: ip.afl || undefined,
      cvmList: ip.cvmList || undefined,
      pdol: ip.pdol || undefined,
      cdol1: ip.cdol1 || undefined,
      cdol2: ip.cdol2 || undefined,
      iacDefault: ip.iacDefault || undefined,
      iacDenial: ip.iacDenial || undefined,
      iacOnline: ip.iacOnline || undefined,
      appUsageControl: ip.appUsageControl || undefined,
      currencyCode: ip.currencyCode || undefined,
      currencyExponent: ip.currencyExponent || undefined,
      countryCode: ip.countryCode || undefined,
      sdaTagList: ip.sdaTagList || undefined,
      appVersionNumber: ip.appVersionNumber || undefined,
      appPriority: ip.appPriority || undefined,
      aid: ip.aid || undefined,
      appLabel: ip.appLabel || undefined,
      appPreferredName: ip.appPreferredName || undefined,
      issuerPkCertificate: ip.issuerPkCertificate || undefined,
      issuerPkRemainder: ip.issuerPkRemainder || undefined,
      issuerPkExponent: ip.issuerPkExponent || undefined,
      caPkIndex: ip.caPkIndex || undefined,
    };
  }

  /**
   * Encrypt SAD blob.
   * - Production (KMS_SAD_KEY_ARN set): AWS KMS envelope encryption.
   *   The returned CiphertextBlob is self-describing (contains key metadata).
   *   sadKeyVersion = 0 — KMS manages its own key rotation.
   * - Dev mode (KMS_SAD_KEY_ARN empty): AES-128-ECB under the static dev
   *   SAD master key.  Stored as raw ciphertext bytes — the Bytes column
   *   holds ECB output directly, no base64 wrapping at rest.  Matching
   *   decrypt lives in services/data-prep/src/services/sad-crypto.ts.
   *   sadKeyVersion = 1 to distinguish from KMS-encrypted blobs.
   */
  private async encryptSad(
    sadBytes: Buffer,
    kmsKeyArn: string,
  ): Promise<{ encrypted: Buffer; keyVersion: number }> {
    if (kmsKeyArn) {
      // Production: KMS encrypt via shared singleton (keeps TLS keep-alive).
      const resp = await kmsClient().send(
        new EncryptCommand({ KeyId: kmsKeyArn, Plaintext: sadBytes }),
      );
      if (!resp.CiphertextBlob) {
        throw new Error('KMS encrypt returned empty CiphertextBlob');
      }
      return {
        encrypted: Buffer.from(resp.CiphertextBlob),
        keyVersion: 0,
      };
    }

    // Dev mode: AES-128-ECB under the static dev master key.  Raw
    // ciphertext bytes go into SadRecord.sadEncrypted.
    return {
      encrypted: encryptSadDev(sadBytes),
      keyVersion: SAD_KEY_VERSION_DEV_AES_ECB,
    };
  }

  /**
   * Decrypt a SAD blob previously encrypted by {@link encryptSad}.
   *
   * Can be called from other services (e.g. RCA) via the static overload.
   *
   * @param encrypted - The encrypted SAD buffer (raw bytes read from
   *                    SadRecord.sadEncrypted).
   * @param kmsKeyArn - KMS key ARN. Empty string = dev mode (AES-128-ECB).
   * @param sadKeyVersion - 0 = KMS encrypted, 1 = dev AES-128-ECB.
   */
  static async decryptSad(
    encrypted: Buffer,
    kmsKeyArn: string,
    sadKeyVersion = 0,
  ): Promise<Buffer> {
    // Instrument EVERY decrypt with a duration sample + outcome counter.
    // This is the single biggest contributor to provisioning SAD_TRANSFER
    // latency (KMS Decrypt round-trip = 150-400 ms cold), so operators
    // need a p95 dashboard to spot drift.  Tag on `mode` so dev AES-ECB
    // and prod KMS paths are visible separately.
    const mode =
      sadKeyVersion === SAD_KEY_VERSION_DEV_AES_ECB ? 'dev'
      : sadKeyVersion === 0 && kmsKeyArn ? 'kms'
      : 'unknown';
    const startedAt = Date.now();
    try {
      if (sadKeyVersion === 0 && kmsKeyArn) {
        // Production: KMS decrypt — CiphertextBlob is self-describing.
        // Use the module-level KMSClient singleton; constructing a fresh
        // client on every call adds ~10-20 ms of TLS + DNS warm-up on the
        // first request after process start (latency audit, opt #5).
        const resp = await kmsClient().send(
          new DecryptCommand({ CiphertextBlob: encrypted }),
        );
        if (!resp.Plaintext) {
          throw new Error('KMS decrypt returned empty Plaintext');
        }
        const pt = Buffer.from(resp.Plaintext);
        metrics().counter('data-prep.sad_decrypt.ok', 1, { mode });
        metrics().timing('data-prep.sad_decrypt.duration_ms', Date.now() - startedAt, { mode });
        return pt;
      }

      if (sadKeyVersion === SAD_KEY_VERSION_DEV_AES_ECB) {
        const pt = decryptSadDev(encrypted);
        metrics().counter('data-prep.sad_decrypt.ok', 1, { mode });
        metrics().timing('data-prep.sad_decrypt.duration_ms', Date.now() - startedAt, { mode });
        return pt;
      }

      throw new Error(
        `decryptSad: unsupported sadKeyVersion=${sadKeyVersion} (kmsKeyArn=${kmsKeyArn ? 'set' : 'empty'})`,
      );
    } catch (err) {
      const msg = err instanceof Error ? err.message.toLowerCase() : '';
      const reason =
        msg.includes('kms') ? 'kms_error'
        : msg.includes('unsupported sadkeyversion') ? 'unsupported_version'
        : msg.includes('empty plaintext') ? 'empty_plaintext'
        : 'other';
      metrics().counter('data-prep.sad_decrypt.fail', 1, { mode, reason });
      metrics().timing('data-prep.sad_decrypt.duration_ms', Date.now() - startedAt, { mode });
      throw err;
    }
  }

  private computeEffectiveDate(expiryYymm: string): string {
    const yy = parseInt(expiryYymm.slice(0, 2), 10);
    const mm = expiryYymm.slice(2, 4);
    const effectiveYy = Math.max(0, yy - 5);
    return `${effectiveYy.toString().padStart(2, '0')}${mm}`;
  }
}
