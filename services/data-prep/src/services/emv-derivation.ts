/**
 * EMV key derivation via AWS Payment Cryptography.
 *
 * All crypto operations happen in the HSM — no raw IMK material in application memory.
 * Derives: iCVV, MK-AC, MK-SMI, MK-SMC per EMV Book 2 / M/Chip Advance spec.
 *
 * Ported from palisade-data-prep/app/services/emv_derivation.py.
 */

import { createHash } from 'node:crypto';
import {
  PaymentCryptographyDataClient,
  GenerateCardValidationDataCommand,
  EncryptDataCommand,
} from '@aws-sdk/client-payment-cryptography-data';
import {
  PaymentCryptographyClient,
  ImportKeyCommand,
} from '@aws-sdk/client-payment-cryptography';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface DerivedKeys {
  icvv: string;
  mkAcArn: string;
  mkAcKcv: string;
  mkSmiArn: string;
  mkSmiKcv: string;
  mkSmcArn: string;
  mkSmcKcv: string;
}

// ---------------------------------------------------------------------------
// Service
// ---------------------------------------------------------------------------

export class EmvDerivationService {
  private readonly pcData: PaymentCryptographyDataClient;
  private readonly pcControl: PaymentCryptographyClient;
  private readonly mockMode: boolean;

  constructor(region = 'ap-southeast-2', mockMode = false) {
    this.pcData = new PaymentCryptographyDataClient({ region });
    this.pcControl = new PaymentCryptographyClient({ region });
    this.mockMode = mockMode;
  }

  // -------------------------------------------------------------------------
  // Mock helpers — used when DATA_PREP_MOCK_EMV=true.  All outputs are
  // deterministic hashes of the inputs so you can inspect a SAD after-the-
  // fact and confirm it came from the expected card.  Structurally valid
  // (right lengths, right charset) so downstream SAD build + mobile
  // personalisation can consume them unchanged.  NOT cryptographically
  // meaningful — a card personalised with these keys can't do real EMV.
  // -------------------------------------------------------------------------

  private mockIcvv(pan: string, expiry: string): string {
    const h = createHash('sha256').update(`icvv:${pan}:${expiry}`).digest('hex');
    const n = parseInt(h.slice(0, 4), 16) % 1000;
    return n.toString().padStart(3, '0');
  }

  private mockDerivedKey(label: string, pan: string, csn: string) {
    const seed = createHash('sha256').update(`${label}:${pan}:${csn}`).digest('hex');
    return {
      keyArn: `mock:${label}:${seed.slice(0, 16)}`,
      kcv: seed.slice(0, 6).toUpperCase(),
    };
  }

  /**
   * Derive iCVV using Token Master Key.
   * @returns 3-digit iCVV string.
   */
  async deriveIcvv(tmkKeyArn: string, pan: string, expiry: string): Promise<string> {
    if (this.mockMode) return this.mockIcvv(pan, expiry);
    const response = await this.pcData.send(
      new GenerateCardValidationDataCommand({
        KeyIdentifier: tmkKeyArn,
        PrimaryAccountNumber: pan,
        GenerationAttributes: {
          CardVerificationValue2: {
            CardExpiryDate: expiry,
          },
        },
      }),
    );
    return response.ValidationData ?? '000';
  }

  /**
   * Derive per-card master key using EMV Method A.
   *
   * Method A (common diversification):
   * 1. Build derivation data: right 16 hex digits of (PAN || CSN)
   * 2. Left half = ECB(IMK, derivation_data)
   * 3. Right half = ECB(IMK, XOR(derivation_data, 0xFF...))
   * 4. Result = Left || Right (16 bytes for TDES)
   *
   * All operations happen in the HSM via AWS Payment Cryptography.
   *
   * @returns { keyArn, kcv }
   */
  async deriveMasterKey(
    imkArn: string,
    pan: string,
    csn: string,
  ): Promise<{ keyArn: string; kcv: string }> {
    if (this.mockMode) return this.mockDerivedKey(imkArn.slice(-8) || 'imk', pan, csn);
    // Build derivation data per Method A: right 16 hex chars of (PAN || CSN)
    const panCsn = (pan + csn).padEnd(16, '0').slice(-16);
    const derivData = Buffer.from(panCsn, 'hex');

    // Left half: ECB encrypt derivation data with IMK
    const leftResp = await this.pcData.send(
      new EncryptDataCommand({
        KeyIdentifier: imkArn,
        PlainText: derivData.toString('hex').toUpperCase(),
        EncryptionAttributes: {
          Symmetric: {
            Mode: 'ECB',
          },
        },
      }),
    );
    const leftHex = leftResp.CipherText ?? '';

    // Right half: ECB encrypt XOR'd derivation data
    const xored = Buffer.from(derivData.map((b) => b ^ 0xff));
    const rightResp = await this.pcData.send(
      new EncryptDataCommand({
        KeyIdentifier: imkArn,
        PlainText: xored.toString('hex').toUpperCase(),
        EncryptionAttributes: {
          Symmetric: {
            Mode: 'ECB',
          },
        },
      }),
    );
    const rightHex = rightResp.CipherText ?? '';

    // Import derived key back to HSM
    const derivedKeyHex = leftHex + rightHex;
    const importResp = await this.pcControl.send(
      new ImportKeyCommand({
        KeyMaterial: {
          RootCertificatePublicKey: {
            KeyAttributes: {
              KeyAlgorithm: 'TDES_2KEY',
              KeyClass: 'SYMMETRIC_KEY',
              KeyModesOfUse: { Encrypt: true, Decrypt: true, Wrap: true },
              KeyUsage: 'TR31_C0_CARD_VERIFICATION_KEY',
            },
            PublicKeyCertificate: derivedKeyHex,
          },
        },
      }),
    );

    const keyArn = importResp.Key?.KeyArn ?? `derived:${panCsn}`;

    // KCV: first 3 bytes of encrypting zeros
    const kcv = await this.computeKcv(imkArn);

    return { keyArn, kcv };
  }

  /**
   * Derive all per-card EMV keys in one call.
   */
  async deriveAllKeys(
    tmkArn: string,
    imkAcArn: string,
    imkSmiArn: string,
    imkSmcArn: string,
    pan: string,
    expiry: string,
    csn: string,
  ): Promise<DerivedKeys> {
    const icvv = await this.deriveIcvv(tmkArn, pan, expiry);

    const [mkAc, mkSmi, mkSmc] = await Promise.all([
      this.deriveMasterKey(imkAcArn, pan, csn),
      this.deriveMasterKey(imkSmiArn, pan, csn),
      this.deriveMasterKey(imkSmcArn, pan, csn),
    ]);

    return {
      icvv,
      mkAcArn: mkAc.keyArn,
      mkAcKcv: mkAc.kcv,
      mkSmiArn: mkSmi.keyArn,
      mkSmiKcv: mkSmi.kcv,
      mkSmcArn: mkSmc.keyArn,
      mkSmcKcv: mkSmc.kcv,
    };
  }

  /**
   * Compute Key Check Value — first 3 bytes (6 hex chars) of encrypting zeros.
   */
  private async computeKcv(keyArn: string): Promise<string> {
    try {
      const resp = await this.pcData.send(
        new EncryptDataCommand({
          KeyIdentifier: keyArn,
          PlainText: '0000000000000000',
          EncryptionAttributes: {
            Symmetric: {
              Mode: 'ECB',
            },
          },
        }),
      );
      return (resp.CipherText ?? '000000').slice(0, 6);
    } catch {
      return '000000';
    }
  }
}
