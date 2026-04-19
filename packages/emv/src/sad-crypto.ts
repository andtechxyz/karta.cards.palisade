/**
 * SAD at-rest encryption — dev-mode AES-128-ECB helpers.
 *
 * In production the SAD blob is encrypted via AWS KMS (`KMS_SAD_KEY_ARN`
 * on the data-prep service) and decrypted with the KMS DecryptCommand —
 * the stored ciphertext is KMS's self-describing CiphertextBlob.
 *
 * In local dev, e2e, and pre-Phase-2 staging we don't want to provision a
 * KMS key just to let the provisioning pipeline exercise itself.  We
 * instead AES-128-ECB encrypt the SAD bytes under a static stub master key
 * (sixteen 0x00 bytes), PKCS#7 padded.  Raw ciphertext bytes go straight
 * into the Postgres Bytes column — no base64 at rest — and the RCA
 * service decrypts with the matching helper before shipping plaintext to
 * the PA applet over TRANSFER_SAD.
 *
 * sadKeyVersion tells the reader which regime applies:
 *   0 → AWS KMS envelope (prod)
 *   1 → AES-128-ECB under DEV_SAD_MASTER_KEY (dev/e2e/staging)
 *
 * This module lives in @palisade/emv so both data-prep (encrypt) and rca
 * (decrypt) can import it without cross-service dependencies.  It is NEVER
 * used in prod — the data-prep service only calls the dev path when
 * KMS_SAD_KEY_ARN is unset, and prod deployments always set that ARN.
 */

import { createCipheriv, createDecipheriv } from 'node:crypto';

/**
 * Dev-mode SAD master key.  16 bytes of 0x00.  Matches the AES-128-ECB
 * stub master key in the SAD-regen brief.  Present in both data-prep
 * (encrypt) and rca (decrypt).  Swapped out for a real KMS key when
 * KMS_SAD_KEY_ARN is set on data-prep.
 */
export const DEV_SAD_MASTER_KEY: Buffer = Buffer.alloc(16, 0x00);

/**
 * sadKeyVersion value meaning "stored bytes are AES-128-ECB ciphertext
 * under DEV_SAD_MASTER_KEY, PKCS#7 padded".
 */
export const SAD_KEY_VERSION_DEV_AES_ECB = 1 as const;

/**
 * sadKeyVersion value meaning "stored bytes are an AWS KMS CiphertextBlob".
 */
export const SAD_KEY_VERSION_KMS = 0 as const;

/**
 * AES-128-ECB encrypt with PKCS#7 padding under DEV_SAD_MASTER_KEY.
 *
 * Node's ECB mode with autoPadding=true emits correct PKCS#7 padding,
 * so we rely on that instead of hand-padding.  Output length is always
 * a multiple of 16.
 */
export function encryptSadDev(plaintext: Buffer): Buffer {
  const cipher = createCipheriv('aes-128-ecb', DEV_SAD_MASTER_KEY, null);
  cipher.setAutoPadding(true);
  return Buffer.concat([cipher.update(plaintext), cipher.final()]);
}

/**
 * AES-128-ECB decrypt with PKCS#7 padding under DEV_SAD_MASTER_KEY.
 * Inverse of {@link encryptSadDev}.
 */
export function decryptSadDev(ciphertext: Buffer): Buffer {
  const decipher = createDecipheriv('aes-128-ecb', DEV_SAD_MASTER_KEY, null);
  decipher.setAutoPadding(true);
  return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
}
