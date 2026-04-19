/**
 * ICC PK Certificate builder (Tag 9F46) per EMV 4.3 Book 2, Section 5.4.
 *
 * Builds the ICC Public Key Certificate signed by the Issuer Private Key.
 * This is the ONLY per-provisioning crypto operation — everything else is
 * pre-computed by the Data Prep Service.
 *
 * Ported from palisade-rca/app/services/icc_cert_builder.py.
 */

import { createHash } from 'node:crypto';

export interface IccCertInput {
  /** Uncompressed ICC public key bytes (64 or 65 bytes — 04 prefix stripped if present) */
  iccPublicKey: Buffer;
  /** PAN digits */
  pan: string;
  /** Expiry in YYMM format */
  expiry: string;
  /** Card Sequence Number (1–3 hex digits) */
  csn: string;
  /** Issuer PK modulus length in bytes (e.g. 128 for RSA-1024, 256 for RSA-2048) */
  issuerPkLen?: number;
}

/**
 * Build ICC PK Certificate per EMV Book 2 Section 5.4.
 *
 * Certificate structure (before signing):
 *   Header(6A) || Format(04) || AppPAN(10) || CertExpiry(2) ||
 *   CertSerial(3) || HashAlgo(01) || ICCPKAlgo(01) ||
 *   ICCPKLen(1) || ICCPKExpLen(1) ||
 *   ICCPKLeftmost(issuerPkLen-42) || Padding(BB...) || Hash || Trailer(BC)
 *
 * @returns [certificateBytes, remainderBytes]
 */
export function buildIccPkCertificate(input: IccCertInput): [Buffer, Buffer] {
  const { pan, expiry, csn, issuerPkLen = 128 } = input;

  // Pad PAN to 20 digits (10 bytes BCD)
  const panBcd = Buffer.from(pan.padEnd(20, 'F'), 'hex');

  // Certificate expiry (MMYY from YYMM)
  const certExpiry = Buffer.from(expiry.substring(2, 4) + expiry.substring(0, 2), 'hex');

  // Certificate serial (CSN padded to 3 bytes)
  const certSerial = Buffer.from(csn.padEnd(6, '0'), 'hex');

  // ICC public key — strip 04 prefix if uncompressed
  let iccPk = input.iccPublicKey;
  if (iccPk.length === 65 && iccPk[0] === 0x04) {
    iccPk = iccPk.subarray(1); // X || Y = 64 bytes
  }

  const iccPkLen = iccPk.length;
  const iccPkExpLen = 1; // Exponent length

  // Space available for ICC PK in certificate = issuerPkLen - 42
  const pkSpace = issuerPkLen - 42;
  let iccPkLeftmost: Buffer;
  let remainder: Buffer;
  let paddingLen: number;

  if (iccPkLen <= pkSpace) {
    iccPkLeftmost = iccPk;
    remainder = Buffer.alloc(0);
    paddingLen = pkSpace - iccPkLen;
  } else {
    iccPkLeftmost = iccPk.subarray(0, pkSpace);
    remainder = Buffer.from(iccPk.subarray(pkSpace));
    paddingLen = 0;
  }

  const padding = Buffer.alloc(paddingLen, 0xbb);

  // Build plaintext for hash
  const plaintext = Buffer.concat([
    Buffer.from([0x04]),       // Format
    panBcd,                    // Application PAN (10 bytes)
    certExpiry,                // Certificate Expiry (2 bytes)
    certSerial,                // Certificate Serial (3 bytes)
    Buffer.from([0x01]),       // Hash Algorithm (SHA-1)
    Buffer.from([0x01]),       // ICC PK Algorithm
    Buffer.from([iccPkLen]),   // ICC PK Length
    Buffer.from([iccPkExpLen]),// ICC PK Exponent Length
    iccPkLeftmost,
    padding,
  ]);

  // Hash = SHA-1(plaintext || remainder || exponent)
  const exponent = Buffer.from([0x01, 0x00, 0x01]); // 65537
  const hashInput = Buffer.concat([plaintext, remainder, exponent]);
  const sha1Hash = createHash('sha1').update(hashInput).digest();

  // Full certificate content: header + plaintext + hash + trailer
  // Production: this would be RSA-signed with the Issuer Private Key via AWS Payment Cryptography
  // Prototype: the unsigned certificate structure is returned
  const certificate = Buffer.concat([
    Buffer.from([0x6a]),       // Header
    plaintext,
    sha1Hash,
    Buffer.from([0xbc]),       // Trailer
  ]);

  return [certificate, Buffer.from(remainder)];
}
