/**
 * SAD (Static Authority Data) builder.
 *
 * Builds all per-profile and per-card TLV objects, groups them into DGIs
 * per the chip profile, and returns a serialisable list of [dgiNumber, data] tuples.
 *
 * Does NOT include ICC private key DGI (generated on-card by PA)
 * or ICC PK Certificate (Tag 9F46, computed during provisioning).
 *
 * Ported from palisade-data-prep/app/services/sad_builder.py.
 */

import { TLV } from './tlv.js';
import { DGI } from './dgi.js';
import { Track2 } from './track2.js';
import type { ChipProfile } from './chip-profile.js';
import { buildIad, type Scheme } from './iad-builder.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CardData {
  pan: string;
  /** YYMM */
  expiryDate: string;
  /** YYMM (default: same as expiry minus 5 years) */
  effectiveDate: string;
  serviceCode: string;
  cardSequenceNumber: string;
  icvv: string;
}

/**
 * Issuer profile fields needed by the SAD builder.
 * (Matches the relevant subset of the full IssuerProfile model.)
 */
export interface IssuerProfileForSad {
  scheme: string;
  cvn: number;
  // Hex-encoded EMV constant values
  aip?: string;
  afl?: string;
  cvmList?: string;
  pdol?: string;
  cdol1?: string;
  cdol2?: string;
  iacDefault?: string;
  iacDenial?: string;
  iacOnline?: string;
  appUsageControl?: string;
  currencyCode?: string;
  currencyExponent?: string;
  countryCode?: string;
  sdaTagList?: string;
  appVersionNumber?: string;
  appPriority?: string;
  aid?: string;
  // String tags
  appLabel?: string;
  appPreferredName?: string;
  // Issuer certificates
  issuerPkCertificate?: string;
  issuerPkRemainder?: string;
  issuerPkExponent?: string;
  caPkIndex?: string;
}

// ---------------------------------------------------------------------------
// SAD Builder
// ---------------------------------------------------------------------------

export const SADBuilder = {
  /**
   * Build the complete SAD as a list of [dgiNumber, dgiContainerBytes] tuples.
   *
   * @param profile     Issuer profile with EMV constants and cert data
   * @param chipProfile Chip profile with DGI definitions
   * @param cardData    Per-card data (PAN, expiry, etc.)
   * @returns List of [dgiNumber, dgiContainerBytes] tuples
   */
  buildSad(
    profile: IssuerProfileForSad,
    chipProfile: ChipProfile,
    cardData: CardData,
  ): Array<[number, Buffer]> {
    // Build all TLV objects keyed by tag number
    const tagValues = new Map<number, Buffer>();

    // Per-profile constant tags
    buildProfileTags(profile, tagValues);

    // Per-card tags
    buildCardTags(cardData, profile, tagValues);

    // Issuer certificates
    buildCertTags(profile, tagValues);

    // Group into DGIs per chip profile
    const dgis = groupIntoDgis(chipProfile, tagValues);

    // Validate completeness
    const missing = chipProfile.validateCompleteness(new Set(tagValues.keys()));
    if (missing.length > 0) {
      console.warn('[sad-builder] incomplete SAD:', missing);
    }

    return dgis;
  },

  /**
   * Serialise DGI list into a flat byte blob for encryption.
   * Format: count(2) || [dgiNum(2) || dgiLen(2) || dgiData] * N
   */
  serialiseDgis(dgis: Array<[number, Buffer]>): Buffer {
    const parts: Buffer[] = [];
    const header = Buffer.alloc(2);
    header.writeUInt16BE(dgis.length, 0);
    parts.push(header);

    for (const [dgiNum, dgiData] of dgis) {
      const entry = Buffer.alloc(4);
      entry.writeUInt16BE(dgiNum, 0);
      entry.writeUInt16BE(dgiData.length, 2);
      parts.push(entry, dgiData);
    }

    return Buffer.concat(parts);
  },

  /**
   * Deserialise flat byte blob back into DGI list.
   */
  deserialiseDgis(data: Buffer): Array<[number, Buffer]> {
    const count = data.readUInt16BE(0);
    const dgis: Array<[number, Buffer]> = [];
    let offset = 2;

    for (let i = 0; i < count; i++) {
      const dgiNum = data.readUInt16BE(offset);
      const dgiLen = data.readUInt16BE(offset + 2);
      const dgiData = Buffer.from(data.subarray(offset + 4, offset + 4 + dgiLen));
      dgis.push([dgiNum, dgiData]);
      offset += 4 + dgiLen;
    }

    return dgis;
  },
} as const;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

function buildProfileTags(profile: IssuerProfileForSad, tags: Map<number, Buffer>): void {
  const hexTags: Array<[number, string | undefined]> = [
    [0x82, profile.aip],
    [0x94, profile.afl],
    [0x8e, profile.cvmList],
    [0x9f38, profile.pdol],
    [0x8c, profile.cdol1],
    [0x8d, profile.cdol2],
    [0x9f0d, profile.iacDefault],
    [0x9f0e, profile.iacDenial],
    [0x9f0f, profile.iacOnline],
    [0x9f07, profile.appUsageControl],
    [0x9f42, profile.currencyCode],
    [0x9f44, profile.currencyExponent],
    [0x5f28, profile.countryCode],
    [0x9f4a, profile.sdaTagList],
    [0x9f08, profile.appVersionNumber],
    [0x87, profile.appPriority],
    [0x84, profile.aid],
  ];

  for (const [tag, hexValue] of hexTags) {
    if (hexValue) tags.set(tag, Buffer.from(hexValue, 'hex'));
  }

  // String tags
  if (profile.appLabel) tags.set(0x50, Buffer.from(profile.appLabel, 'ascii'));
  if (profile.appPreferredName) tags.set(0x9f12, Buffer.from(profile.appPreferredName, 'ascii'));
}

function buildCardTags(
  cardData: CardData,
  profile: IssuerProfileForSad,
  tags: Map<number, Buffer>,
): void {
  // Tag 5A — Application PAN (packed BCD, F-pad if odd length)
  let panHex = cardData.pan;
  if (panHex.length % 2 !== 0) panHex += 'F';
  tags.set(0x5a, Buffer.from(panHex, 'hex'));

  // Tag 5F24 — Application Expiration Date (YYMMDD, DD=31 convention)
  tags.set(0x5f24, Buffer.from(cardData.expiryDate + '31', 'hex'));

  // Tag 5F25 — Application Effective Date
  tags.set(0x5f25, Buffer.from(cardData.effectiveDate + '01', 'hex'));

  // Tag 57 — Track 2 Equivalent Data
  tags.set(0x57, Track2.build(cardData.pan, cardData.expiryDate, cardData.serviceCode));

  // Tag 5F34 — PAN Sequence Number
  tags.set(0x5f34, Buffer.from(cardData.cardSequenceNumber, 'hex'));

  // Tag 9F10 — IAD (Issuer Application Data)
  const iad = buildIad(profile.cvn, 0x01, cardData.icvv, profile.scheme as Scheme);
  tags.set(0x9f10, iad);
}

function buildCertTags(profile: IssuerProfileForSad, tags: Map<number, Buffer>): void {
  if (profile.issuerPkCertificate) tags.set(0x90, Buffer.from(profile.issuerPkCertificate, 'hex'));
  if (profile.issuerPkRemainder) tags.set(0x92, Buffer.from(profile.issuerPkRemainder, 'hex'));
  if (profile.issuerPkExponent) tags.set(0x9f32, Buffer.from(profile.issuerPkExponent, 'hex'));
  if (profile.caPkIndex) tags.set(0x8f, Buffer.from(profile.caPkIndex, 'hex'));
}

function groupIntoDgis(
  chipProfile: ChipProfile,
  tagValues: Map<number, Buffer>,
): Array<[number, Buffer]> {
  const dgis: Array<[number, Buffer]> = [];

  for (const dgiDef of chipProfile.dgiDefinitions) {
    // Skip PA-internal DGIs (ICC private key, generated on-card)
    if (dgiDef.source === 'pa_internal') continue;
    // Skip per_provisioning DGIs (computed during live session)
    if (dgiDef.source === 'per_provisioning') continue;

    // Collect TLV data for this DGI
    const tlvParts: Buffer[] = [];
    for (const tag of dgiDef.tags) {
      const value = tagValues.get(tag);
      if (value) tlvParts.push(TLV.build(tag, value));
    }

    if (tlvParts.length > 0) {
      const tlvData = Buffer.concat(tlvParts);
      const dgiBytes = DGI.build(dgiDef.dgiNumber, tlvData);
      dgis.push([dgiDef.dgiNumber, dgiBytes]);
    }
  }

  return dgis;
}
