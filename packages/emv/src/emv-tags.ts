/**
 * EMV tag constants with metadata for validation and documentation.
 *
 * Ported from palisade-tlv/emv_tags.py.
 */

export type TagSource = 'per_profile' | 'per_card' | 'per_provisioning' | 'pa_internal';

export interface TagInfo {
  name: string;
  source: TagSource;
}

export const EMV_TAGS: Record<number, TagInfo> = {
  0x50:   { name: 'Application Label',                source: 'per_profile' },
  0x57:   { name: 'Track 2 Equivalent Data',          source: 'per_card' },
  0x5a:   { name: 'Application PAN',                  source: 'per_card' },
  0x82:   { name: 'Application Interchange Profile',  source: 'per_profile' },
  0x84:   { name: 'Dedicated File Name',              source: 'per_profile' },
  0x87:   { name: 'Application Priority Indicator',   source: 'per_profile' },
  0x8c:   { name: 'CDOL1',                            source: 'per_profile' },
  0x8d:   { name: 'CDOL2',                            source: 'per_profile' },
  0x8e:   { name: 'CVM List',                         source: 'per_profile' },
  0x90:   { name: 'Issuer PK Certificate',            source: 'per_profile' },
  0x92:   { name: 'Issuer PK Remainder',              source: 'per_profile' },
  0x94:   { name: 'Application File Locator',         source: 'per_profile' },
  0x5f24: { name: 'Application Expiration Date',      source: 'per_card' },
  0x5f25: { name: 'Application Effective Date',       source: 'per_card' },
  0x5f28: { name: 'Issuer Country Code',              source: 'per_profile' },
  0x5f34: { name: 'PAN Sequence Number',              source: 'per_card' },
  0x9f07: { name: 'Application Usage Control',        source: 'per_profile' },
  0x9f08: { name: 'Application Version Number',       source: 'per_profile' },
  0x9f0d: { name: 'IAC Default',                      source: 'per_profile' },
  0x9f0e: { name: 'IAC Denial',                       source: 'per_profile' },
  0x9f0f: { name: 'IAC Online',                       source: 'per_profile' },
  0x9f10: { name: 'Issuer Application Data',          source: 'per_card' },
  0x9f12: { name: 'Application Preferred Name',       source: 'per_profile' },
  0x9f32: { name: 'Issuer PK Exponent',               source: 'per_profile' },
  0x9f38: { name: 'PDOL',                             source: 'per_profile' },
  0x9f42: { name: 'Application Currency Code',        source: 'per_profile' },
  0x9f44: { name: 'Application Currency Exponent',    source: 'per_profile' },
  0x9f46: { name: 'ICC PK Certificate',               source: 'per_provisioning' },
  0x9f48: { name: 'ICC PK Exponent',                  source: 'per_provisioning' },
  0x9f4a: { name: 'SDA Tag List',                     source: 'per_profile' },
} as const;
