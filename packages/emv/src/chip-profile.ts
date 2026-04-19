/**
 * Chip profile loader — maps DGI numbers to tag contents from vendor perso specs.
 *
 * Ported from palisade-tlv/chip_profile.py.
 */

import { readFileSync } from 'node:fs';
import { EMV_TAGS } from './emv-tags.js';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type DGISource = 'per_profile' | 'per_card' | 'per_provisioning' | 'pa_internal';

export interface DGIDefinition {
  dgiNumber: number;
  name: string;
  tags: number[];
  mandatory: boolean;
  source: DGISource;
}

export interface ChipProfileData {
  profileId: string;
  profileName: string;
  /** "mchip_advance" | "vsdc" */
  scheme: string;
  /** "nxp" | "infineon" */
  appletVendor: string;
  /** Cryptogram Version Number: 10, 17, 18, 22 */
  cvn: number;

  dgiDefinitions: DGIDefinition[];

  // Special DGI references the PA needs
  iccPrivateKeyDgi: number;
  iccPrivateKeyTag: number;
  mkAcDgi: number;
  mkSmiDgi: number;
  mkSmcDgi: number;

  // AIDs
  elfAid: string;
  moduleAid: string;
  paAid: string;
  fidoAid: string;
}

// ---------------------------------------------------------------------------
// ChipProfile class
// ---------------------------------------------------------------------------

export class ChipProfile implements ChipProfileData {
  readonly profileId: string;
  readonly profileName: string;
  readonly scheme: string;
  readonly appletVendor: string;
  readonly cvn: number;
  readonly dgiDefinitions: DGIDefinition[];
  readonly iccPrivateKeyDgi: number;
  readonly iccPrivateKeyTag: number;
  readonly mkAcDgi: number;
  readonly mkSmiDgi: number;
  readonly mkSmcDgi: number;
  readonly elfAid: string;
  readonly moduleAid: string;
  readonly paAid: string;
  readonly fidoAid: string;

  constructor(data: ChipProfileData) {
    this.profileId = data.profileId;
    this.profileName = data.profileName;
    this.scheme = data.scheme;
    this.appletVendor = data.appletVendor;
    this.cvn = data.cvn;
    this.dgiDefinitions = data.dgiDefinitions;
    this.iccPrivateKeyDgi = data.iccPrivateKeyDgi;
    this.iccPrivateKeyTag = data.iccPrivateKeyTag;
    this.mkAcDgi = data.mkAcDgi;
    this.mkSmiDgi = data.mkSmiDgi;
    this.mkSmcDgi = data.mkSmcDgi;
    this.elfAid = data.elfAid;
    this.moduleAid = data.moduleAid;
    this.paAid = data.paAid;
    this.fidoAid = data.fidoAid;
  }

  /** Load a chip profile from a JSON file path. */
  static fromJsonFile(path: string): ChipProfile {
    const raw = JSON.parse(readFileSync(path, 'utf-8'));
    return ChipProfile.fromJson(raw);
  }

  /** Load a chip profile from a parsed JSON object. */
  static fromJson(data: Record<string, unknown>): ChipProfile {
    const defs = (data.dgi_definitions as Array<Record<string, unknown>>).map(
      (d): DGIDefinition => ({
        dgiNumber: d.dgi_number as number,
        name: d.name as string,
        tags: d.tags as number[],
        mandatory: d.mandatory as boolean,
        source: d.source as DGISource,
      }),
    );

    return new ChipProfile({
      profileId: data.profile_id as string,
      profileName: data.profile_name as string,
      scheme: data.scheme as string,
      appletVendor: data.applet_vendor as string,
      cvn: data.cvn as number,
      dgiDefinitions: defs,
      iccPrivateKeyDgi: data.icc_private_key_dgi as number,
      iccPrivateKeyTag: data.icc_private_key_tag as number,
      mkAcDgi: data.mk_ac_dgi as number,
      mkSmiDgi: data.mk_smi_dgi as number,
      mkSmcDgi: data.mk_smc_dgi as number,
      elfAid: data.elf_aid as string,
      moduleAid: data.module_aid as string,
      paAid: data.pa_aid as string,
      fidoAid: data.fido_aid as string,
    });
  }

  /** DGIs that are constant per issuer profile. */
  getPerProfileDgis(): DGIDefinition[] {
    return this.dgiDefinitions.filter((d) => d.source === 'per_profile');
  }

  /** DGIs that vary per card. */
  getPerCardDgis(): DGIDefinition[] {
    return this.dgiDefinitions.filter((d) => d.source === 'per_card');
  }

  /** DGIs that the PA generates on-card (e.g. ICC private key). */
  getPaInternalDgis(): DGIDefinition[] {
    return this.dgiDefinitions.filter((d) => d.source === 'pa_internal');
  }

  /** DGIs computed at provisioning time (e.g. ICC PK Certificate). */
  getPerProvisioningDgis(): DGIDefinition[] {
    return this.dgiDefinitions.filter((d) => d.source === 'per_provisioning');
  }

  /**
   * Check if all mandatory tags across all mandatory DGIs are present.
   *
   * @returns Human-readable descriptions of missing tags. Empty list = all present.
   */
  validateCompleteness(tagsPresent: Set<number>): string[] {
    const missing: string[] = [];
    for (const dgiDef of this.dgiDefinitions) {
      if (!dgiDef.mandatory) continue;
      for (const tag of dgiDef.tags) {
        if (!tagsPresent.has(tag)) {
          const tagInfo = EMV_TAGS[tag];
          const tagName = tagInfo?.name ?? `Unknown(0x${tag.toString(16).padStart(4, '0')})`;
          missing.push(
            `DGI 0x${dgiDef.dgiNumber.toString(16).padStart(4, '0')} (${dgiDef.name}): ` +
              `missing tag 0x${tag.toString(16).padStart(4, '0')} (${tagName})`,
          );
        }
      }
    }
    return missing;
  }
}
