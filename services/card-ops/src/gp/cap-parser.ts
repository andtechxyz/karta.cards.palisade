/**
 * CAP file parser — surfaces package AID + applet AIDs and produces the
 * Load File Data Block that gets chunked into LOAD APDUs.
 *
 * A CAP file is a ZIP containing numbered "components" named by their
 * role (Header.cap, Directory.cap, Import.cap, Applet.cap, ...).  The
 * JavaCard VM spec defines the component order that gets concatenated
 * into the Load File Data Block — we follow §6.11 of the VM spec.
 *
 * What we care about here:
 *   - Header.cap    → package AID (for DELETE / install-load ref)
 *   - Applet.cap    → list of {aid, installMethodOffset} tuples.  The
 *                     applet AID is what `INSTALL [install+selectable]`
 *                     references.  We ignore the offset — the card's GP
 *                     already knows where to jump for the standard
 *                     install entry point.
 *
 * Out of scope: no Descriptor / ReferenceLocation rewriting, no CAP
 * validation.  This parser assumes the CAP was produced by a compliant
 * JavaCard toolchain (palisade-pa is, palisade-t4t is).
 */

import { readFileSync } from 'node:fs';
import AdmZip from 'adm-zip';

// ---------------------------------------------------------------------------
// Component tags — JavaCard VM spec §6.x.  Only the ones we parse.
// ---------------------------------------------------------------------------

const TAG = {
  HEADER: 1,
  DIRECTORY: 2,
  APPLET: 3,
  IMPORT: 4,
  CONSTANT_POOL: 5,
  CLASS: 6,
  METHOD: 7,
  STATIC_FIELD: 8,
  REFERENCE_LOCATION: 9,
  EXPORT: 10,
  DESCRIPTOR: 11,
} as const;

// Load File Data Block order (JC VM spec §6.11).  Skip Debug (12) and
// Descriptor (11) per the standard — Debug is never shipped in prod
// builds, and Descriptor is excluded from the loaded bytes.  The
// Reference Location and Export tags may be absent on stripped builds;
// we only concatenate components that are actually present in the CAP.
const LOAD_ORDER = [
  TAG.HEADER,
  TAG.DIRECTORY,
  TAG.IMPORT,
  TAG.APPLET,
  TAG.CLASS,
  TAG.METHOD,
  TAG.STATIC_FIELD,
  TAG.EXPORT,
  TAG.CONSTANT_POOL,
  TAG.REFERENCE_LOCATION,
];

// Mapping tag → the common filename the JC toolchain writes.  adm-zip's
// getEntries() returns the original paths (e.g. com/foo/javacard/Header.cap);
// we match by the trailing file name only.
const COMPONENT_FILENAME: Record<number, string> = {
  [TAG.HEADER]: 'Header.cap',
  [TAG.DIRECTORY]: 'Directory.cap',
  [TAG.APPLET]: 'Applet.cap',
  [TAG.IMPORT]: 'Import.cap',
  [TAG.CONSTANT_POOL]: 'ConstantPool.cap',
  [TAG.CLASS]: 'Class.cap',
  [TAG.METHOD]: 'Method.cap',
  [TAG.STATIC_FIELD]: 'StaticField.cap',
  [TAG.REFERENCE_LOCATION]: 'RefLocation.cap',
  [TAG.EXPORT]: 'Export.cap',
  [TAG.DESCRIPTOR]: 'Descriptor.cap',
};

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

export interface CapFile {
  /** Package AID (hex string, uppercase, no separators). */
  packageAid: string;
  /** Applet AIDs declared in the CAP's Applet component. */
  appletAids: string[];
  /**
   * Concatenated Load File Data Block — the bytes we chunk into LOAD
   * [block] APDUs after the INSTALL [load] preamble.
   */
  loadFileDataBlock: Buffer;
}

// ---------------------------------------------------------------------------
// Component reader
// ---------------------------------------------------------------------------

function readComponents(capBytes: Buffer): Map<number, Buffer> {
  const zip = new AdmZip(capBytes);
  const map = new Map<number, Buffer>();
  for (const entry of zip.getEntries()) {
    const base = entry.entryName.split('/').pop() ?? entry.entryName;
    for (const [tag, name] of Object.entries(COMPONENT_FILENAME)) {
      if (base === name) {
        map.set(Number(tag), entry.getData());
      }
    }
  }
  return map;
}

// ---------------------------------------------------------------------------
// Header component — extract package AID
// ---------------------------------------------------------------------------

/**
 * Header.cap layout (JC VM §6.3):
 *   u1 tag                 (= 1)
 *   u2 size
 *   u4 magic               (0x00FACADE)
 *   u1 minor_version
 *   u1 major_version
 *   u1 flags
 *   package_info {
 *     u1 minor_version
 *     u1 major_version
 *     u1 AID_length
 *     u1[] aid
 *   }
 *   package_name_info (optional — only when HEADER flag 0x04 set)
 *
 * Offsets (from start of component, NOT including the 3B CAP-component
 * header tag+size we strip below):
 *   4 magic, 1 minor, 1 major, 1 flags → 7 bytes
 *   then package_info at offset 7: 1 minor + 1 major + 1 AID_length + AID
 *
 * The first 3 bytes of the component buffer we get from the zip IS the
 * tag+size header — data[0]=0x01, data[1..2]=size, data[3..]=body.
 */
function parseHeader(component: Buffer): { packageAid: Buffer } {
  if (component.length < 3 || component[0] !== TAG.HEADER) {
    throw new Error('Header.cap: missing or wrong tag');
  }
  // Body starts at offset 3.
  const bodyStart = 3;
  // package_info begins at body + 7 (skip magic/minor/major/flags).
  const aidLen = component[bodyStart + 7 + 2];
  const aidStart = bodyStart + 7 + 3;
  if (aidLen < 5 || aidLen > 16) {
    throw new Error(`Header.cap: invalid AID length ${aidLen}`);
  }
  return {
    packageAid: component.subarray(aidStart, aidStart + aidLen),
  };
}

// ---------------------------------------------------------------------------
// Applet component — extract applet AIDs
// ---------------------------------------------------------------------------

/**
 * Applet.cap layout (JC VM §6.5):
 *   u1 tag                 (= 3)
 *   u2 size
 *   u1 count
 *   applets[count] {
 *     u1 AID_length
 *     u1[] AID
 *     u2 install_method_offset
 *   }
 */
function parseApplet(component: Buffer): { appletAids: Buffer[] } {
  if (component.length < 4 || component[0] !== TAG.APPLET) {
    throw new Error('Applet.cap: missing or wrong tag');
  }
  const bodyStart = 3;
  const count = component[bodyStart];
  const aids: Buffer[] = [];
  let offset = bodyStart + 1;
  for (let i = 0; i < count; i++) {
    const len = component[offset];
    offset += 1;
    aids.push(component.subarray(offset, offset + len));
    offset += len;
    offset += 2; // skip install_method_offset
  }
  return { appletAids: aids };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/** Parse a CAP file from a Buffer of zip bytes. */
export function parseCapBytes(capBytes: Buffer): CapFile {
  const components = readComponents(capBytes);
  const headerComp = components.get(TAG.HEADER);
  if (!headerComp) throw new Error('CAP missing Header component');
  const { packageAid } = parseHeader(headerComp);

  const appletComp = components.get(TAG.APPLET);
  const { appletAids } = appletComp ? parseApplet(appletComp) : { appletAids: [] as Buffer[] };

  // Build the load block in canonical order.
  const parts: Buffer[] = [];
  for (const tag of LOAD_ORDER) {
    const comp = components.get(tag);
    if (comp) parts.push(comp);
  }
  const loadFileDataBlock = Buffer.concat(parts);

  return {
    packageAid: packageAid.toString('hex').toUpperCase(),
    appletAids: appletAids.map((a) => a.toString('hex').toUpperCase()),
    loadFileDataBlock,
  };
}

/** Read + parse a CAP file from disk. */
export function parseCapFile(path: string): CapFile {
  return parseCapBytes(readFileSync(path));
}
