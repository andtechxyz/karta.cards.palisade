/**
 * GlobalPlatform and Provisioning Agent APDU command construction.
 *
 * Ported from palisade-rca/app/services/apdu_builder.py.
 */

export const APDUBuilder = {
  /**
   * SELECT applet by AID. Returns APDU hex string.
   */
  selectApplet(aidHex: string): string {
    const aid = Buffer.from(aidHex, 'hex');
    const apdu = Buffer.concat([Buffer.from([0x00, 0xa4, 0x04, 0x00, aid.length]), aid]);
    return apdu.toString('hex').toUpperCase();
  },

  /**
   * PA GENERATE_KEYS command (CLA=80 INS=E0).
   * Data: keyType(01=ECC_P256) || sessionId(16)
   *
   * Appended Le=0x00 makes this a case-4 APDU so the card's
   * `APDU.setOutgoingAndSend()` can emit the 65-byte pubkey response.
   * Without the trailing Le, JC 3.0.4 rejects the outgoing direction with
   * SW=6700 (verified on pa-v3 JCOP 5 — pa-v1 happened to work because
   * its NFC readers usually patch the Le byte in reader-mode; phones
   * don't).
   */
  generateKeys(sessionIdHex = ''): string {
    let data = Buffer.from([0x01]); // ECC P-256
    if (sessionIdHex) {
      data = Buffer.concat([data, Buffer.from(sessionIdHex, 'hex')]);
    }
    const apdu = Buffer.concat([
      Buffer.from([0x80, 0xe0, 0x00, 0x00, data.length]),
      data,
      Buffer.from([0x00]), // Le=00 → "up to 256 bytes of response"
    ]);
    return apdu.toString('hex').toUpperCase();
  },

  /**
   * PA TRANSFER_SAD command (CLA=80 INS=E2).
   * Data: SAD_payload || SSD_pubkey(65) || iccPrivDgi(2) || iccPrivEmvTag(2)
   * May need chaining for large payloads.
   */
  transferSad(
    sadData: Buffer,
    ssdKeys: Buffer,
    iccPrivDgi: number,
    iccPrivEmvTag: number,
    isLast = true,
  ): string {
    const dgiBytes = Buffer.alloc(2);
    dgiBytes.writeUInt16BE(iccPrivDgi, 0);
    const tagBytes = Buffer.alloc(2);
    tagBytes.writeUInt16BE(iccPrivEmvTag, 0);

    const data = Buffer.concat([sadData, ssdKeys, dgiBytes, tagBytes]);
    const cla = isLast ? 0x80 : 0x90; // Chain bit

    let apdu: Buffer;
    if (data.length <= 255) {
      apdu = Buffer.concat([
        Buffer.from([cla, 0xe2, 0x00, 0x00, data.length]),
        data,
      ]);
    } else {
      // Extended APDU
      const lcBuf = Buffer.alloc(2);
      lcBuf.writeUInt16BE(data.length, 0);
      apdu = Buffer.concat([
        Buffer.from([cla, 0xe2, 0x00, 0x00, 0x00]),
        lcBuf,
        data,
      ]);
    }

    return apdu.toString('hex').toUpperCase();
  },

  /** PA CONFIRM command (CLA=80 INS=E8). */
  confirm(): string {
    return '80E8000000';
  },

  /** PA WIPE command (CLA=80 INS=EA). Requires SCP11 session. */
  wipe(): string {
    return '80EA000000';
  },

  /** PA GET_STATE command (CLA=80 INS=EE). */
  getState(): string {
    return '80EE000000';
  },

  /** PA FINAL_STATUS command (CLA=80 INS=E6). */
  finalStatus(): string {
    return '80E6000000';
  },

  /**
   * pav2 GET_CHALLENGE command (CLA=80 INS=EC Le=10).  Targets the
   * Palisade T4T v2 applet (AID D2760000850101) and returns 16 bytes
   * of on-chip RNG output.
   *
   * Not consumed by the current provisioning flow.  Server-side SAD
   * replay prevention runs via the `SadRecord.status: READY → CONSUMED`
   * transition (see services/rca/src/services/plan-builder.ts
   * `PlanOptions.includeChipChallenge` + applets/pav2/README.md for
   * the chip-side defence-in-depth path this helper supports).
   */
  getChallenge(): string {
    return '80EC000010';
  },

  /**
   * SELECT pav2 T4T applet by AID (D2760000850101).  Convenience
   * wrapper for the optional chip-challenge flow where the RCA
   * temporarily switches from the PA applet to pav2, fetches a
   * challenge, and switches back.  The AID is fixed and standardised
   * by NFC Forum for Type 4 Tag applications; karta-se v1 reuses it
   * so off-the-shelf NDEF readers work without modification.
   */
  selectPav2(): string {
    return '00A4040007D2760000850101';
  },

  /**
   * GP INSTALL [for install and make selectable].
   * CLA=80 INS=E6 P1=0C P2=00
   */
  installForInstall(
    elfAid: string,
    moduleAid: string,
    instanceAid: string,
    privileges = '00',
    installParams: Buffer = Buffer.alloc(0),
  ): string {
    const elf = Buffer.from(elfAid, 'hex');
    const mod = Buffer.from(moduleAid, 'hex');
    const inst = Buffer.from(instanceAid, 'hex');
    const priv = Buffer.from(privileges, 'hex');

    const parts: Buffer[] = [];
    parts.push(Buffer.from([elf.length]), elf);
    parts.push(Buffer.from([mod.length]), mod);
    parts.push(Buffer.from([inst.length]), inst);
    parts.push(Buffer.from([priv.length]), priv);
    if (installParams.length > 0) {
      parts.push(Buffer.from([installParams.length]), installParams);
    } else {
      parts.push(Buffer.from([0x00]));
    }
    parts.push(Buffer.from([0x00])); // No install token

    const data = Buffer.concat(parts);
    const apdu = Buffer.concat([
      Buffer.from([0x80, 0xe6, 0x0c, 0x00, data.length]),
      data,
    ]);
    return apdu.toString('hex').toUpperCase();
  },

  /**
   * Parse APDU response into [data, statusWord].
   */
  parseResponse(hexResponse: string): [Buffer, number] {
    const resp = Buffer.from(hexResponse, 'hex');
    if (resp.length < 2) return [Buffer.alloc(0), 0x6f00];
    const sw = (resp[resp.length - 2] << 8) | resp[resp.length - 1];
    const data = resp.subarray(0, resp.length - 2);
    return [Buffer.from(data), sw];
  },
} as const;
