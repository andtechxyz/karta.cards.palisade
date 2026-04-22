package com.palisade.pa;

/**
 * PA v3 shared constants.  Single source of truth for APDU INS bytes,
 * ParamBundle tag numbers, ParamBundle state byte values, and applet
 * state-machine states.
 *
 * Any value here that's also present in a server-side file MUST match
 * byte-for-byte — in particular:
 *
 *   - ParamBundle tag numbers MUST match packages/emv/src/
 *     param-bundle-builder.ts's `ParamTag` enum.
 *   - ECDH/HKDF/GCM constants MUST match packages/emv-ecdh/src/
 *     index.ts's `ECDH_PROTOCOL` constant.
 *   - Scheme + CVN byte values MUST match scheme-mchip.ts.
 *
 * On divergence → applet refuses to parse / GCM tag fails / DGI bytes
 * don't match what the backend expects.  ALWAYS update both sides in
 * the same commit.
 */
public final class Constants {

    private Constants() { /* static only */ }

    // -----------------------------------------------------------------
    // APDU CLA/INS bytes
    // -----------------------------------------------------------------

    /** Proprietary CLA for PA APDUs. */
    public static final byte CLA_PA = (byte) 0x80;

    /** INS_GENERATE_KEYS — unchanged from PA v2. */
    public static final byte INS_GENERATE_KEYS = (byte) 0xE0;

    /**
     * INS_TRANSFER_PARAMS — same slot as pa-v1's INS_TRANSFER_SAD
     * (0xE2) but body semantics differ: v3 always expects an ECDH-
     * wrapped ParamBundle (see EcdhUnwrapper wire format).  There is
     * no legacy-SAD fallback — mixing v1 and v3 cards in a fleet is
     * handled by AID selection, not by dual-format TRANSFER_PARAMS.
     */
    public static final byte INS_TRANSFER_PARAMS = (byte) 0xE2;

    /** INS_FINAL_STATUS — unchanged from v2. */
    public static final byte INS_FINAL_STATUS = (byte) 0xE6;

    /** INS_CONFIRM — unchanged from v2. */
    public static final byte INS_CONFIRM = (byte) 0xE8;

    /** INS_WIPE — unchanged from v2. */
    public static final byte INS_WIPE = (byte) 0xEA;

    /**
     * INS_STORE_ATTESTATION (patent C16/C23).  Loads per-card
     * attestation material during personalisation.  P1 selects the
     * DGI sub-type:
     *   ATTEST_P1_PRIV_KEY  (0x01)  raw 32-byte P-256 private scalar
     *   ATTEST_P1_CARD_CERT (0x02)  card cert blob (issuer-signed)
     *   ATTEST_P1_CPLC      (0x03)  42-byte NXP CPLC
     * Only accepted in STATE_IDLE; post-keygen loads are rejected
     * with SW_WRONG_STATE so a mid-session material swap can't
     * masquerade as a legitimate attestation.
     */
    public static final byte INS_STORE_ATTESTATION = (byte) 0xEC;

    /**
     * INS_GET_ATTESTATION_CHAIN (patent C16/C23).  Returns the loaded
     * card cert blob verbatim so rca can walk the Root→Issuer→Card
     * chain before encrypting any SAD/ParamBundle for this chip.
     * Keeping this as a separate query (rather than stuffing the
     * cert into the GENERATE_KEYS response) keeps every APDU in
     * short-form range — iOS CoreNFC has been flaky about extended-
     * length responses on JCOP 5.
     */
    public static final byte INS_GET_ATTESTATION_CHAIN = (byte) 0xEE;

    // --- STORE_ATTESTATION P1 dispatch values ---
    public static final byte ATTEST_P1_PRIV_KEY  = (byte) 0x01;
    public static final byte ATTEST_P1_CARD_CERT = (byte) 0x02;
    public static final byte ATTEST_P1_CPLC      = (byte) 0x03;

    /** Raw P-256 private scalar width (attestation key). */
    public static final short ATTEST_PRIV_KEY_LEN = (short) 32;
    /** NXP CPLC fixed width (per CPLC spec). */
    public static final short ATTEST_CPLC_LEN = (short) 42;
    /** Upper bound for the card cert blob allocation.  Real format is
     *  card_pubkey(65) + cplc(42) + DER sig(~72) = ~179 B; 192 B gives
     *  ~13 B slack.  Don't grow without re-verifying applet install on
     *  the target JCOP 5 SKU — this, sessionId, and the four DGI NVM
     *  byte arrays together live in a persistent EEPROM pool sized to
     *  fit alongside the persistent Signature + MessageDigest for C16. */
    public static final short ATTEST_CARD_CERT_MAX = (short) 192;

    // -----------------------------------------------------------------
    // ParamBundle tag numbers.  Mirror of `ParamTag` in
    // packages/emv/src/param-bundle-builder.ts.
    //
    // Tags 0x01..0x7F so single-byte tag decode in the applet parser.
    // -----------------------------------------------------------------

    public static final byte PB_PAN                 = (byte) 0x01;
    public static final byte PB_PSN                 = (byte) 0x02;
    public static final byte PB_EXPIRY              = (byte) 0x03;
    public static final byte PB_EFFECTIVE           = (byte) 0x04;
    public static final byte PB_SERVICE_CODE        = (byte) 0x05;
    public static final byte PB_SCHEME              = (byte) 0x06;
    public static final byte PB_CVN                 = (byte) 0x07;
    public static final byte PB_AID                 = (byte) 0x08;
    public static final byte PB_MK_AC               = (byte) 0x09;
    public static final byte PB_MK_SMI              = (byte) 0x0A;
    public static final byte PB_MK_SMC              = (byte) 0x0B;
    public static final byte PB_AIP                 = (byte) 0x0C;
    public static final byte PB_AFL                 = (byte) 0x0D;
    public static final byte PB_AUC                 = (byte) 0x0E;
    public static final byte PB_IAC_DEFAULT         = (byte) 0x0F;
    public static final byte PB_IAC_DENIAL          = (byte) 0x10;
    public static final byte PB_IAC_ONLINE          = (byte) 0x11;
    public static final byte PB_CVM_LIST            = (byte) 0x12;
    // Tags 0x13 (bankId), 0x14 (progId), 0x15 (postProvisionUrl) are
    // emitted by the server in the ParamBundle but have no chip-side
    // consumer — they're server-DB-held metadata.  The chip ignores
    // them; ParamBundleParser just walks past.  Reserved values.
    public static final byte PB_ICC_RSA_PRIV        = (byte) 0x16;
    public static final byte PB_ICC_PK_CERT         = (byte) 0x17;
    public static final byte PB_APP_LABEL           = (byte) 0x18;
    public static final byte PB_APP_PREFERRED_NAME  = (byte) 0x19;
    public static final byte PB_APP_VERSION         = (byte) 0x1A;
    public static final byte PB_CURRENCY_CODE       = (byte) 0x1B;
    public static final byte PB_CURRENCY_EXPONENT   = (byte) 0x1C;
    public static final byte PB_COUNTRY_CODE        = (byte) 0x1D;
    public static final byte PB_ICVV                = (byte) 0x1E;
    public static final byte PB_ISSUER_PK_EXP       = (byte) 0x1F;
    public static final byte PB_ISSUER_PK_CERT      = (byte) 0x20;
    public static final byte PB_ISSUER_PK_REMAINDER = (byte) 0x21;
    public static final byte PB_CA_PK_INDEX         = (byte) 0x22;

    // -----------------------------------------------------------------
    // Scheme / CVN bytes (also in scheme-mchip.ts)
    // -----------------------------------------------------------------

    public static final byte SCHEME_MCHIP = (byte) 0x01;
    public static final byte SCHEME_VSDC  = (byte) 0x02;
    public static final byte CVN_MCHIP_18 = (byte) 0x12;

    // -----------------------------------------------------------------
    // State machine (replaces v2's more permissive states)
    // -----------------------------------------------------------------

    /** Virgin state — pre-any-provisioning.  TRANSFER_PARAMS expects this. */
    public static final byte STATE_IDLE              = (byte) 0x00;
    /** After GENERATE_KEYS — ECC keypair ready; awaiting ParamBundle. */
    public static final byte STATE_KEYGEN_COMPLETE   = (byte) 0x01;
    /** After TRANSFER_PARAMS — DGIs committed; awaiting FINAL_STATUS. */
    public static final byte STATE_PARAMS_COMMITTED  = (byte) 0x02;
    /** After FINAL_STATUS — provenance hash emitted; awaiting CONFIRM. */
    public static final byte STATE_AWAITING_CONFIRM  = (byte) 0x03;
    /** After CONFIRM — fully provisioned; TRANSFER_PARAMS/GENKEYS rejected. */
    public static final byte STATE_COMMITTED         = (byte) 0x04;

    // -----------------------------------------------------------------
    // ECDH / HKDF / AES-GCM protocol constants
    // MUST match packages/emv-ecdh/src/index.ts's ECDH_PROTOCOL.
    // -----------------------------------------------------------------

    /** HKDF salt — "paramBundleV1" ASCII, 13 bytes. */
    public static final byte[] HKDF_SALT = {
        (byte) 'p', (byte) 'a', (byte) 'r', (byte) 'a',
        (byte) 'm', (byte) 'B', (byte) 'u', (byte) 'n',
        (byte) 'd', (byte) 'l', (byte) 'e', (byte) 'V',
        (byte) '1'
    };
    public static final short HKDF_SALT_LEN = (short) 13;

    public static final short SEC1_UNCOMPRESSED_LEN = (short) 65;
    public static final short AES_KEY_LEN = (short) 16;
    public static final short AES_IV_LEN = (short) 16;      // AES block size
    public static final short HMAC_KEY_LEN = (short) 32;    // right-sized HMAC-SHA256 key
    public static final short HMAC_TAG_LEN = (short) 16;    // truncated HMAC-SHA256

    /**
     * Chip-side nonce width used for patent claim C4 replay binding.
     * 16 bytes is enough that a collision across a single card's
     * lifetime is negligible and matches AES-IV / HMAC-tag sizing
     * patterns already in the ECDH wire format — so callers can
     * reuse the same scratch buffers interchangeably.
     */
    public static final short CHIP_NONCE_LEN = (short) 16;
    /** HKDF-SHA256 output: aesKey(16) || iv(16) || hmacKey(32) = 64 bytes. */
    public static final short HKDF_OUTPUT_LEN =
        (short) (AES_KEY_LEN + AES_IV_LEN + HMAC_KEY_LEN);

    // -----------------------------------------------------------------
    // EMV tag numbers (2-byte big-endian for tags >= 0x5F)
    // -----------------------------------------------------------------

    public static final short TAG_AIP              = (short) 0x0082;
    public static final short TAG_AFL              = (short) 0x0094;
    public static final short TAG_AUC              = (short) 0x9F07;
    public static final short TAG_PAN              = (short) 0x005A;
    public static final short TAG_EXPIRY_YYMMDD    = (short) 0x5F24;
    public static final short TAG_EFFECTIVE_YYMMDD = (short) 0x5F25;
    public static final short TAG_TRACK2           = (short) 0x0057;
    public static final short TAG_PSN              = (short) 0x5F34;
    public static final short TAG_AID              = (short) 0x0084;
    public static final short TAG_APP_VERSION      = (short) 0x9F08;
    public static final short TAG_CURRENCY_CODE    = (short) 0x9F42;
    public static final short TAG_CURRENCY_EXP     = (short) 0x9F44;
    public static final short TAG_COUNTRY_CODE     = (short) 0x5F28;
    public static final short TAG_APP_LABEL        = (short) 0x0050;
    public static final short TAG_IAC_DEFAULT      = (short) 0x9F0D;
    public static final short TAG_IAC_DENIAL       = (short) 0x9F0E;
    public static final short TAG_IAC_ONLINE       = (short) 0x9F0F;
    public static final short TAG_CVM_LIST         = (short) 0x008E;
    public static final short TAG_ICC_PK_CERT      = (short) 0x9F46;

    /** Proprietary MChip MK-AC slot. */
    public static final short TAG_MC_MK_AC  = (short) 0x9F52;
    /** Proprietary MChip MK-SMI slot. */
    public static final short TAG_MC_MK_SMI = (short) 0x9F53;
    /** Proprietary MChip MK-SMC slot. */
    public static final short TAG_MC_MK_SMC = (short) 0x9F54;
    /** Proprietary PA slot for ICC RSA priv. */
    public static final short TAG_ICC_RSA_PRIV_SLOT = (short) 0xDF73;
    /** Proprietary PA slot for iCVV (CVN 18 offline Track 2 verify). */
    public static final short TAG_ICVV_SLOT = (short) 0xDF74;

    // -----------------------------------------------------------------
    // DGI numbers the applet emits (mirror of simulateMChipChipBuild)
    // -----------------------------------------------------------------

    public static final short DGI_APP_DATA     = (short) 0x0101;
    public static final short DGI_AFL_DUPE     = (short) 0x0102;
    public static final short DGI_KEY_SLOTS    = (short) 0x8201;
    public static final short DGI_MCHIP_SCHEME = (short) 0x9201;

    // -----------------------------------------------------------------
    // SW error codes
    // -----------------------------------------------------------------

    public static final short SW_DATA_INVALID       = (short) 0x6984;
    public static final short SW_WRONG_STATE        = (short) 0x6985;
    public static final short SW_FUNC_NOT_SUPPORTED = (short) 0x6A81;
    public static final short SW_CLA_NOT_SUPPORTED  = (short) 0x6E00;
    public static final short SW_INS_NOT_SUPPORTED  = (short) 0x6D00;

    /** Custom — ECDH unwrap HMAC tag verification failed. */
    public static final short SW_PARAM_BUNDLE_GCM_FAILED = (short) 0x6A80;
    /** Custom — ParamBundle missing a required tag. */
    public static final short SW_PARAM_BUNDLE_INCOMPLETE = (short) 0x6A81;
    /** Custom — unsupported scheme or CVN. */
    public static final short SW_PARAM_BUNDLE_UNSUPPORTED = (short) 0x6A82;

    // --- Debug SWs emitted by EcdhUnwrapper — distinct per failure
    //     point so a server-side log diff between server OKM and chip
    //     OKM can be narrowed to the exact mismatch.  Prod reverts
    //     these all to SW_PARAM_BUNDLE_GCM_FAILED once the prototype
    //     is byte-parity proven on real silicon.
    /** Debug — wire too short for 65+16+16 framing. */
    public static final short SW_DBG_WIRE_TOO_SHORT   = (short) 0x6AE1;
    /** Debug — ciphertext length not a positive multiple of 16. */
    public static final short SW_DBG_CT_BAD_LEN       = (short) 0x6AE2;
    /** Debug — ECDH generateSecret returned not-32 bytes. */
    public static final short SW_DBG_SHARED_LEN_BAD   = (short) 0x6AE3;
    /** Debug — HKDF-derived IV != wire IV (OKM mismatch up to IV). */
    public static final short SW_DBG_IV_MISMATCH      = (short) 0x6AE4;
    /** Debug — HMAC tag mismatch (OKM matches through IV but hmacKey differs
     *  OR ciphertext tampered). */
    public static final short SW_DBG_HMAC_MISMATCH    = (short) 0x6AE5;
    /** Debug — AES-CBC doFinal threw (PKCS#5 unpad fail, usually). */
    public static final short SW_DBG_CBC_UNPAD_FAIL   = (short) 0x6AE6;

    // --- Per-step debug SWs for the post-unwrap NVM-commit path.  If
    //     any of these escape to the server, the named builder faulted
    //     (usually buffer overflow from an under-sized work buffer, or
    //     a missing ParamBundle tag that validateMChipCvn18 let slip).
    //     Prod folds all of these into SW_DATA_INVALID once the 4 DGI
    //     builders are byte-parity proven on-chip vs the TS simulator.
    /** Debug — DgiBuilderMchip.buildDgi0101 threw an uncaught runtime. */
    public static final short SW_DBG_BUILD_0101_FAIL  = (short) 0x6AF1;
    /** Debug — DgiBuilderMchip.buildDgi0102 threw an uncaught runtime. */
    public static final short SW_DBG_BUILD_0102_FAIL  = (short) 0x6AF2;
    /** Debug — DgiBuilderMchip.buildDgi8201 threw an uncaught runtime. */
    public static final short SW_DBG_BUILD_8201_FAIL  = (short) 0x6AF3;
    /** Debug — DgiBuilderMchip.buildDgi9201 threw an uncaught runtime. */
    public static final short SW_DBG_BUILD_9201_FAIL  = (short) 0x6AF4;
    // 0x6AF5 was SW_DBG_METADATA_FAIL — retired with the v2
    // persistMetadata stub; slot reserved to avoid renumbering the
    // adjacent BUILD_*/COMMIT_FAIL codes that rca log-greps for.
    /** Debug — commitTransaction itself threw (transaction buffer full?). */
    public static final short SW_DBG_COMMIT_FAIL      = (short) 0x6AF6;

    // --- STORE_ATTESTATION / GET_ATTESTATION_CHAIN debug SWs ---
    /** Debug — STORE_ATTESTATION P1 not one of the defined values. */
    public static final short SW_DBG_ATTEST_BAD_P1    = (short) 0x6AF7;
    /** Debug — STORE_ATTESTATION body length doesn't match the
     *  expected width for the selected P1 (priv=32, cplc=42, cert=<=256). */
    public static final short SW_DBG_ATTEST_BAD_LEN   = (short) 0x6AF8;
    /** Debug — signAttestation / getCardCert / getCplc called before
     *  the corresponding STORE_ATTESTATION load. */
    public static final short SW_DBG_ATTEST_NOT_LOADED = (short) 0x6AF9;
}
