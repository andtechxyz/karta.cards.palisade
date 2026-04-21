package com.palisade.pa;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;

/**
 * Palisade Provisioning Agent v3 — chip-computed-DGI prototype.
 *
 * Accepts an ECDH-wrapped ParamBundle via TRANSFER_PARAMS (INS=0xE2),
 * unwraps on-chip, parses the TLV bundle, builds the four MChip CVN 18
 * DGIs inline, and commits them to NVM.  The server never builds or
 * sees a plaintext DGI image — C17/C22 patent claim ("no perso image
 * outside the SE") satisfied.
 *
 * STATE MACHINE:
 *
 *   IDLE                (virgin state, after install or WIPE)
 *    └──GENERATE_KEYS──▶ KEYGEN_COMPLETE
 *                         └──TRANSFER_PARAMS──▶ PARAMS_COMMITTED
 *                                                └──FINAL_STATUS──▶ AWAITING_CONFIRM
 *                                                                    └──CONFIRM──▶ COMMITTED
 *
 *   Any state → WIPE → IDLE
 *   COMMITTED: GENERATE_KEYS / TRANSFER_PARAMS return 6985
 *
 * APDU HANDLING (selector from this.process()):
 *
 *   CLA != 0x80                → SW 6E00
 *   INS_GENERATE_KEYS (0xE0)   → processGenerateKeys()
 *   INS_TRANSFER_PARAMS (0xE2) → processTransferParams()
 *   INS_FINAL_STATUS (0xE6)    → processFinalStatus() [unchanged from v2]
 *   INS_CONFIRM (0xE8)         → processConfirm() [unchanged from v2]
 *   INS_WIPE (0xEA)            → processWipe() [unchanged from v2]
 *   Unknown INS                → SW 6D00
 *
 * LIFECYCLE OF THE DECRYPTED PARAM BUNDLE:
 *
 *   1. Server sends TRANSFER_PARAMS APDU with ECDH-wrapped bundle
 *   2. Applet allocates a transient RAM buffer (CLEAR_ON_DESELECT)
 *   3. EcdhUnwrapper.unwrap writes plaintext into that buffer
 *   4. ParamBundleParser.validateMChipCvn18 confirms required tags
 *   5. DgiBuilderMchip builds DGI 0101/0102/8201/9201 into NVM buffers
 *   6. All NVM writes happen inside JCSystem.beginTransaction() /
 *      commitTransaction() so a power-off mid-write rolls back
 *   7. Plaintext bundle buffer zeroed via Util.arrayFillNonAtomic
 *   8. All transient buffers auto-clear at next SELECT (CLEAR_ON_DESELECT)
 *   9. State → PARAMS_COMMITTED
 *
 * RAM BUDGET:
 *
 *   Wire bytes buffer:       512 B (transient) — holds TRANSFER_PARAMS body
 *   Plaintext bundle buffer: 512 B (transient) — holds unwrapped bundle
 *   DGI assembly buffer:     256 B (transient) — one DGI at a time,
 *                                                reused per DGI
 *   Scratch offsets short[]: 2 × 2 B = 4 B
 *
 * NVM FOOTPRINT:
 *
 *   DGI 0x0101 storage:   ~120 B persistent
 *   DGI 0x0102 storage:    ~12 B
 *   DGI 0x8201 storage:   ~200 B (3 MKs + ICC PK cert + ICC RSA priv)
 *   DGI 0x9201 storage:    ~50 B
 *   Plus per-card metadata (bankId, progId, postProvisionUrl, etc.)
 *
 * BUILD + INSTALL:
 *
 *   See applets/pa-v3/README.md
 *
 * TEST HARNESS:
 *
 *   Byte-parity with the TS simulator is proved in packages/emv/src/
 *   byte-parity.test.ts — the Java DGI builders must match.  Applet-
 *   side unit tests (on JCOP 5 reference hardware) live at
 *   applets/pa-v3/test/ (to be written as part of integration phase).
 */
public class ProvisioningAgentV3 extends Applet {

    // -----------------------------------------------------------------
    // Applet state (EEPROM — persists across power cycles)
    // -----------------------------------------------------------------

    /** State machine position. */
    private byte state;

    /** Session ID for the current provisioning attempt (set at GEN_KEYS,
     *  used during TRANSFER_PARAMS for HKDF info binding). */
    private byte[] sessionId;
    private short sessionIdLen;

    /** NVM storage for each DGI's TLV payload. */
    private byte[] dgi0101Nvm;
    private short dgi0101Len;

    private byte[] dgi0102Nvm;
    private short dgi0102Len;

    private byte[] dgi8201Nvm;
    private short dgi8201Len;

    private byte[] dgi9201Nvm;
    private short dgi9201Len;

    // -----------------------------------------------------------------
    // Transient RAM
    // -----------------------------------------------------------------

    /** Holds the ECDH-wrapped TRANSFER_PARAMS APDU body. */
    private byte[] wireBuf;

    /** Holds the decrypted ParamBundle plaintext. */
    private byte[] bundleBuf;

    /** Working buffer for DGI assembly; reused across all 4 DGIs. */
    private byte[] dgiWorkBuf;

    /** 2-element scratch for ParamBundleParser.findTag output
     *  [valueOff, valueLen]. */
    private short[] scratch;

    // -----------------------------------------------------------------
    // ECC P-256 keypair (generated in GENERATE_KEYS, used for ECDH
    // during TRANSFER_PARAMS).  Verbatim curve parameters from
    // palisade-pa's ProvisioningAgent.java so the key agreement math
    // matches the server's wrap side.
    // -----------------------------------------------------------------

    private static final byte[] P256_P = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF
    };
    private static final byte[] P256_A = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFC
    };
    private static final byte[] P256_B = {
        (byte)0x5A,(byte)0xC6,(byte)0x35,(byte)0xD8, (byte)0xAA,(byte)0x3A,(byte)0x93,(byte)0xE7,
        (byte)0xB3,(byte)0xEB,(byte)0xBD,(byte)0x55, (byte)0x76,(byte)0x98,(byte)0x86,(byte)0xBC,
        (byte)0x65,(byte)0x1D,(byte)0x06,(byte)0xB0, (byte)0xCC,(byte)0x53,(byte)0xB0,(byte)0xF6,
        (byte)0x3B,(byte)0xCE,(byte)0x3C,(byte)0x3E, (byte)0x27,(byte)0xD2,(byte)0x60,(byte)0x4B
    };
    private static final byte[] P256_G = {
        (byte)0x04,
        (byte)0x6B,(byte)0x17,(byte)0xD1,(byte)0xF2, (byte)0xE1,(byte)0x2C,(byte)0x42,(byte)0x47,
        (byte)0xF8,(byte)0xBC,(byte)0xE6,(byte)0xE5, (byte)0x63,(byte)0xA4,(byte)0x40,(byte)0xF2,
        (byte)0x77,(byte)0x03,(byte)0x7D,(byte)0x81, (byte)0x2D,(byte)0xEB,(byte)0x33,(byte)0xA0,
        (byte)0xF4,(byte)0xA1,(byte)0x39,(byte)0x45, (byte)0xD8,(byte)0x98,(byte)0xC2,(byte)0x96,
        (byte)0x4F,(byte)0xE3,(byte)0x42,(byte)0xE2, (byte)0xFE,(byte)0x1A,(byte)0x7F,(byte)0x9B,
        (byte)0x8E,(byte)0xE7,(byte)0xEB,(byte)0x4A, (byte)0x7C,(byte)0x0F,(byte)0x9E,(byte)0x16,
        (byte)0x2B,(byte)0xCE,(byte)0x33,(byte)0x57, (byte)0x6B,(byte)0x31,(byte)0x5E,(byte)0xCE,
        (byte)0xCB,(byte)0xB6,(byte)0x40,(byte)0x68, (byte)0x37,(byte)0xBF,(byte)0x51,(byte)0xF5
    };
    private static final byte[] P256_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xBC,(byte)0xE6,(byte)0xFA,(byte)0xAD, (byte)0xA7,(byte)0x17,(byte)0x9E,(byte)0x84,
        (byte)0xF3,(byte)0xB9,(byte)0xCA,(byte)0xC2, (byte)0xFC,(byte)0x63,(byte)0x25,(byte)0x51
    };

    private final KeyPair iccKeyPair;

    /** Scratch for exporting the private scalar during GENERATE_KEYS. */
    private byte[] privScratch;

    // -----------------------------------------------------------------
    // Constructor + install
    // -----------------------------------------------------------------

    protected ProvisioningAgentV3(byte[] bArray, short bOffset, byte bLength) {
        // EEPROM allocations.  Sized for MChip CVN 18 worst-case DGIs.
        sessionId  = new byte[64];  // cuid2 is 24 chars; 64 = generous
        dgi0101Nvm = new byte[128];
        dgi0102Nvm = new byte[16];
        dgi8201Nvm = new byte[256];
        dgi9201Nvm = new byte[64];

        // Transient RAM — auto-cleared on deselect.  We need the full
        // APDU body in RAM for ECDH unwrap since AES-GCM's tag verify
        // needs the full ciphertext in one pass.  500+ bytes is fine
        // on JCOP 5 (typical RAM is 4-8 KB).
        wireBuf    = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
        bundleBuf  = JCSystem.makeTransientByteArray((short) 512, JCSystem.CLEAR_ON_DESELECT);
        dgiWorkBuf = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_DESELECT);
        scratch    = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_DESELECT);

        // 32-byte scratch for exporting the EC private scalar inside
        // GENERATE_KEYS — transient so the secret never survives deselect.
        privScratch = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);

        // P-256 keypair — curve params installed once here; keypair regen
        // happens every GENERATE_KEYS call.
        iccKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        initP256Params((ECPublicKey) iccKeyPair.getPublic());
        initP256Params((ECPrivateKey) iccKeyPair.getPrivate());

        state = Constants.STATE_IDLE;
        register();

        EcdhUnwrapper.initOnce();
    }

    // -----------------------------------------------------------------
    // P-256 curve parameter injection helpers.  ALG_EC_FP keys ship
    // uninitialised; the applet must set the field prime, a, b, base
    // point, order, and cofactor before genKeyPair() works.
    // -----------------------------------------------------------------

    private static void initP256Params(ECPublicKey key) {
        key.setFieldFP(P256_P, (short) 0, (short) P256_P.length);
        key.setA(P256_A, (short) 0, (short) P256_A.length);
        key.setB(P256_B, (short) 0, (short) P256_B.length);
        key.setG(P256_G, (short) 0, (short) P256_G.length);
        key.setR(P256_N, (short) 0, (short) P256_N.length);
        key.setK((short) 1);
    }

    private static void initP256Params(ECPrivateKey key) {
        key.setFieldFP(P256_P, (short) 0, (short) P256_P.length);
        key.setA(P256_A, (short) 0, (short) P256_A.length);
        key.setB(P256_B, (short) 0, (short) P256_B.length);
        key.setG(P256_G, (short) 0, (short) P256_G.length);
        key.setR(P256_N, (short) 0, (short) P256_N.length);
        key.setK((short) 1);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new ProvisioningAgentV3(bArray, bOffset, bLength);
    }

    // -----------------------------------------------------------------
    // APDU dispatch
    // -----------------------------------------------------------------

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buf = apdu.getBuffer();

        if (buf[ISO7816.OFFSET_CLA] != Constants.CLA_PA) {
            ISOException.throwIt(Constants.SW_CLA_NOT_SUPPORTED);
        }

        switch (buf[ISO7816.OFFSET_INS]) {
            case Constants.INS_GENERATE_KEYS:
                processGenerateKeys(apdu);
                break;
            case Constants.INS_TRANSFER_PARAMS:
                processTransferParams(apdu);
                break;
            case Constants.INS_FINAL_STATUS:
                processFinalStatus(apdu);
                break;
            case Constants.INS_CONFIRM:
                processConfirm(apdu);
                break;
            case Constants.INS_WIPE:
                processWipe(apdu);
                break;
            default:
                ISOException.throwIt(Constants.SW_INS_NOT_SUPPORTED);
        }
    }

    // -----------------------------------------------------------------
    // GENERATE_KEYS — unchanged from v2 except state transition
    // -----------------------------------------------------------------

    private void processGenerateKeys(APDU apdu) {
        if (state == Constants.STATE_COMMITTED) {
            // Already provisioned — no re-keygen without WIPE.
            ISOException.throwIt(Constants.SW_WRONG_STATE);
        }

        // Request body format (same as v2): keyType(0x01 = ECC P-256)
        // || sessionId (up to 63 bytes).  Validate + persist sessionId.
        short bodyLen = apdu.setIncomingAndReceive();
        byte[] buf = apdu.getBuffer();

        if (bodyLen < (short) 1) {
            ISOException.throwIt(Constants.SW_DATA_INVALID);
        }
        if (buf[ISO7816.OFFSET_CDATA] != (byte) 0x01) {
            // Only ECC P-256 supported.
            ISOException.throwIt(Constants.SW_DATA_INVALID);
        }
        sessionIdLen = (short) (bodyLen - 1);
        if (sessionIdLen > (short) 63) {
            ISOException.throwIt(Constants.SW_DATA_INVALID);
        }
        Util.arrayCopyNonAtomic(
            buf, (short) (ISO7816.OFFSET_CDATA + 1),
            sessionId, (short) 0, sessionIdLen
        );

        // Generate the ECC P-256 keypair.  genKeyPair() populates both
        // public and private halves of iccKeyPair using the curve params
        // we installed in the constructor.
        iccKeyPair.genKeyPair();

        ECPrivateKey priv = (ECPrivateKey) iccKeyPair.getPrivate();
        ECPublicKey  pub  = (ECPublicKey)  iccKeyPair.getPublic();

        // Hand the freshly-generated scalar to EcdhUnwrapper so the
        // subsequent TRANSFER_PARAMS can drive ECDH against the same
        // keypair.  Scrub the scratch immediately after so the plaintext
        // scalar never lives longer than this APDU.
        short sLen = priv.getS(privScratch, (short) 0);
        try {
            EcdhUnwrapper.setChipPriv(privScratch, (short) 0, sLen);
        } finally {
            Util.arrayFillNonAtomic(privScratch, (short) 0, (short) privScratch.length, (byte) 0);
        }

        // Write the 65-byte uncompressed public key (0x04 || X(32) || Y(32))
        // into the APDU response buffer.  TODO(jc-dev): once the factory
        // attestation key is provisioned at install time, append the
        // signature + CPLC trailer here so rca's AttestationVerifier has
        // real material to verify in strict mode.  Until then permissive
        // mode accepts pubkey-only responses, which is what this emits.
        short wLen = pub.getW(buf, (short) 0);

        state = Constants.STATE_KEYGEN_COMPLETE;
        apdu.setOutgoingAndSend((short) 0, wLen);
    }

    // -----------------------------------------------------------------
    // TRANSFER_PARAMS — THE NEW STUFF
    // -----------------------------------------------------------------

    private void processTransferParams(APDU apdu) {
        if (state != Constants.STATE_KEYGEN_COMPLETE) {
            ISOException.throwIt(Constants.SW_WRONG_STATE);
        }

        // 1. Receive the full APDU body into wireBuf.
        //    Extended APDUs or chained short APDUs both land here —
        //    APDU.setIncomingAndReceive() handles the chaining for us.
        short totalLen = apdu.setIncomingAndReceive();
        byte[] apduBuf = apdu.getBuffer();

        if (totalLen > (short) wireBuf.length) {
            ISOException.throwIt(Constants.SW_DATA_INVALID);
        }
        Util.arrayCopyNonAtomic(
            apduBuf, ISO7816.OFFSET_CDATA,
            wireBuf, (short) 0, totalLen
        );

        // 2. ECDH + HKDF + AES-GCM unwrap into bundleBuf.
        //    Throws SW_PARAM_BUNDLE_GCM_FAILED on tag verify failure.
        short bundleLen = EcdhUnwrapper.unwrap(
            wireBuf, (short) 0, totalLen,
            sessionId, (short) 0, sessionIdLen,
            bundleBuf, (short) 0
        );

        // 3. Validate the bundle has all required tags for MChip CVN 18.
        short validateSw = ParamBundleParser.validateMChipCvn18(
            bundleBuf, (short) 0, bundleLen, scratch
        );
        if (validateSw != (short) 0x9000) {
            // Scrub before throwing.
            Util.arrayFillNonAtomic(bundleBuf, (short) 0, bundleLen, (byte) 0);
            ISOException.throwIt(validateSw);
        }

        // 4. Build DGIs and write to NVM atomically.
        JCSystem.beginTransaction();
        try {
            dgi0101Len = DgiBuilderMchip.buildDgi0101(
                bundleBuf, (short) 0, bundleLen, scratch,
                dgiWorkBuf, (short) 0
            );
            Util.arrayCopy(dgiWorkBuf, (short) 0, dgi0101Nvm, (short) 0, dgi0101Len);

            dgi0102Len = DgiBuilderMchip.buildDgi0102(
                bundleBuf, (short) 0, bundleLen, scratch,
                dgiWorkBuf, (short) 0
            );
            Util.arrayCopy(dgiWorkBuf, (short) 0, dgi0102Nvm, (short) 0, dgi0102Len);

            dgi8201Len = DgiBuilderMchip.buildDgi8201(
                bundleBuf, (short) 0, bundleLen, scratch,
                dgiWorkBuf, (short) 0
            );
            Util.arrayCopy(dgiWorkBuf, (short) 0, dgi8201Nvm, (short) 0, dgi8201Len);

            dgi9201Len = DgiBuilderMchip.buildDgi9201(
                bundleBuf, (short) 0, bundleLen, scratch,
                dgiWorkBuf, (short) 0
            );
            Util.arrayCopy(dgiWorkBuf, (short) 0, dgi9201Nvm, (short) 0, dgi9201Len);

            // Also extract + persist per-card metadata (bankId, progId,
            // postProvisionUrl) that existed in the v2 TRANSFER_SAD
            // metadata-trailer format.  Same tags; just pull via
            // ParamBundleParser.findTag.
            persistMetadata(bundleBuf, (short) 0, bundleLen);

            state = Constants.STATE_PARAMS_COMMITTED;

            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            Util.arrayFillNonAtomic(bundleBuf, (short) 0, bundleLen, (byte) 0);
            throw (e instanceof ISOException) ? (ISOException) e
                                               : new ISOException(Constants.SW_DATA_INVALID);
        }

        // 5. Scrub the plaintext bundle.  Transient clears on deselect
        //    anyway but an attacker who physically glitches the power
        //    between decrypt and deselect could read residual state;
        //    the explicit zero pass shortens the window.
        Util.arrayFillNonAtomic(bundleBuf, (short) 0, bundleLen, (byte) 0);

        // No response body — SW=9000 signals success.
    }

    /**
     * Extract per-card metadata from the ParamBundle and persist.
     * Called inside the TRANSFER_PARAMS transaction.
     */
    private void persistMetadata(byte[] bBuf, short bOff, short bLen) {
        // bankId (4 BE bytes)
        if (ParamBundleParser.findTag(bBuf, bOff, bLen, Constants.PB_BANK_ID, scratch)) {
            // TODO: Util.arrayCopy into bankIdNvm[0..4]
        }
        // progId
        if (ParamBundleParser.findTag(bBuf, bOff, bLen, Constants.PB_PROG_ID, scratch)) {
            // TODO: arrayCopy into progIdNvm[0..4]
        }
        // postProvisionUrl
        if (ParamBundleParser.findTag(bBuf, bOff, bLen, Constants.PB_POST_PROVISION_URL, scratch)) {
            // TODO: arrayCopy into urlNvm[0..urlLen]
        }
    }

    // -----------------------------------------------------------------
    // FINAL_STATUS — unchanged from v2; port verbatim
    // -----------------------------------------------------------------

    private void processFinalStatus(APDU apdu) {
        if (state != Constants.STATE_PARAMS_COMMITTED) {
            ISOException.throwIt(Constants.SW_WRONG_STATE);
        }
        // Emits [status(1) || provenance_hash(32) || fido_cred_len(1) ||
        //        fido_cred_id(var)] — compute provenance from the four
        // DGIs and copy to output.
        //
        // TODO(jc-dev): port v2's processFinalStatus body here.

        state = Constants.STATE_AWAITING_CONFIRM;
    }

    // -----------------------------------------------------------------
    // CONFIRM — unchanged from v2; port verbatim
    // -----------------------------------------------------------------

    private void processConfirm(APDU apdu) {
        if (state != Constants.STATE_AWAITING_CONFIRM) {
            ISOException.throwIt(Constants.SW_WRONG_STATE);
        }

        // Latch to COMMITTED.  No response body.  NVM write wrapped in
        // transaction.
        JCSystem.beginTransaction();
        state = Constants.STATE_COMMITTED;
        JCSystem.commitTransaction();
    }

    // -----------------------------------------------------------------
    // WIPE — unchanged from v2; zeroes all DGI NVM + state → IDLE
    // -----------------------------------------------------------------

    private void processWipe(APDU apdu) {
        JCSystem.beginTransaction();
        Util.arrayFillNonAtomic(dgi0101Nvm, (short) 0, (short) dgi0101Nvm.length, (byte) 0);
        Util.arrayFillNonAtomic(dgi0102Nvm, (short) 0, (short) dgi0102Nvm.length, (byte) 0);
        Util.arrayFillNonAtomic(dgi8201Nvm, (short) 0, (short) dgi8201Nvm.length, (byte) 0);
        Util.arrayFillNonAtomic(dgi9201Nvm, (short) 0, (short) dgi9201Nvm.length, (byte) 0);
        dgi0101Len = 0;
        dgi0102Len = 0;
        dgi8201Len = 0;
        dgi9201Len = 0;
        Util.arrayFillNonAtomic(sessionId, (short) 0, (short) sessionId.length, (byte) 0);
        sessionIdLen = 0;
        state = Constants.STATE_IDLE;
        JCSystem.commitTransaction();
    }
}
