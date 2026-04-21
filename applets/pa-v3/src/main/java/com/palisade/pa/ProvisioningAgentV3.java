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
import javacard.security.RandomData;

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

    /** Accumulated byte count when receiving TRANSFER_PARAMS as a
     *  series of chained short APDUs (CLA bit 0x10 set on non-final
     *  chunks).  Reset to 0 on the final chunk AFTER processing. */
    private short chainOff;

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

    static final byte[] P256_P = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF
    };
    static final byte[] P256_A = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x01,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFC
    };
    static final byte[] P256_B = {
        (byte)0x5A,(byte)0xC6,(byte)0x35,(byte)0xD8, (byte)0xAA,(byte)0x3A,(byte)0x93,(byte)0xE7,
        (byte)0xB3,(byte)0xEB,(byte)0xBD,(byte)0x55, (byte)0x76,(byte)0x98,(byte)0x86,(byte)0xBC,
        (byte)0x65,(byte)0x1D,(byte)0x06,(byte)0xB0, (byte)0xCC,(byte)0x53,(byte)0xB0,(byte)0xF6,
        (byte)0x3B,(byte)0xCE,(byte)0x3C,(byte)0x3E, (byte)0x27,(byte)0xD2,(byte)0x60,(byte)0x4B
    };
    static final byte[] P256_G = {
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
    static final byte[] P256_N = {
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00,
        (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF, (byte)0xFF,(byte)0xFF,(byte)0xFF,(byte)0xFF,
        (byte)0xBC,(byte)0xE6,(byte)0xFA,(byte)0xAD, (byte)0xA7,(byte)0x17,(byte)0x9E,(byte)0x84,
        (byte)0xF3,(byte)0xB9,(byte)0xCA,(byte)0xC2, (byte)0xFC,(byte)0x63,(byte)0x25,(byte)0x51
    };

    private final KeyPair iccKeyPair;

    /**
     * RNG for chip-side nonce generation (patent claim C4).  Uses
     * JCOP 5's hardware TRNG via ALG_SECURE_RANDOM — cryptographically
     * strong per JC spec.  Reused across sessions; internal state is
     * self-reseeding.
     */
    private final RandomData rng;

    /**
     * Per-card attestation material (patent claims C16/C23).  Loaded
     * at personalisation via STORE_ATTESTATION; queried at
     * GENERATE_KEYS time (Phase B) to sign the ephemeral iccPubkey
     * with the per-card attestation key, and at GET_ATTESTATION_CHAIN
     * time to emit the issuer-signed card cert blob.
     */
    private final IssuerAttestation attestation;

    // -----------------------------------------------------------------
    // Constructor + install
    // -----------------------------------------------------------------

    protected ProvisioningAgentV3(byte[] bArray, short bOffset, byte bLength) {
        // EEPROM allocations.  Sized for MChip CVN 18 worst-case DGIs.
        //
        // DGI 8201 sizing breakdown (see DgiBuilderMchip.buildDgi8201):
        //   9F52 MK-AC   : 2 + 1 +  16 =  19 B
        //   9F53 MK-SMI  : 2 + 1 +  16 =  19 B
        //   9F54 MK-SMC  : 2 + 1 +  16 =  19 B
        //   9F46 PK cert : 2 + 1 + 112 = 115 B (short-form, 112<128)
        //   DF73 RSA prv : 2 + 2 + 128 = 132 B (long-form,  128>=128)
        //                                ---
        //                                304 B  ← with today's 128B/112B
        //   Worst case (both keys at the MAX_FIELD_LEN=255 cap):
        //                       2+2+255 + 2+2+255 + 3*19 = 576 B
        //
        // An earlier dgi8201Nvm=256 was too small for even the current
        // data-prep defaults (304 B); buffer overflow during
        // Util.arrayCopy inside beginTransaction caused the JCVM to
        // mute the contactless interface mid-commit on tap.
        // Bumped to 512 B to cover typical 1408-bit RSA paths and
        // 2048-bit cert paths with some slack, still well inside the
        // JCOP 5 EEPROM budget.
        // sessionId stores incoming server session id (typ 24 B cuid2)
        // followed by the 16-byte chip-side nonce generated at GEN_KEYS.
        // 96 B leaves ample headroom for future id schemes without
        // risking an off-by-one when the nonce is appended.  See
        // processGenerateKeys for the C4 nonce binding that extends
        // sessionIdLen by 16 after keygen and uses the combined buffer
        // as HKDF info during TRANSFER_PARAMS.
        sessionId  = new byte[96];
        dgi0101Nvm = new byte[256]; // bumped from 128 for Track 2 + long PANs
        // DGI 0102 = 1B tag(0x94) + 1B len + AFL bytes.  The karta-platinum
        // seed sets AFL = 16 B (32 hex chars), so DGI 0102 = 18 B — the
        // original 16 B buffer overflowed in Util.arrayCopy during the
        // post-build NVM write and returned SW 6AF2.  Bumped to 64 B to
        // cover realistic AFL lengths (4 records × 4 B each = 16 B is
        // the common case, up to maybe 24-32 B for uncommon card designs).
        dgi0102Nvm = new byte[64];
        dgi8201Nvm = new byte[512]; // bumped from 256 — see note above
        dgi9201Nvm = new byte[128]; // bumped from 64 for CVM-list headroom

        // Transient RAM — auto-cleared on deselect.  We need the full
        // APDU body in RAM for ECDH unwrap since the HMAC tag verify
        // needs the full ciphertext in one pass.  Real TRANSFER_PARAMS
        // bodies run ~700-800 B (65 pubkey + 16 IV + 16 HMAC + ct
        // where ct is the AES-CBC-padded bundle ~ 600 B).  1024 B
        // leaves headroom for larger ParamBundles (iCVV rotation,
        // post-provisioning URLs longer than 64 B, etc.).
        //
        // dgiWorkBuf is the scratch used by DgiBuilderMchip to assemble
        // one DGI at a time before the caller copies it to the matching
        // NVM slot.  Must be >= the largest DGI output (8201 @ 304 B
        // today, up to 576 B in worst case), so we use 1024 B to match
        // wireBuf / bundleBuf and leave plenty of slack.
        //
        // JCOP 5 transient RAM budget is 4-8 KB so 1024+1024+1024 stays
        // within budget even with EcdhUnwrapper's ~280 B of statics.
        wireBuf    = JCSystem.makeTransientByteArray((short) 1024, JCSystem.CLEAR_ON_DESELECT);
        bundleBuf  = JCSystem.makeTransientByteArray((short) 1024, JCSystem.CLEAR_ON_DESELECT);
        dgiWorkBuf = JCSystem.makeTransientByteArray((short) 1024, JCSystem.CLEAR_ON_DESELECT);
        scratch    = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_DESELECT);

        // P-256 keypair — curve params installed once here; keypair regen
        // happens every GENERATE_KEYS call.  EcdhUnwrapper reads the
        // private half directly out of iccKeyPair (no scalar copy) so
        // there's no persistent scratch buffer for the private scalar.
        iccKeyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        initP256Params((ECPublicKey) iccKeyPair.getPublic());
        initP256Params((ECPrivateKey) iccKeyPair.getPrivate());

        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        attestation = new IssuerAttestation();

        state = Constants.STATE_IDLE;
        register();

        // CRITICAL — all transient-array allocations happen HERE, before
        // any TRANSFER_PARAMS call can start a transaction.  JCSystem.
        // makeTransientByteArray throws TransactionException.IN_PROGRESS
        // if called inside beginTransaction, and on JCOP 5 an uncaught
        // TransactionException during transient allocation mutes the
        // contactless interface — the card just stops responding
        // instead of returning a SW.  A previous build had lazy inits
        // inside DgiBuilderMchip.buildTrack2 and the result was a
        // silent-on-final-APDU crash that took hours to trace.  Do
        // NOT reintroduce lazy initialisation of transient arrays.
        EcdhUnwrapper.initOnce();
        DgiBuilderMchip.initOnce();
        attestation.initOnce();
    }

    // -----------------------------------------------------------------
    // P-256 curve parameter injection helpers.  ALG_EC_FP keys ship
    // uninitialised; the applet must set the field prime, a, b, base
    // point, order, and cofactor before genKeyPair() works.
    // -----------------------------------------------------------------

    static void initP256Params(ECPublicKey key) {
        key.setFieldFP(P256_P, (short) 0, (short) P256_P.length);
        key.setA(P256_A, (short) 0, (short) P256_A.length);
        key.setB(P256_B, (short) 0, (short) P256_B.length);
        key.setG(P256_G, (short) 0, (short) P256_G.length);
        key.setR(P256_N, (short) 0, (short) P256_N.length);
        key.setK((short) 1);
    }

    static void initP256Params(ECPrivateKey key) {
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

        // Accept CLA = 0x80 (Palisade proprietary, single APDU) OR
        // 0x90 (same, with ISO 7816-4 §5.1.1.1 command-chaining bit
        // 0x10 set).  Masking bit 4 out before comparison lets the
        // chained-short-APDU TRANSFER_PARAMS path work.  Anything else
        // (non-proprietary CLA, unknown bits in the low nibble) is
        // rejected with SW_CLA_NOT_SUPPORTED as before.
        byte cla = buf[ISO7816.OFFSET_CLA];
        if ((byte) (cla & (byte) 0xEF) != Constants.CLA_PA) {
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
            case Constants.INS_STORE_ATTESTATION:
                processStoreAttestation(apdu);
                break;
            case Constants.INS_GET_ATTESTATION_CHAIN:
                processGetAttestationChain(apdu);
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

        // GENERATE_KEYS marks the start of a fresh provisioning session,
        // so every accumulator from a prior (possibly crashed) attempt
        // has to be zeroed BEFORE we accept any chunks for this session.
        //
        // chainOff is an EEPROM field (not a transient) and so persists
        // across power cycles.  If a previous tap crashed partway
        // through TRANSFER_PARAMS (e.g. the silent-JCVM-mute that
        // happened when transient allocation failed inside a
        // transaction), the cleanup code at the tail of
        // processTransferParams never ran, and chainOff still holds
        // whatever cumulative offset that tap reached.  The next
        // session's chain #1 then passes the overflow guard but chain
        // #2 fails when (stale_chainOff + new_Lc) > wireBuf.length →
        // SW_DATA_INVALID on chain #2 out of nowhere.  Reset here.
        chainOff = 0;

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
        // we installed in the constructor.  processTransferParams() later
        // passes iccKeyPair.getPrivate() directly to EcdhUnwrapper —
        // NO getS/setS round-trip, which JCOP 5 can truncate on scalars
        // whose top byte is 0x00 (1/256 of keygens) and produce a
        // different curve point.
        iccKeyPair.genKeyPair();

        ECPublicKey pub = (ECPublicKey) iccKeyPair.getPublic();

        // Write the 65-byte uncompressed public key (0x04 || X(32) || Y(32))
        // into the APDU response buffer.
        short wLen = pub.getW(buf, (short) 0);

        // --- Patent C4: chip-side nonce binding -----------------------
        //
        // Generate a fresh 16-byte nonce and emit it right after the
        // public key in the GEN_KEYS response.  The same bytes get
        // APPENDED to our own sessionId[] buffer so the HKDF info for
        // the subsequent TRANSFER_PARAMS expand becomes
        //   info = incoming_sessionId || chip_nonce
        //
        // The server MUST concatenate the same chip_nonce into its
        // wrap-side info; if it forgets (or if an attacker replays a
        // recorded TRANSFER_PARAMS whose info was bound to a PRIOR
        // chip_nonce), HKDF produces different keys and the unwrap
        // HMAC tag fails closed.  No explicit comparison on-chip
        // needed — the crypto itself enforces freshness.
        //
        // Replay across sessions also fails for a second reason: every
        // GEN_KEYS regenerates the ephemeral ICC keypair, so the ECDH
        // shared secret is different → HKDF PRK is different → unwrap
        // fails.  C4 adds defence-in-depth against replay to the SAME
        // live session (e.g. attacker tamper-reply-relay) which the
        // ephemeral keypair alone doesn't cover.
        final short nonceOff = wLen;
        rng.generateData(sessionId, sessionIdLen, Constants.CHIP_NONCE_LEN);
        Util.arrayCopyNonAtomic(
            sessionId, sessionIdLen, buf, nonceOff, Constants.CHIP_NONCE_LEN
        );
        sessionIdLen = (short) (sessionIdLen + Constants.CHIP_NONCE_LEN);

        // --- Patent C16/C23: attestation signature trailer -----------
        //
        // If the issuer loaded attestation material at perso (three
        // STORE_ATTESTATION APDUs), sign (iccPubkey || cplc) with the
        // per-card attestation key and append the DER ECDSA signature
        // to the response.
        //
        // Response layout with attestation loaded:
        //   iccPubkey(65) || chipNonce(16) || attestSig(DER, ~71 B)
        //                                            total ~152 B
        //
        // Without attestation (prototype cards before C16/C23 rollout),
        // the trailer is just iccPubkey || chipNonce = 81 B as before.
        // rca's AttestationVerifier.extract tolerates both shapes in
        // permissive mode.  Strict mode requires the trailer.
        short respLen = (short) (wLen + Constants.CHIP_NONCE_LEN);
        if (attestation.isFullyLoaded()) {
            short sigLen = attestation.signAttestation(
                buf, (short) 0, wLen,  // sign (iccPubkey || cplc), internal concat
                buf, respLen
            );
            respLen = (short) (respLen + sigLen);
        }

        state = Constants.STATE_KEYGEN_COMPLETE;
        apdu.setOutgoingAndSend((short) 0, respLen);
    }

    // -----------------------------------------------------------------
    // TRANSFER_PARAMS — THE NEW STUFF
    // -----------------------------------------------------------------

    private void processTransferParams(APDU apdu) {
        if (state != Constants.STATE_KEYGEN_COMPLETE) {
            ISOException.throwIt(Constants.SW_WRONG_STATE);
        }

        // Receive the APDU body into wireBuf.  Two framings supported,
        // matching whatever the host middleware decides to emit:
        //
        //   (a) Single extended APDU up to wireBuf.length.  Use the
        //       setIncomingAndReceive + receiveBytes loop per JC 3.0.4
        //       spec §3.3 so bodies larger than the JCOP 5 APDU buffer
        //       (typically 261 B) still land fully in wireBuf.
        //
        //   (b) A chain of short APDUs where the non-final chunks have
        //       CLA bit 0x10 set (ISO 7816-4 §5.1.1.1 "command
        //       chaining").  Each chunk returns SW=9000, data is
        //       appended to wireBuf.  The final chunk has the chain bit
        //       cleared and triggers the unwrap/parse/commit path.
        //       This matches pa-v1's TRANSFER_SAD accumulator pattern
        //       and is the belt-and-suspenders fallback if the iOS
        //       CoreNFC stack or JC runtime rejects extended APDUs at
        //       the ISO-DEP layer (observed SW=6700 before chaining
        //       support landed).
        //
        // chainOff tracks the write cursor into wireBuf across calls.
        // 0 means "start of a fresh bundle".  The ACCUMULATOR IS RESET
        // TO 0 AT EVERY EXIT PATH — success, failure, or ISO exception
        // — so a retried provisioning attempt always starts clean.
        byte[] apduBuf = apdu.getBuffer();
        boolean isChained = (apduBuf[ISO7816.OFFSET_CLA] & (byte) 0x10) != 0;

        short bytesRead  = apdu.setIncomingAndReceive();
        short declaredLc = apdu.getIncomingLength();

        if ((short) (chainOff + declaredLc) > (short) wireBuf.length) {
            chainOff = 0;
            ISOException.throwIt(Constants.SW_DATA_INVALID);
        }

        // Copy first chunk from APDU buffer into wireBuf at chainOff.
        Util.arrayCopyNonAtomic(apduBuf, ISO7816.OFFSET_CDATA,
            wireBuf, chainOff, bytesRead);
        short received = bytesRead;

        // Extended APDU: read remaining chunks via receiveBytes().
        while (received < declaredLc) {
            short more = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
            if (more <= 0) {
                chainOff = 0;
                ISOException.throwIt(Constants.SW_DATA_INVALID);
            }
            Util.arrayCopyNonAtomic(apduBuf, ISO7816.OFFSET_CDATA,
                wireBuf, (short) (chainOff + received), more);
            received += more;
        }
        chainOff = (short) (chainOff + declaredLc);

        if (isChained) {
            // Intermediate short APDU — return 9000, keep the
            // accumulator for the next chunk.
            return;
        }

        // Final (or only) chunk — wireBuf[0..chainOff) is the full body.
        final short totalLen = chainOff;

        // 2. ECDH + HKDF + AES-CBC + HMAC unwrap into bundleBuf.
        //    Throws SW_PARAM_BUNDLE_GCM_FAILED on HMAC tag verify fail
        //    (or CBC unpad fail).  Reset chainOff + scrub wire on error
        //    so a retry with the correct keys/session gets a fresh slate.
        short bundleLen;
        try {
            // Pass the APDU buffer as the diagnostic scratch — unwrap
            // writes 32 B (chip_iv || wire_iv) there on IV mismatch.
            // Those bytes shipped back in the response let the server
            // diff its HKDF output byte-for-byte without another build.
            //
            // Safe to clobber offset 0 of the APDU buffer because
            // setIncomingAndReceive has already finished consuming the
            // incoming chunk, and the receiveBytes loop above has
            // already extracted everything we need out of it.
            bundleLen = EcdhUnwrapper.unwrap(
                (ECPrivateKey) iccKeyPair.getPrivate(),
                wireBuf, (short) 0, totalLen,
                sessionId, (short) 0, sessionIdLen,
                bundleBuf, (short) 0,
                apdu.getBuffer(), (short) 0
            );
        } catch (ISOException e) {
            if (e.getReason() == Constants.SW_DBG_IV_MISMATCH) {
                // Ship the diagnostic blob.  Throwing after
                // setOutgoingAndSend preserves the emitted data but
                // replaces the implicit 9000 SW with our mismatch SW
                // (per JC 3.0.4 §9.5.4).  If the APDU was case-3 (no
                // Le), the setOutgoingAndSend itself will throw; we
                // swallow that and let the original IV_MISMATCH SW
                // propagate — the server still learns it was an IV
                // mismatch, just without the 32-B detail.
                try {
                    apdu.setOutgoingAndSend((short) 0, EcdhUnwrapper.DBG_IV_DIAG_LEN);
                } catch (Exception inner) {
                    // Case-3 last chunk — no outgoing slot.  Discard.
                }
            }
            Util.arrayFillNonAtomic(wireBuf, (short) 0, chainOff, (byte) 0);
            chainOff = 0;
            throw e;
        }

        // 3. Validate the bundle has all required tags for MChip CVN 18.
        short validateSw = ParamBundleParser.validateMChipCvn18(
            bundleBuf, (short) 0, bundleLen, scratch
        );
        if (validateSw != (short) 0x9000) {
            // Scrub before throwing — bundle + wire accumulator.
            Util.arrayFillNonAtomic(bundleBuf, (short) 0, bundleLen, (byte) 0);
            Util.arrayFillNonAtomic(wireBuf, (short) 0, chainOff, (byte) 0);
            chainOff = 0;
            ISOException.throwIt(validateSw);
        }

        // 4. Build DGIs and write to NVM atomically.
        //
        // Each DGI builder's output goes to dgiWorkBuf (1024 B transient)
        // before we copy to the matching NVM slot.  Per-step SW codes
        // (0x6AF1..0x6AF6) let the server localise any future crash to
        // the exact DGI that blew up; once the prototype is stable we
        // collapse these back to SW_DATA_INVALID.
        //
        // Why a transaction wraps ALL four copies: a tear between DGI 1
        // and DGI 4 would leave the card in a half-provisioned state
        // that neither v3 nor the server could recover — atomic commit
        // keeps the state machine truthful about STATE_PARAMS_COMMITTED.
        short failStep = (short) 0;  // set before each builder call
        JCSystem.beginTransaction();
        try {
            failStep = Constants.SW_DBG_BUILD_0101_FAIL;
            dgi0101Len = DgiBuilderMchip.buildDgi0101(
                bundleBuf, (short) 0, bundleLen, scratch,
                dgiWorkBuf, (short) 0
            );
            Util.arrayCopy(dgiWorkBuf, (short) 0, dgi0101Nvm, (short) 0, dgi0101Len);

            failStep = Constants.SW_DBG_BUILD_0102_FAIL;
            dgi0102Len = DgiBuilderMchip.buildDgi0102(
                bundleBuf, (short) 0, bundleLen, scratch,
                dgiWorkBuf, (short) 0
            );
            Util.arrayCopy(dgiWorkBuf, (short) 0, dgi0102Nvm, (short) 0, dgi0102Len);

            failStep = Constants.SW_DBG_BUILD_8201_FAIL;
            dgi8201Len = DgiBuilderMchip.buildDgi8201(
                bundleBuf, (short) 0, bundleLen, scratch,
                dgiWorkBuf, (short) 0
            );
            Util.arrayCopy(dgiWorkBuf, (short) 0, dgi8201Nvm, (short) 0, dgi8201Len);

            failStep = Constants.SW_DBG_BUILD_9201_FAIL;
            dgi9201Len = DgiBuilderMchip.buildDgi9201(
                bundleBuf, (short) 0, bundleLen, scratch,
                dgiWorkBuf, (short) 0
            );
            Util.arrayCopy(dgiWorkBuf, (short) 0, dgi9201Nvm, (short) 0, dgi9201Len);

            // Also extract + persist per-card metadata (bankId, progId,
            // postProvisionUrl) that existed in the v2 TRANSFER_SAD
            // metadata-trailer format.  Same tags; just pull via
            // ParamBundleParser.findTag.
            failStep = Constants.SW_DBG_METADATA_FAIL;
            persistMetadata(bundleBuf, (short) 0, bundleLen);

            state = Constants.STATE_PARAMS_COMMITTED;

            failStep = Constants.SW_DBG_COMMIT_FAIL;
            JCSystem.commitTransaction();
        } catch (ISOException ioe) {
            // Known SW path — abort + rethrow with the original SW so
            // the server sees e.g. SW_PARAM_BUNDLE_INCOMPLETE rather
            // than a generic "build failed".
            if (JCSystem.getTransactionDepth() > 0) {
                JCSystem.abortTransaction();
            }
            Util.arrayFillNonAtomic(bundleBuf, (short) 0, bundleLen, (byte) 0);
            Util.arrayFillNonAtomic(wireBuf, (short) 0, chainOff, (byte) 0);
            chainOff = 0;
            ISOException.throwIt(ioe.getReason());
        } catch (Exception e) {
            // Unknown runtime (ArrayIndexOutOfBoundsException etc.) —
            // emit the per-step SW we latched in failStep so the
            // server can see which DGI builder tripped.
            if (JCSystem.getTransactionDepth() > 0) {
                JCSystem.abortTransaction();
            }
            Util.arrayFillNonAtomic(bundleBuf, (short) 0, bundleLen, (byte) 0);
            Util.arrayFillNonAtomic(wireBuf, (short) 0, chainOff, (byte) 0);
            chainOff = 0;
            ISOException.throwIt(failStep != (short) 0 ? failStep : Constants.SW_DATA_INVALID);
        }

        // 5. Scrub the plaintext bundle.  Transient clears on deselect
        //    anyway but an attacker who physically glitches the power
        //    between decrypt and deselect could read residual state;
        //    the explicit zero pass shortens the window.
        Util.arrayFillNonAtomic(bundleBuf, (short) 0, bundleLen, (byte) 0);

        // 5b. Patent C4: zero the chip-side nonce so a replayed
        //     TRANSFER_PARAMS against the same live session can't
        //     succeed.  State machine already prevents reuse (next
        //     TRANSFER_PARAMS on STATE_PARAMS_COMMITTED is rejected
        //     with SW_WRONG_STATE), but defence-in-depth: if state
        //     tracking ever regresses, the HKDF info for a second
        //     unwrap against the same sessionId+zeros nonce would
        //     differ from what the server wraps, so the crypto still
        //     fails closed.  Also shrinks sessionIdLen back to the
        //     incoming-server-id portion only — any future re-init
        //     starts clean.
        final short nonceStart = (short) (sessionIdLen - Constants.CHIP_NONCE_LEN);
        if (nonceStart >= 0) {
            Util.arrayFillNonAtomic(
                sessionId, nonceStart, Constants.CHIP_NONCE_LEN, (byte) 0
            );
            sessionIdLen = nonceStart;
        }

        // Clear the chain accumulator so the next provisioning attempt
        // (after WIPE + GENERATE_KEYS) starts from wireBuf[0].  Also
        // scrub wireBuf — it still holds the wrapped bundle which
        // carries the server ephemeral pubkey + ciphertext; clearing
        // gets rid of it ahead of the deselect auto-clear.
        Util.arrayFillNonAtomic(wireBuf, (short) 0, chainOff, (byte) 0);
        chainOff = 0;

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

    /**
     * FINAL_STATUS — confirms to rca that the four DGIs committed
     * successfully and emits a provenance hash that binds the card's
     * response to the bytes actually in NVM.
     *
     * Response layout (consumed by rca's handleFinalStatus in
     * services/rca/src/services/session-manager.ts):
     *
     *   [0]     status byte            0x01 = OK, anything else → PA_FAILED
     *   [1..33] provenance hash (32 B) SHA-256(DGI 0101 || 0102 || 8201 || 9201)
     *   [33]    fido cred len (1 B)    0x00 = no FIDO data (prototype)
     *
     * Total response = 34 B.  rca's parser only derefs index >65 when
     * length > 66, so the absent FIDO cred block is fine.
     *
     * The provenance hash uses the DGI payloads in a protocol-stable
     * order and byte-exact lengths.  If any post-commit POS tamper
     * flipped a bit in any DGI, this hash would differ from what
     * activation will later recompute server-side, catching the
     * tamper before the card transitions to PROVISIONED.  For the
     * current prototype activation trusts the hash opaquely
     * (`provenance: expect.any(String)` in tests), but the
     * server-side verifier lands as part of Phase 8.
     */
    private void processFinalStatus(APDU apdu) {
        if (state != Constants.STATE_PARAMS_COMMITTED) {
            ISOException.throwIt(Constants.SW_WRONG_STATE);
        }

        byte[] buf = apdu.getBuffer();
        short pos = (short) 0;

        // Status = success.
        buf[pos++] = (byte) 0x01;

        // Provenance = SHA-256 over the four committed DGI payloads in
        // fixed order.  update() absorbs the first three; doFinal()
        // consumes the fourth and writes the 32-byte digest directly
        // into the APDU response buffer at the provenance offset.
        //
        // We borrow EcdhUnwrapper.sha256 rather than allocating our own
        // MessageDigest — JCOP 5 caps the number of crypto objects
        // per applet, and having two SHA-256 instances makes INSTALL
        // fail 0x6F00 during the applet constructor.
        EcdhUnwrapper.sha256.reset();
        EcdhUnwrapper.sha256.update(dgi0101Nvm, (short) 0, dgi0101Len);
        EcdhUnwrapper.sha256.update(dgi0102Nvm, (short) 0, dgi0102Len);
        EcdhUnwrapper.sha256.update(dgi8201Nvm, (short) 0, dgi8201Len);
        EcdhUnwrapper.sha256.doFinal(dgi9201Nvm, (short) 0, dgi9201Len, buf, pos);
        pos = (short) (pos + 32);

        // FIDO cred block placeholder — 0-length until the FIDO2
        // attestation key flow is wired (deferred per PROTOTYPE_PLAN.md
        // §7).  Emitting a defined zero length keeps rca's parser on
        // the happy path and leaves room to grow without a protocol
        // break.
        buf[pos++] = (byte) 0x00;

        state = Constants.STATE_AWAITING_CONFIRM;
        apdu.setOutgoingAndSend((short) 0, pos);
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
    // STORE_ATTESTATION (INS=0xEC) — patent C16/C23 perso-time load
    // -----------------------------------------------------------------
    //
    // P1 selects the DGI sub-type; P2 reserved (must be 0x00).  Body
    // is the raw bytes for that DGI:
    //
    //   P1 0x01 (PRIV_KEY)  body = 32 B raw P-256 scalar
    //   P1 0x02 (CARD_CERT) body = card_pubkey(65) || cplc(42) || sig(DER)
    //                              (typically ~178 B, capped at 256)
    //   P1 0x03 (CPLC)      body = 42 B NXP CPLC
    //
    // Gated on STATE_IDLE only — a mid-session material swap would let
    // an attacker who got a STORE_ATTESTATION APDU through (SCP session
    // compromise during perso) overwrite the legit attestation with
    // their own, so post-keygen loads are rejected with SW_WRONG_STATE.
    // The issuer's perso equipment is expected to send all three
    // STORE_ATTESTATION APDUs before the first GENERATE_KEYS.

    private void processStoreAttestation(APDU apdu) {
        if (state != Constants.STATE_IDLE) {
            ISOException.throwIt(Constants.SW_WRONG_STATE);
        }

        byte[] buf = apdu.getBuffer();
        short bodyLen = apdu.setIncomingAndReceive();
        byte p1 = buf[ISO7816.OFFSET_P1];
        short bodyOff = ISO7816.OFFSET_CDATA;

        switch (p1) {
            case Constants.ATTEST_P1_PRIV_KEY:
                attestation.loadPrivKey(buf, bodyOff, bodyLen);
                break;
            case Constants.ATTEST_P1_CARD_CERT:
                attestation.loadCardCert(buf, bodyOff, bodyLen);
                break;
            case Constants.ATTEST_P1_CPLC:
                attestation.loadCplc(buf, bodyOff, bodyLen);
                break;
            default:
                ISOException.throwIt(Constants.SW_DBG_ATTEST_BAD_P1);
        }
        // No response body.  SW=9000 signals successful load.
    }

    // -----------------------------------------------------------------
    // GET_ATTESTATION_CHAIN (INS=0xEE) — return the loaded card cert
    // -----------------------------------------------------------------
    //
    // No P1/P2/body.  Response = card cert blob (~178 B) + SW=9000.
    // Short-APDU safe.  rca calls this AFTER GENERATE_KEYS so it can
    // walk the Root → Issuer → Card → iccPubkey chain before
    // committing to wrap the ParamBundle for this chip.
    //
    // No state gate — rca may call this any time after at least one
    // STORE_ATTESTATION(P1=CARD_CERT) has succeeded.  Pre-load state
    // returns SW_DBG_ATTEST_NOT_LOADED (6AF9) from
    // IssuerAttestation.getCardCert.

    private void processGetAttestationChain(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short certLen = attestation.getCardCert(buf, (short) 0);
        apdu.setOutgoingAndSend((short) 0, certLen);
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
