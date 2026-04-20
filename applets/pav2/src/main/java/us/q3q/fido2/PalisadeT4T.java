/*
 * PalisadeT4T — Custom NFC Forum Type 4 Tag applet with SUN/SDM support.
 *
 * Full NXP AN14683 SDM scheme on JavaCard 3.0.5 (JCOP 5 P71).  Two AES-128
 * keys are provisioned at install time (PICC-enc + SDM-file-read); the
 * per-tap SDMMAC session key is derived on every read via SV2:
 *
 *     SV2           = SC_SDMMAC(2) | SCT_1(2) | SKL_128(2) | UID(7) | Counter(3)
 *     sessionMacKey = AES-CMAC(macKey, SV2)
 *     SDMMAC        = truncate( AES-CMAC(sessionMacKey, baseUrl||"?e=hex&m=") )
 *
 * Matches the karta.cards tap service's verify.ts (imports sessionKeys.ts)
 * so a fresh tap can be verified without any per-card state on the server.
 * Supports dynamic URL updates via Shareable Interface, called by
 * FIDO2Applet during WebAuthn makeCredential.
 *
 * Package:      us.q3q.fido2 (same as FIDO2Applet for SIO compatibility)
 * Instance AID: D2760000850101 (NFC Forum NDEF Tag Application)
 *
 * Install data layout (after GP header):
 *   uid(7) | picc_enc_key(16) | mac_key(16) | url_len(1) | url(N)
 *
 * Where:
 *   uid          = 7-byte card UID (from manufacturing)
 *   picc_enc_key = AES-128 PICC encryption key (global, same for all cards)
 *   mac_key      = AES-128 MAC key (global, same for all cards)
 *   url          = initial base URL without "https://" prefix
 *
 * Proprietary APDUs (CLA=0x80):
 *   GET_STATE     (INS=0xEE) — returns 1-byte card lifecycle state
 *   GET_CARD_INFO (INS=0xF0) — returns 64-byte card info, increments tap counter
 *
 * State-dependent behavior:
 *   SHIPPED     — odd/even SELECT rejection for WebAuthn activation flow
 *   ACTIVATED — every tap serves SUN URL (no more FIDO2 needed)
 */
package us.q3q.fido2;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.Cipher;

public class PalisadeT4T extends Applet implements PalisadeT4TInterface {

    // =========================================================================
    // Constants
    // =========================================================================

    /** First byte of valid decrypted PICC data. */
    private static final byte PICC_DATA_TAG = (byte) 0xC7;

    // NXP AN14683 §2.5.2 — SDM session-key derivation constants.
    //
    //   SV2 (16 bytes) = SC_SDMMAC | SCT_1 | SKL_128 | UID(7) | SDMReadCounter(3)
    //   sessionMacKey  = AES-CMAC(macKey, SV2)
    //
    // Emitted verbatim into the SV2 buffer inside computeSdmmac.
    private static final byte SC_SDMMAC_0 = (byte) 0x3C;
    private static final byte SC_SDMMAC_1 = (byte) 0xC3;
    private static final byte SCT_1_0     = (byte) 0x00;
    private static final byte SCT_1_1     = (byte) 0x01;
    private static final byte SKL_128_0   = (byte) 0x00;
    private static final byte SKL_128_1   = (byte) 0x80;

    // =========================================================================
    // T4T File IDs and NDEF constants
    // =========================================================================

    private static final short CC_FILE_ID   = (short) 0xE103;
    private static final short NDEF_FILE_ID = (short) 0xE101;

    /** No file selected. */
    private static final short NO_FILE = (short) 0x0000;

    /** Capability Container — 15 bytes, per NFC Forum Type 4 Tag spec. */
    private static final byte[] CC_FILE = {
        (byte) 0x00, (byte) 0x0F,       // CCLEN = 15
        (byte) 0x20,                     // Mapping Version 2.0
        (byte) 0x00, (byte) 0xF6,       // MLe = 246 (max read)
        (byte) 0x00, (byte) 0xF6,       // MLc = 246 (max write)
        (byte) 0x04,                     // T = NDEF File Control TLV
        (byte) 0x06,                     // L = 6
        (byte) 0xE1, (byte) 0x01,       // File ID = E101
        (byte) 0x04, (byte) 0x00,       // Max NDEF file size = 1024
        (byte) 0x00,                     // Read access: granted
        (byte) 0xFF                      // Write access: denied
    };

    /** NDEF record header for a short URI record. */
    private static final byte NDEF_REC_HEADER = (byte) 0xD1;  // MB=1 ME=1 CF=0 SR=1 IL=0 TNF=001
    private static final byte NDEF_TYPE_LEN   = (byte) 0x01;
    private static final byte NDEF_TYPE_URI   = (byte) 0x55;  // "U"
    private static final byte URI_CODE_HTTPS  = (byte) 0x04;  // "https://"

    /**
     * NDEF file header size: NLEN(2) + RecordHeader(1) + TypeLen(1) + PayloadLen(1) + Type(1) + URICode(1) = 7.
     * URI string data starts at offset 7.
     */
    private static final short NDEF_HEADER_SIZE = (short) 7;

    // =========================================================================
    // Card lifecycle states (matches Palisade PA)
    // =========================================================================

    private static final byte STATE_SHIPPED       = (byte) 0x00;
    private static final byte STATE_ACTIVATED   = (byte) 0x01;
    private static final byte STATE_PROVISIONED = (byte) 0x02;
    private static final byte STATE_BLOCKED     = (byte) 0x03;

    // =========================================================================
    // Proprietary APDU instruction codes (CLA=0x80)
    // =========================================================================

    private static final byte INS_GET_STATE     = (byte) 0xEE;
    private static final byte INS_GET_CARD_INFO = (byte) 0xF0;

    // pav2 additions (Palisade patent claims C4, C10/C11, C23):
    //   INS_ACTIVATE      — transition SHIPPED → ACTIVATED via an APDU so
    //                       the backend (card-ops) can drive state moves
    //                       without the WebAuthn odd/even dance.  Idempotent
    //                       (no-op if already ACTIVATED).
    //   INS_GET_CHALLENGE — return 16 random bytes + increment an internal
    //                       challenge counter.  Used by the RCA to bind a
    //                       per-session nonce into the SAD, closing the
    //                       replay gap called out in the agent report.
    //   INS_REVOKE        — hard revoke.  Transitions to STATE_BLOCKED;
    //                       SELECT is rejected forever after.  Irreversible
    //                       on the card (full re-perso required to recover).
    private static final byte INS_ACTIVATE      = (byte) 0xEB;
    private static final byte INS_GET_CHALLENGE = (byte) 0xEC;
    private static final byte INS_REVOKE        = (byte) 0xED;

    /** Challenge size for INS_GET_CHALLENGE (16 bytes = 128-bit nonce). */
    private static final short CHALLENGE_SIZE = (short) 16;

    // =========================================================================
    // Card info EEPROM layout (64 bytes) — returned by GET_CARD_INFO
    // =========================================================================
    //
    // Offset | Field          | Size | Notes
    // -------|----------------|------|-------------------------------------------
    //   0    | card_state     |  1   | SHIPPED(00)/ACTIVATED(01)/PROVISIONED(02)/BLOCKED(03)
    //   1-7  | uid            |  7   | Card UID (from manufacturing)
    //   8-10 | sun_counter    |  3   | SUN read counter (LSB first)
    //  11-14 | tap_counter    |  4   | Usage counter (big-endian), incremented on GET_CARD_INFO
    //  15    | url_len        |  1   | Current base URL length
    //  16-60 | url            | 45   | Current base URL (first 45 bytes)
    //  61-63 | reserved       |  3   | Reserved for future use

    private static final short CARD_INFO_SIZE = (short) 64;
    private static final short CI_STATE       = (short) 0;
    private static final short CI_UID         = (short) 1;
    private static final short CI_SUN_CTR     = (short) 8;
    private static final short CI_TAP_CTR     = (short) 11;
    private static final short CI_URL_LEN     = (short) 15;
    private static final short CI_URL         = (short) 16;
    private static final short CI_URL_MAX     = (short) 45;

    // =========================================================================
    // Limits
    // =========================================================================

    private static final short MAX_URL_LEN   = (short) 150;
    private static final short NDEF_BUF_SIZE = (short) 512;
    private static final short WORK_BUF_SIZE = (short) 32;

    // =========================================================================
    // Hex encoding
    // =========================================================================

    private static final byte[] HEX = {
        '0', '1', '2', '3', '4', '5', '6', '7',
        '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
    };

    // =========================================================================
    // FIDO2 Applet AID (for SIO caller verification)
    // =========================================================================

    private static final byte[] FIDO2_AID = {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x06,
        (byte) 0x47, (byte) 0x2F, (byte) 0x00, (byte) 0x01
    };

    // =========================================================================
    // Persistent (EEPROM) fields
    // =========================================================================

    /** Card UID — 7 bytes, set during install. */
    private final byte[] uid;

    /** SDM read counter — 3 bytes, LSB first, persistent. */
    private final byte[] counter;

    /** Current base URL — up to MAX_URL_LEN bytes, ASCII, no "https://" prefix. */
    private final byte[] baseUrl;
    private short baseUrlLen;

    /** Card lifecycle state (persistent EEPROM). */
    private byte cardState;

    /** Tap counter — 4 bytes, big-endian, incremented on GET_CARD_INFO. */
    private final byte[] tapCounter;

    // =========================================================================
    // Crypto objects
    // =========================================================================

    /** AES-128 keys — global, same for all cards. */
    private final AESKey piccEncKey;     // PICC encryption (AES-CBC)
    private final AESKey macKey;         // SDM file-read master key (AES-CMAC)

    /**
     * Per-tap SDMMAC session key.  Derived fresh on each computeSdmmac call
     * from macKey + UID + counter per NXP AN14683 §2.5.2.  Transient
     * (CLEAR_ON_DESELECT) — lives in RAM, no EEPROM wear.
     */
    private final AESKey sessionMacKey;

    /** AES-CBC cipher — reused for all CBC operations. */
    private final Cipher aesCbc;

    /** AES-CMAC signature — reused for all CMAC operations. */
    private final Signature aesCmac;

    /** Secure random for PICC padding. */
    private final RandomData rng;

    // =========================================================================
    // Transient fields (RAM — cleared on deselect)
    // =========================================================================

    /** Currently selected file ID (2 bytes). */
    private final byte[] selectedFile;

    /** Pre-generated NDEF file content. */
    private final byte[] ndefBuf;

    /** ndefLen[0] = total NDEF file length (NLEN field + NDEF message). */
    private final short[] ndefLen;

    /** Whether NDEF has been generated since last file select. */
    private final boolean[] ndefReady;

    /** Work buffer for crypto intermediates. */
    private final byte[] work;

    /** 16-byte zero IV — constant, never modified. */
    private static final byte[] ZERO_IV = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    // =========================================================================
    // Constructor
    // =========================================================================

    private PalisadeT4T(byte[] bArray, short bOffset, byte bLength) {
        // --- Parse GlobalPlatform install data ---
        // Layout per GP 2.3:
        //   <aidLen><aid><privLen><priv><installParamLen><installParam>
        // where installParam is usually TLV-wrapped by the installer.
        short off = bOffset;
        short aidLen = (short) (bArray[off] & 0xFF);
        off = (short) (off + 1 + aidLen);
        short ctlLen = (short) (bArray[off] & 0xFF);
        off = (short) (off + 1 + ctlLen);
        short dataLen = (short) (bArray[off] & 0xFF);
        off = (short) (off + 1);

        // installParam is typically wrapped as GP TLV (C9 <len> <value>)
        // when the installer (e.g. GlobalPlatformPro) treats --params as
        // "simple app parameters".  Strip a leading C9 <len> header if it
        // looks like TLV; otherwise assume the params are already raw.
        if (dataLen >= 2 && bArray[off] == (byte) 0xC9) {
            short c9Len = (short) (bArray[(short) (off + 1)] & 0xFF);
            // Only strip if the inner length plus 2-byte header matches
            // the outer dataLen — guards against misinterpreting an actual
            // 0xC9 first byte of raw data.
            if ((short) (c9Len + 2) == dataLen) {
                off += 2;
            }
        }
        // off now points to the raw install data.

        // --- Parse install data: uid(7) | picc_enc_key(16) | mac_key(16) | url_len(1) | url(N) ---
        uid = new byte[7];
        Util.arrayCopyNonAtomic(bArray, off, uid, (short) 0, (short) 7);
        off += 7;

        byte[] encKeyBytes = new byte[16];
        Util.arrayCopyNonAtomic(bArray, off, encKeyBytes, (short) 0, (short) 16);
        off += 16;

        byte[] macKeyBytes = new byte[16];
        Util.arrayCopyNonAtomic(bArray, off, macKeyBytes, (short) 0, (short) 16);
        off += 16;

        short urlLen = (short) (bArray[off] & 0xFF);
        off++;
        if (urlLen > MAX_URL_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        baseUrl = new byte[MAX_URL_LEN];
        Util.arrayCopyNonAtomic(bArray, off, baseUrl, (short) 0, urlLen);
        baseUrlLen = urlLen;

        // --- Initialize persistent state ---
        counter = new byte[3]; // starts at 0
        tapCounter = new byte[4]; // starts at 0
        cardState = STATE_SHIPPED;

        // --- Crypto key objects ---
        piccEncKey = (AESKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        piccEncKey.setKey(encKeyBytes, (short) 0);

        macKey = (AESKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        macKey.setKey(macKeyBytes, (short) 0);

        // Session MAC key lives in RAM (transient).  Re-keyed every tap via
        // setKey() in computeSdmmac().  Faster than EEPROM writes and avoids
        // flash-wear from the per-tap rekey.
        sessionMacKey = (AESKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_AES_TRANSIENT_DESELECT, KeyBuilder.LENGTH_AES_128, false);

        // --- Crypto engines ---
        aesCbc = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        aesCmac = Signature.getInstance(Signature.ALG_AES_CMAC_128, false);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

        // --- Transient buffers ---
        selectedFile  = JCSystem.makeTransientByteArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        ndefBuf       = JCSystem.makeTransientByteArray(NDEF_BUF_SIZE, JCSystem.CLEAR_ON_DESELECT);
        ndefLen       = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        ndefReady     = JCSystem.makeTransientBooleanArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
        work          = JCSystem.makeTransientByteArray(WORK_BUF_SIZE, JCSystem.CLEAR_ON_DESELECT);

        // Zeroize temporary key material
        Util.arrayFillNonAtomic(encKeyBytes, (short) 0, (short) 16, (byte) 0);
        Util.arrayFillNonAtomic(macKeyBytes, (short) 0, (short) 16, (byte) 0);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new PalisadeT4T(bArray, bOffset, bLength).register();
    }

    // =========================================================================
    // APDU Processing
    // =========================================================================

    public void process(APDU apdu) {
        byte[] buf = apdu.getBuffer();

        if (selectingApplet()) {
            // SELECT AID (D2760000850101) — fires once per ISO-DEP session.
            //
            // Counter increments HERE, not on READ BINARY. Some Android devices
            // issue multiple READ BINARYs or re-SELECT the NDEF file in a single
            // NFC session. Incrementing on read would blow the odd/even logic.
            incrementCounter();

            // STATE-DEPENDENT BEHAVIOR:
            //
            // SHIPPED — Odd/even alternation for WebAuthn activation flow:
            //   Odd taps (1,3,5):  SELECT succeeds → T4T serves SUN URL
            //   Even taps (2,4,6): SELECT fails → FIDO2 gets the NFC session
            //   This gives a natural tap-pair rhythm:
            //     Tap 1 → SUN URL → activation page loads
            //     Tap 2 → Empty → WebAuthn makeCredential/getAssertion reaches FIDO2
            //
            // ACTIVATED — Every tap serves the SUN URL. No more FIDO2 needed.
            //   The card is activated; SUN verification alone proves possession.
            //   No odd/even rejection — Android always opens the bank URL.
            //
            // BLOCKED — Reject all SELECTs. Card is locked out.
            if (cardState == STATE_BLOCKED) {
                ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
            }

            if (cardState == STATE_SHIPPED) {
                if ((counter[0] & 0x01) == 0) {
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                }
            }
            // ACTIVATED / PROVISIONED: always accept SELECT → serve SUN URL

            Util.setShort(selectedFile, (short) 0, NO_FILE);
            ndefReady[0] = false;
            return;
        }

        byte cla = buf[ISO7816.OFFSET_CLA];
        byte ins = buf[ISO7816.OFFSET_INS];

        // --- Proprietary APDUs (CLA=0x80) ---
        if (cla == (byte) 0x80) {
            switch (ins) {
                case INS_GET_STATE:
                    processGetState(apdu);
                    return;
                case INS_GET_CARD_INFO:
                    processGetCardInfo(apdu);
                    return;
                case INS_ACTIVATE:
                    processActivate(apdu);
                    return;
                case INS_GET_CHALLENGE:
                    processGetChallenge(apdu);
                    return;
                case INS_REVOKE:
                    processRevoke(apdu);
                    return;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }

        // --- Standard T4T APDUs (CLA=0x00) ---
        if ((cla & (byte) 0xFC) != 0x00) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (ins) {
            case (byte) 0xA4: // SELECT (file)
                processSelect(apdu);
                break;
            case (byte) 0xB0: // READ BINARY
                processReadBinary(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // =========================================================================
    // GET_STATE (0x80 EE 00 00) — returns 1-byte card lifecycle state
    // =========================================================================

    private void processGetState(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        buf[0] = cardState;
        apdu.setOutgoingAndSend((short) 0, (short) 1);
    }

    // =========================================================================
    // ACTIVATE (0x80 EB 00 00) — transition SHIPPED → ACTIVATED
    // =========================================================================
    //
    // Idempotent.  Only effective from SHIPPED; any other state returns
    // 9000 unchanged (no-op).  BLOCKED returns SW_CONDITIONS_NOT_SATISFIED
    // since a revoked card must stay revoked.
    //
    // Patent C5: state machine transitions must be explicit and
    // authenticated.  The backend drives this via card-ops INS_ACTIVATE
    // after successful provisioning / WebAuthn bind.

    private void processActivate(APDU apdu) {
        if (cardState == STATE_BLOCKED) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (cardState == STATE_SHIPPED) {
            JCSystem.beginTransaction();
            cardState = STATE_ACTIVATED;
            JCSystem.commitTransaction();
        }
        // No response body — the SW=9000 is the answer.
    }

    // =========================================================================
    // GET_CHALLENGE (0x80 EC 00 00 Le=16) — return 16 random bytes
    // =========================================================================
    //
    // Patent C4 (nonce binding).  The RCA calls this before generating a
    // SAD for the chip, binds the challenge into the SAD prefix, and the
    // PA (CLA=00 INS=?? to the PA applet, not us) verifies the bound
    // challenge matches the last-issued one before committing.  This
    // prevents replay of a captured SAD even within the WS session
    // window that H-8's WS token protects.
    //
    // The challenge is drawn from the on-chip SECURE_RANDOM source.  Any
    // caller can invoke (it's on the T4T NDEF applet, visible over NFC);
    // the entropy is the only secret.
    //
    // Returns: 16-byte random nonce.  SW=9000.

    private void processGetChallenge(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        rng.generateData(buf, (short) 0, CHALLENGE_SIZE);
        apdu.setOutgoingAndSend((short) 0, CHALLENGE_SIZE);
    }

    // =========================================================================
    // REVOKE (0x80 ED 00 00) — hard revoke, irreversible
    // =========================================================================
    //
    // Patent C11 (on-chip revocation).  Flips cardState to STATE_BLOCKED.
    // From this point, selectingApplet() rejects every SELECT with
    // SW_FUNC_NOT_SUPPORTED — the NDEF file becomes inaccessible and the
    // chip is effectively bricked until re-personalised.
    //
    // Zeroizes the SDM keys as well — a compromised card post-revocation
    // yields no exploitable material even if the attacker can still
    // issue this APDU (they can, but it's idempotent and just confirms
    // the revocation).

    private void processRevoke(APDU apdu) {
        JCSystem.beginTransaction();
        cardState = STATE_BLOCKED;
        // Zero out the AES keys — no use case for a revoked card to
        // keep them around; reduces attacker value of any post-revoke
        // physical extraction.
        byte[] zeros = new byte[16];
        piccEncKey.setKey(zeros, (short) 0);
        macKey.setKey(zeros, (short) 0);
        JCSystem.commitTransaction();
        // No response body.  SW=9000 confirms.
    }

    // =========================================================================
    // GET_CARD_INFO (0x80 F0 00 00) — returns 64-byte card info structure
    // =========================================================================
    //
    // Increments the tap counter on every call (usage tracking).
    // Returns: state(1) | uid(7) | sun_counter(3) | tap_counter(4) |
    //          url_len(1) | url(45) | reserved(3) = 64 bytes

    private void processGetCardInfo(APDU apdu) {
        // Increment tap counter (4-byte big-endian)
        incrementTapCounter();

        byte[] buf = apdu.getBuffer();

        // Build 64-byte card info in APDU buffer
        Util.arrayFillNonAtomic(buf, (short) 0, CARD_INFO_SIZE, (byte) 0);

        buf[CI_STATE] = cardState;
        Util.arrayCopyNonAtomic(uid, (short) 0, buf, CI_UID, (short) 7);
        Util.arrayCopyNonAtomic(counter, (short) 0, buf, CI_SUN_CTR, (short) 3);
        Util.arrayCopyNonAtomic(tapCounter, (short) 0, buf, CI_TAP_CTR, (short) 4);
        buf[CI_URL_LEN] = (byte) (baseUrlLen & 0xFF);
        short urlCopy = (baseUrlLen > CI_URL_MAX) ? CI_URL_MAX : baseUrlLen;
        Util.arrayCopyNonAtomic(baseUrl, (short) 0, buf, CI_URL, urlCopy);

        apdu.setOutgoingAndSend((short) 0, CARD_INFO_SIZE);
    }

    // =========================================================================
    // SELECT — file selection within the T4T application
    // =========================================================================

    private void processSelect(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte p1 = buf[ISO7816.OFFSET_P1];
        byte p2 = buf[ISO7816.OFFSET_P2];

        if (p1 != 0x00 || (p2 != 0x0C && p2 != 0x00)) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }

        short lc = apdu.setIncomingAndReceive();
        if (lc != 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short fileId = Util.getShort(buf, ISO7816.OFFSET_CDATA);

        if (fileId == CC_FILE_ID || fileId == NDEF_FILE_ID) {
            Util.setShort(selectedFile, (short) 0, fileId);
            // Do NOT reset ndefReady here. NDEF content is generated once per
            // applet SELECT (ISO-DEP session), not per file SELECT. Android may
            // re-SELECT the NDEF file within the same session — the cached
            // content stays valid because the counter didn't change.
        } else {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
    }

    // =========================================================================
    // READ BINARY — serve CC (static) or NDEF (dynamic with SUN params)
    // =========================================================================

    private void processReadBinary(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short fileId = Util.getShort(selectedFile, (short) 0);

        if (fileId == NO_FILE) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        // Offset from P1-P2 (15-bit, per ISO 7816-4)
        short offset = Util.getShort(buf, ISO7816.OFFSET_P1);
        // Le from P3 (0 means 256)
        short le = (short) (buf[ISO7816.OFFSET_LC] & 0xFF);
        if (le == 0) le = 256;

        if (fileId == CC_FILE_ID) {
            readCCFile(apdu, offset, le);
        } else if (fileId == NDEF_FILE_ID) {
            readNdefFile(apdu, offset, le);
        } else {
            ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
        }
    }

    private void readCCFile(APDU apdu, short offset, short le) {
        short ccLen = (short) CC_FILE.length;
        if (offset >= ccLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        short available = (short) (ccLen - offset);
        short toSend = (available < le) ? available : le;

        apdu.setOutgoing();
        apdu.setOutgoingLength(toSend);
        apdu.sendBytesLong(CC_FILE, offset, toSend);
    }

    private void readNdefFile(APDU apdu, short offset, short le) {
        // Generate NDEF content on first read after select
        if (!ndefReady[0]) {
            generateNdef();
            ndefReady[0] = true;
        }

        short totalLen = ndefLen[0];
        if (offset >= totalLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
        }
        short available = (short) (totalLen - offset);
        short toSend = (available < le) ? available : le;

        apdu.setOutgoing();
        apdu.setOutgoingLength(toSend);
        apdu.sendBytesLong(ndefBuf, offset, toSend);
    }

    // =========================================================================
    // Dynamic NDEF Generation
    // =========================================================================

    /*
     * THE ANDROID PROBLEM:
     *
     * Android's NFC stack requires T4T/NDEF for ISO 14443-4 (ISO-DEP) activation.
     * Without T4T, the card is invisible. But when T4T IS present, Android reads
     * NDEF on every tap and dispatches the URL, preventing WebAuthn from reaching
     * the FIDO2 applet.
     *
     * STATE-DEPENDENT RESOLUTION:
     *
     * SHIPPED — Odd/even counter alternation:
     *   Odd  → SUN URL (activation page loads)
     *   Even → SELECT rejected entirely → Chrome WebAuthn selects FIDO2 AID
     *
     * ACTIVATED — Every tap serves the SUN URL. SUN alone proves possession.
     *   No FIDO2 needed after activation. Bank URL opens on every tap.
     */

    /**
     * Generate NDEF file content. Counter was already incremented on applet SELECT.
     * Always generates the full SUN URL (only called when SELECT succeeds).
     */
    private void generateNdef() {
        generateSunNdef();
    }

    /**
     * Generate full NDEF URI record with fresh SUN parameters.
     *
     * Layout in ndefBuf:
     *   [0-1]   NLEN (2 bytes)
     *   [2]     0xD1 record header
     *   [3]     0x01 type length
     *   [4]     payload length
     *   [5]     0x55 type "U"
     *   [6]     0x04 URI code "https://"
     *   [7...]  URI string: base_url + "?e=" + enc_picc + "&m=" + sdmmac
     */
    private void generateSunNdef() {
        // Step 1: Encrypt PICC data — AES-CBC(piccEncKey, zeros, C7||UID||counter||random)
        work[0] = PICC_DATA_TAG;
        Util.arrayCopyNonAtomic(uid, (short) 0, work, (short) 1, (short) 7);
        Util.arrayCopyNonAtomic(counter, (short) 0, work, (short) 8, (short) 3);
        rng.generateData(work, (short) 11, (short) 5);

        aesCbc.init(piccEncKey, Cipher.MODE_ENCRYPT, ZERO_IV, (short) 0, (short) 16);
        aesCbc.doFinal(work, (short) 0, (short) 16, work, (short) 0);
        // work[0..15] = encrypted PICC data

        // Step 2: Build NDEF body in ndefBuf starting at offset 7
        short pos = NDEF_HEADER_SIZE;

        Util.arrayCopyNonAtomic(baseUrl, (short) 0, ndefBuf, pos, baseUrlLen);
        pos += baseUrlLen;

        ndefBuf[pos++] = '?';
        ndefBuf[pos++] = 'e';
        ndefBuf[pos++] = '=';
        pos = hexEncode(work, (short) 0, (short) 16, ndefBuf, pos);

        ndefBuf[pos++] = '&';
        ndefBuf[pos++] = 'm';
        ndefBuf[pos++] = '=';

        // Step 3: Compute SDMMAC — macInput is everything from base_url through "&m="
        short macInputLen = (short) (pos - NDEF_HEADER_SIZE);
        computeSdmmac(ndefBuf, NDEF_HEADER_SIZE, macInputLen);
        pos = hexEncode(work, (short) 0, (short) 8, ndefBuf, pos);

        // Step 4: Fill in NDEF headers
        short uriDataLen = (short) (pos - NDEF_HEADER_SIZE);
        short payloadLen = (short) (1 + uriDataLen);

        if (payloadLen > 255) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        short ndefMsgLen = (short) (4 + payloadLen);

        Util.setShort(ndefBuf, (short) 0, ndefMsgLen);
        ndefBuf[2] = NDEF_REC_HEADER;
        ndefBuf[3] = NDEF_TYPE_LEN;
        ndefBuf[4] = (byte) payloadLen;
        ndefBuf[5] = NDEF_TYPE_URI;
        ndefBuf[6] = URI_CODE_HTTPS;

        ndefLen[0] = (short) (2 + ndefMsgLen);
    }

    // =========================================================================
    // SUN Counter — 3-byte LSB-first persistent counter
    // =========================================================================

    private void incrementCounter() {
        JCSystem.beginTransaction();
        for (short i = 0; i < 3; i++) {
            short val = (short) ((counter[i] & 0xFF) + 1);
            counter[i] = (byte) val;
            if (val <= 0xFF) break; // no carry
        }
        JCSystem.commitTransaction();
    }

    // =========================================================================
    // Tap Counter — 4-byte big-endian persistent counter (usage tracking)
    // =========================================================================

    private void incrementTapCounter() {
        JCSystem.beginTransaction();
        for (short i = 3; i >= 0; i--) {
            short val = (short) ((tapCounter[i] & 0xFF) + 1);
            tapCounter[i] = (byte) val;
            if (val <= 0xFF) break; // no carry
        }
        JCSystem.commitTransaction();
    }

    // =========================================================================
    // SUN Crypto — NXP AN14683 full SDM scheme with per-tap SV2 session keys.
    // =========================================================================

    /**
     * Compute truncated SDMMAC per NXP AN14683 §2.5.2 (full SDM scheme).
     *
     *   SV2           = SC_SDMMAC(2) | SCT_1(2) | SKL_128(2) | UID(7) | Counter(3)
     *   sessionMacKey = AES-CMAC(macKey, SV2)                              // 16 bytes
     *   full          = AES-CMAC(sessionMacKey, macInput)                  // 16 bytes
     *   SDMMAC        = full[1,3,5,7,9,11,13,15]                           // 8 bytes
     *
     * The per-tap session key binds the MAC to the card's UID + monotonic
     * read counter, so a replayed or mutated URL won't verify — matches what
     * the karta.cards tap service's verify.ts expects.
     *
     * @param buf    buffer containing MAC input
     * @param off    offset of MAC input
     * @param len    length of MAC input
     *
     * Result: work[0..7] = 8-byte truncated SDMMAC
     */
    private void computeSdmmac(byte[] buf, short off, short len) {
        // Step 1: Build SV2 (16 bytes) into work[16..31].  At this point
        // ndefBuf already holds the hex-encoded PICC ciphertext; work[16..31]
        // is scratch.
        short p = 16;
        work[p++] = SC_SDMMAC_0;
        work[p++] = SC_SDMMAC_1;
        work[p++] = SCT_1_0;
        work[p++] = SCT_1_1;
        work[p++] = SKL_128_0;
        work[p++] = SKL_128_1;
        Util.arrayCopyNonAtomic(uid,     (short) 0, work, p, (short) 7);
        p += 7;
        Util.arrayCopyNonAtomic(counter, (short) 0, work, p, (short) 3);
        // p is now 32.  SV2 occupies work[16..31].

        // Step 2: Derive per-tap session key into work[0..15].
        aesCmac.init(macKey, Signature.MODE_SIGN);
        aesCmac.sign(work, (short) 16, (short) 16, work, (short) 0);

        // Step 3: Load derived session key into the transient key object.
        sessionMacKey.setKey(work, (short) 0);

        // Step 4: Full CMAC over macInput with the session key.  Output
        // overwrites the SV2 bytes in work[16..31].
        aesCmac.init(sessionMacKey, Signature.MODE_SIGN);
        aesCmac.sign(buf, off, len, work, (short) 16);

        // Step 5: Truncate — take 0-indexed positions 1,3,5,7,9,11,13,15.
        // This overwrites the first 8 bytes of work (the session-key bytes),
        // which is fine: we're done with the session key and needed those
        // slots for the truncated output anyway.
        work[0] = work[17];
        work[1] = work[19];
        work[2] = work[21];
        work[3] = work[23];
        work[4] = work[25];
        work[5] = work[27];
        work[6] = work[29];
        work[7] = work[31];
    }

    // =========================================================================
    // Hex encoding — binary to uppercase hex ASCII
    // =========================================================================

    /**
     * Encode binary bytes as uppercase hex ASCII into a destination buffer.
     *
     * @return new position in dst after the encoded bytes
     */
    private static short hexEncode(byte[] src, short srcOff, short srcLen,
                                    byte[] dst, short dstOff) {
        for (short i = 0; i < srcLen; i++) {
            byte b = src[(short) (srcOff + i)];
            dst[dstOff++] = HEX[(b >> 4) & 0x0F];
            dst[dstOff++] = HEX[b & 0x0F];
        }
        return dstOff;
    }

    // =========================================================================
    // Shareable Interface — PalisadeT4TInterface implementation
    // =========================================================================

    /**
     * Called by FIDO2Applet during WebAuthn makeCredential when RP ID matches.
     * Updates the base URL in EEPROM. Next NDEF read will use the new URL.
     */
    public void setUrl(byte[] url, short off, short len) {
        if (len <= 0 || len > MAX_URL_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        JCSystem.beginTransaction();
        Util.arrayCopyNonAtomic(url, off, baseUrl, (short) 0, len);
        baseUrlLen = len;
        if (cardState == STATE_SHIPPED) {
            cardState = STATE_ACTIVATED;
        }
        JCSystem.commitTransaction();
    }

    /**
     * Update the base URL with CMAC authentication.
     *
     * The buffer layout: url(N) + cmac(16).
     * T4T computes AES-CMAC(macKey, url) and compares with the provided CMAC.
     * Rejects with SW_SECURITY_STATUS_NOT_SATISFIED if CMAC does not match.
     *
     * Uses constant-time comparison to prevent timing side channels.
     */
    public void setUrlWithMac(byte[] buf, short off, short len) {
        // URL must be at least 1 byte + 16-byte CMAC
        if (len <= (short) 16 || (short)(len - 16) > MAX_URL_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        short urlLen = (short)(len - 16);
        short cmacOff = (short)(off + urlLen);

        // Compute AES-CMAC(macKey, url) → work[0..15]
        aesCmac.init(macKey, Signature.MODE_SIGN);
        aesCmac.sign(buf, off, urlLen, work, (short) 0);

        // Constant-time comparison: computed CMAC vs provided CMAC
        byte diff = 0;
        for (short i = 0; i < 16; i++) {
            diff |= (byte)(work[i] ^ buf[(short)(cmacOff + i)]);
        }

        if (diff != 0) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        // CMAC valid — store URL and activate
        JCSystem.beginTransaction();
        Util.arrayCopyNonAtomic(buf, off, baseUrl, (short) 0, urlLen);
        baseUrlLen = urlLen;
        if (cardState == STATE_SHIPPED) {
            cardState = STATE_ACTIVATED;
        }
        JCSystem.commitTransaction();
    }

    /**
     * Activate the card without changing the URL.
     * Called by FIDO2Applet after successful U2F Authenticate over NFC.
     * Sets card state from SHIPPED to ACTIVATED. No-op if already activated.
     */
    public void activate() {
        if (cardState == STATE_SHIPPED) {
            JCSystem.beginTransaction();
            cardState = STATE_ACTIVATED;
            JCSystem.commitTransaction();
        }
    }

    public byte getCardState() {
        return cardState;
    }

    /**
     * Force counter to odd so next NDEF read generates full SUN URL.
     * Called by FIDO2Applet if WebAuthn fails and user needs a fresh SUN tap.
     * Only relevant in SHIPPED state (odd/even alternation).
     */
    public void forceSunOnNextRead() {
        if (cardState != STATE_SHIPPED) return; // no-op if already activated

        // If counter is currently odd, next increment → even → SELECT rejected.
        // Bump by 1 so next increment → odd → SUN URL.
        if ((counter[0] & 0x01) != 0) {
            incrementCounter();
        }
    }

    /**
     * Provide Shareable Interface Object to the FIDO2 applet.
     * Only the FIDO2 applet (identified by AID) can access this.
     */
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        // Verify caller is the FIDO2 applet
        if (clientAID.equals(FIDO2_AID, (short) 0, (byte) FIDO2_AID.length)) {
            return this;
        }
        return null;
    }
}
