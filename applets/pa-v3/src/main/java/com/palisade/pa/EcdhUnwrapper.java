package com.palisade.pa;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacardx.crypto.Cipher;

/**
 * ECDH + HKDF-SHA256 + AES-128-CBC + HMAC-SHA256 unwrapper
 * (encrypt-then-MAC).
 *
 * Mirror of packages/emv-ecdh/src/index.ts's `unwrapParamBundle`.
 * Any divergence from the TS reference breaks interop.
 *
 * Why CBC+HMAC instead of GCM?  JavaCard 3.0.4 Classic SDK has
 * `Cipher.ALG_AES_BLOCK_128_CBC_NOPAD` but no `AEADCipher` / GCM
 * (GCM was added in JC 3.1).  AES-CBC + HMAC-SHA256 in encrypt-then-
 * MAC order is security-equivalent when implemented correctly —
 * the tag is computed over `iv || ct` and verified BEFORE decryption.
 *
 * WIRE FORMAT (what's in the TRANSFER_PARAMS APDU body):
 *
 *   server_ephemeral_pub_uncompressed (65 B)    (0x04 || X || Y)
 *   || iv          (16 B)  // matches HKDF-derived IV
 *   || ciphertext  (variable, PKCS#7-padded to 16-byte multiple)
 *   || tag         (16 B)  // leftmost 16 bytes of HMAC-SHA256
 *
 * PROTOCOL:
 *
 *   1. shared = ECDH(chip_priv, server_eph_pub).X  // 32 B raw
 *   2. prk   = HMAC-SHA256(HKDF_SALT, shared)
 *   3. okm   = HMAC-SHA256(prk, sessionId || 0x01)         → 32 B T(1)
 *              HMAC-SHA256(prk, T(1) || sessionId || 0x02) → 32 B T(2)
 *              Take first 64 B = aesKey(16) || iv(16) || hmacKey(32)
 *   4. Verify iv matches wire iv (defence-in-depth — tamper detection
 *      before we even start crypto work)
 *   5. expectedTag = HMAC-SHA256(hmacKey, iv || ct)[:16]
 *      If constant-time-equal(expectedTag, wireTag) == 0 → reject
 *   6. plaintext = AES-CBC-decrypt(aesKey, iv, ct) with PKCS#7 unpad
 *      (via Cipher.ALG_AES_CBC_PKCS5 — PKCS5 and PKCS7 are
 *      compatible for 16-byte-block ciphers)
 *
 * RAM USAGE (static allocations — no per-call new/allocate):
 *
 *   chipPrivKey:    EC private key (on-card, KeyBuilder)
 *   keyAgreement:   ECDH_PLAIN instance, reused
 *   sha256:         MessageDigest instance, reused
 *   aesCipher:      AES-128-CBC-PKCS5 instance, reused
 *   aesKey:         AESKey (16 B) handle, reset per use
 *   sharedBuf:      32-byte scratch for shared secret
 *   prkBuf:         32-byte scratch for HKDF PRK
 *   okmBuf:         64-byte scratch for HKDF OKM (aes || iv || hmac)
 *   expTagBuf:      32-byte scratch for computed HMAC-SHA256 tag
 *   hmacKey, hmacScratch: 64-byte each, inline HMAC-SHA256 pads
 *
 * Total static RAM: ~280 B plus KeyAgreement/Cipher/MessageDigest
 * instances.  Well within JCOP 5 budgets.
 */
public final class EcdhUnwrapper {

    private static ECPrivateKey chipPrivKey;
    private static KeyAgreement keyAgreement;
    private static MessageDigest sha256;
    private static Cipher aesCipher;
    private static AESKey aesKey;

    private static byte[] sharedBuf;
    private static byte[] prkBuf;
    private static byte[] okmBuf;       // 64 B — 16 aes + 16 iv + 32 hmac
    private static byte[] expTagBuf;    // 32 B — full SHA-256 output
    private static byte[] hmacMsgBuf;   // up to iv(16) + max ct — see note

    /** HMAC block-sized key buffer, reused for inline HMAC computations. */
    private static byte[] hmacKey;
    /** Scratch used for HMAC inner/outer pad XOR + final hash input. */
    private static byte[] hmacScratch;

    /**
     * One-time initialisation.  Call from the applet's constructor or
     * before the first unwrap.  All objects are transient (RAM-resident,
     * cleared on power-off) EXCEPT chipPrivKey which lives in EEPROM.
     */
    public static void initOnce() {
        if (keyAgreement != null) return;

        // Most JCOP 5 builds expose ALG_EC_SVDP_DH_PLAIN (returns X only,
        // 32 B) rather than ALG_EC_SVDP_DH_PLAIN_XY (returns X || Y, 64 B).
        // Our ts mirror uses X only (Node's ECDH.computeSecret returns the
        // X coord by default).
        keyAgreement = KeyAgreement.getInstance(
            KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false
        );
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        // AES-128-CBC with PKCS#5/PKCS#7 padding.  JC 3.0.4 exposes this
        // constant directly; chip handles pad/unpad transparently.
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_CBC_PKCS5, false);
        aesKey = (AESKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
            KeyBuilder.LENGTH_AES_128,
            false
        );

        // ECPrivateKey in EEPROM — persists across power cycles.  Populated
        // when GENERATE_KEYS runs; reused here for ECDH.
        chipPrivKey = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE,
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );
        // P-256 curve parameters are set in GENERATE_KEYS handler (where
        // the KeyPair is constructed).  TODO(jc-dev): port palisade-pa's
        // AttestationProvider curve setup when wiring GENERATE_KEYS.

        // Scratch buffers — transient RAM, auto-cleared on deselect.
        sharedBuf   = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        prkBuf      = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        okmBuf      = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        expTagBuf   = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        hmacKey     = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        hmacScratch = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
    }

    /** Get the chip's ECC private key, populated at GENERATE_KEYS time. */
    public static ECPrivateKey getChipPrivKey() {
        return chipPrivKey;
    }

    /**
     * Unwrap an ECDH-wrapped ParamBundle.  Writes the plaintext to
     * `outBuf` starting at `outOff` and returns the plaintext length.
     *
     * Wire bytes layout in `wireBuf` starting at `wireOff`:
     *
     *   [0..65)         server_ephemeral_pub (65 B, uncompressed SEC1)
     *   [65..81)        iv (16 B)
     *   [81..81+ctLen)  ciphertext (multiple of 16 bytes)
     *   [last 16 B)     tag (16 B, leftmost bytes of HMAC-SHA256)
     *
     * Where ctLen = wireLen - 65 - 16 - 16 = wireLen - 97.
     *
     * @throws ISOException SW_PARAM_BUNDLE_GCM_FAILED on HMAC tag
     *                      verify failure (tampering, wrong key, wrong
     *                      session) or CBC unpad failure.
     */
    public static short unwrap(
        byte[] wireBuf, short wireOff, short wireLen,
        byte[] sessionId, short sessionIdOff, short sessionIdLen,
        byte[] outBuf, short outOff
    ) {
        initOnce();

        final short headerLen = (short) (Constants.SEC1_UNCOMPRESSED_LEN + Constants.AES_IV_LEN);
        if (wireLen < (short) (headerLen + Constants.HMAC_TAG_LEN)) {
            ISOException.throwIt(Constants.SW_PARAM_BUNDLE_GCM_FAILED);
        }
        short ctLen = (short) (wireLen - headerLen - Constants.HMAC_TAG_LEN);
        if (ctLen <= 0 || (short) (ctLen % Constants.AES_IV_LEN) != 0) {
            ISOException.throwIt(Constants.SW_PARAM_BUNDLE_GCM_FAILED);
        }

        // Offsets within wireBuf.
        final short pubOff  = wireOff;
        final short ivOff   = (short) (wireOff + Constants.SEC1_UNCOMPRESSED_LEN);
        final short ctOff   = (short) (ivOff + Constants.AES_IV_LEN);
        final short tagOff  = (short) (ctOff + ctLen);

        // --- 1. ECDH → shared secret X coordinate (32 B) ----------------
        keyAgreement.init(chipPrivKey);
        short sharedLen = keyAgreement.generateSecret(
            wireBuf, pubOff, Constants.SEC1_UNCOMPRESSED_LEN,
            sharedBuf, (short) 0
        );
        if (sharedLen != (short) 32) {
            ISOException.throwIt(Constants.SW_PARAM_BUNDLE_GCM_FAILED);
        }

        // --- 2. HKDF-SHA256 extract: prk = HMAC(salt, shared) -----------
        hmacSha256(
            Constants.HKDF_SALT, (short) 0, Constants.HKDF_SALT_LEN,
            sharedBuf, (short) 0, (short) 32,
            prkBuf, (short) 0
        );

        // --- 3. HKDF-SHA256 expand: okm needs 64 B = 2 iterations -------
        // T(1) = HMAC(prk, sessionId || 0x01)
        Util.arrayCopyNonAtomic(sessionId, sessionIdOff, hmacScratch, (short) 0, sessionIdLen);
        hmacScratch[sessionIdLen] = (byte) 0x01;
        hmacSha256(
            prkBuf, (short) 0, (short) 32,
            hmacScratch, (short) 0, (short) (sessionIdLen + 1),
            okmBuf, (short) 0
        );
        // T(2) = HMAC(prk, T(1) || sessionId || 0x02)
        Util.arrayCopyNonAtomic(okmBuf, (short) 0, hmacScratch, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(
            sessionId, sessionIdOff, hmacScratch, (short) 32, sessionIdLen
        );
        hmacScratch[(short) (32 + sessionIdLen)] = (byte) 0x02;
        hmacSha256(
            prkBuf, (short) 0, (short) 32,
            hmacScratch, (short) 0, (short) (32 + sessionIdLen + 1),
            okmBuf, (short) 32
        );
        // okmBuf[ 0..16) = aesKey
        // okmBuf[16..32) = iv
        // okmBuf[32..64) = hmacKey

        // --- 4. Verify wire IV matches HKDF-derived IV (defence) --------
        byte ivCmp = Util.arrayCompare(
            wireBuf, ivOff,
            okmBuf, (short) 16,
            Constants.AES_IV_LEN
        );
        if (ivCmp != (byte) 0) {
            scrubCryptoState();
            ISOException.throwIt(Constants.SW_PARAM_BUNDLE_GCM_FAILED);
        }

        // --- 5. HMAC-SHA256(hmacKey, iv || ct) → first 16 B tag ---------
        // Build (iv || ct) inline by hashing in two updates.  Our
        // hmacSha256() helper only takes one message; extend it for
        // two-segment HMAC here via a direct SHA-256 composition.
        hmacSha256TwoSeg(
            okmBuf, (short) 32, (short) 32,        // key = hmacKey
            wireBuf, ivOff, Constants.AES_IV_LEN,  // seg 1 = iv
            wireBuf, ctOff, ctLen,                 // seg 2 = ciphertext
            expTagBuf, (short) 0
        );

        byte tagCmp = Util.arrayCompare(
            expTagBuf, (short) 0,
            wireBuf, tagOff,
            Constants.HMAC_TAG_LEN
        );
        if (tagCmp != (byte) 0) {
            scrubCryptoState();
            ISOException.throwIt(Constants.SW_PARAM_BUNDLE_GCM_FAILED);
        }

        // --- 6. AES-CBC decrypt with PKCS#7 unpad -----------------------
        aesKey.setKey(okmBuf, (short) 0);
        aesCipher.init(
            aesKey,
            Cipher.MODE_DECRYPT,
            okmBuf, (short) 16, Constants.AES_IV_LEN   // iv
        );
        short ptLen;
        try {
            ptLen = aesCipher.doFinal(
                wireBuf, ctOff, ctLen,
                outBuf, outOff
            );
        } catch (Exception e) {
            scrubCryptoState();
            ISOException.throwIt(Constants.SW_PARAM_BUNDLE_GCM_FAILED);
            return 0;  // unreachable
        }

        scrubCryptoState();
        return ptLen;
    }

    /** Zero all transient crypto buffers. */
    private static void scrubCryptoState() {
        Util.arrayFillNonAtomic(sharedBuf,   (short) 0, (short) 32, (byte) 0);
        Util.arrayFillNonAtomic(prkBuf,      (short) 0, (short) 32, (byte) 0);
        Util.arrayFillNonAtomic(okmBuf,      (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(expTagBuf,   (short) 0, (short) 32, (byte) 0);
        Util.arrayFillNonAtomic(hmacKey,     (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(hmacScratch, (short) 0, (short) 64, (byte) 0);
    }

    // ---------------------------------------------------------------
    // HMAC-SHA256 helpers (inline — no Signature.ALG_HMAC_SHA_256 in 3.0.4)
    // ---------------------------------------------------------------

    /** Single-segment HMAC-SHA256. */
    private static void hmacSha256(
        byte[] keyBuf, short keyOff, short keyLen,
        byte[] msgBuf, short msgOff, short msgLen,
        byte[] out, short outOff
    ) {
        // Key prep: pad to 64 or pre-hash if longer.
        Util.arrayFillNonAtomic(hmacKey, (short) 0, (short) 64, (byte) 0);
        if (keyLen > (short) 64) {
            sha256.reset();
            sha256.doFinal(keyBuf, keyOff, keyLen, hmacKey, (short) 0);
        } else {
            Util.arrayCopyNonAtomic(keyBuf, keyOff, hmacKey, (short) 0, keyLen);
        }

        // inner = SHA-256(ipad || msg)
        for (short i = (short) 0; i < (short) 64; i++) {
            hmacScratch[i] = (byte) (hmacKey[i] ^ 0x36);
        }
        sha256.reset();
        sha256.update(hmacScratch, (short) 0, (short) 64);
        sha256.doFinal(msgBuf, msgOff, msgLen, out, outOff);
        // out[outOff..outOff+32) = inner hash

        // outer = SHA-256(opad || inner)
        for (short i = (short) 0; i < (short) 64; i++) {
            hmacScratch[i] = (byte) (hmacKey[i] ^ 0x5C);
        }
        sha256.reset();
        sha256.update(hmacScratch, (short) 0, (short) 64);
        sha256.doFinal(out, outOff, (short) 32, out, outOff);
    }

    /**
     * Two-segment HMAC-SHA256 — key, then message = seg1 || seg2.
     * Used for encrypt-then-MAC where the tag covers iv || ct without
     * needing to allocate a scratch buffer that holds both.
     */
    private static void hmacSha256TwoSeg(
        byte[] keyBuf, short keyOff, short keyLen,
        byte[] seg1Buf, short seg1Off, short seg1Len,
        byte[] seg2Buf, short seg2Off, short seg2Len,
        byte[] out, short outOff
    ) {
        Util.arrayFillNonAtomic(hmacKey, (short) 0, (short) 64, (byte) 0);
        if (keyLen > (short) 64) {
            sha256.reset();
            sha256.doFinal(keyBuf, keyOff, keyLen, hmacKey, (short) 0);
        } else {
            Util.arrayCopyNonAtomic(keyBuf, keyOff, hmacKey, (short) 0, keyLen);
        }

        // inner = SHA-256(ipad || seg1 || seg2)
        for (short i = (short) 0; i < (short) 64; i++) {
            hmacScratch[i] = (byte) (hmacKey[i] ^ 0x36);
        }
        sha256.reset();
        sha256.update(hmacScratch, (short) 0, (short) 64);
        sha256.update(seg1Buf, seg1Off, seg1Len);
        sha256.doFinal(seg2Buf, seg2Off, seg2Len, out, outOff);

        // outer = SHA-256(opad || inner)
        for (short i = (short) 0; i < (short) 64; i++) {
            hmacScratch[i] = (byte) (hmacKey[i] ^ 0x5C);
        }
        sha256.reset();
        sha256.update(hmacScratch, (short) 0, (short) 64);
        sha256.doFinal(out, outOff, (short) 32, out, outOff);
    }
}
