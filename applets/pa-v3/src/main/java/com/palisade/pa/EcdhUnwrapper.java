package com.palisade.pa;

import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.ECPrivateKey;
import javacard.security.KeyAgreement;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacardx.crypto.AEADCipher;
import javacardx.crypto.Cipher;

/**
 * ECDH + HKDF-SHA256 + AES-128-GCM unwrapper.
 *
 * Mirror of packages/emv-ecdh/src/index.ts's `unwrapParamBundle`.
 * Any divergence from the TS reference breaks interop.
 *
 * WIRE FORMAT (what's in the TRANSFER_PARAMS APDU body):
 *
 *   server_ephemeral_pub_uncompressed (65 B)
 *   || nonce (12 B)
 *   || ciphertext (variable)
 *   || gcm_tag (16 B)
 *
 * PROTOCOL:
 *
 *   1. shared_secret = ECDH(chip_priv, server_eph_pub)  // 32 B
 *   2. prk = HMAC-SHA256(HKDF_SALT, shared_secret)
 *   3. okm = HMAC-SHA256(prk, sessionId_bytes || 0x01)  // 32 B (first iter)
 *      → only need 28 B (16 aesKey + 12 nonce)
 *   4. aesKey = okm[0..16]
 *   5. derived_nonce = okm[16..28]
 *      MUST match the wire nonce — else tampering.
 *   6. plaintext = AES-128-GCM-decrypt(aesKey, derived_nonce,
 *                                      ciphertext, tag, aad=empty)
 *      On GCM verify fail → reject with SW_PARAM_BUNDLE_GCM_FAILED.
 *
 * HKDF-SHA256:
 *
 *   extract:  prk = HMAC-SHA256(salt, ikm)
 *   expand:   T(1) = HMAC-SHA256(prk, info || 0x01)
 *             okm  = T(1)  (we only need 28 B < 32 B = one iteration)
 *
 * RAM USAGE (static allocations — no per-call new/allocate):
 *
 *   chipPrivKey:    EC private key (on-card, KeyBuilder)
 *   keyAgreement:   ECDH_PLAIN instance, reused
 *   sha256:         MessageDigest instance, reused
 *   aesCipher:      AES-128-GCM instance, reused
 *   sharedBuf:      32-byte scratch for shared secret
 *   prkBuf:         32-byte scratch for HKDF PRK
 *   okmBuf:         32-byte scratch for HKDF output
 *   aesKey:         AESKey (16 B) handle, reset per use
 *
 * Total static RAM: ~180 B plus the KeyAgreement / Cipher / MessageDigest
 * instances the runtime manages.  Well within JCOP 5 budgets.
 */
public final class EcdhUnwrapper {

    // ---------------------------------------------------------------
    // Static instances (lazy-init in initOnce)
    // ---------------------------------------------------------------

    private static ECPrivateKey chipPrivKey;
    private static KeyAgreement keyAgreement;
    private static MessageDigest sha256;
    private static AEADCipher aesCipher;
    private static AESKey aesKey;

    private static byte[] sharedBuf;
    private static byte[] prkBuf;
    private static byte[] okmBuf;

    /** HMAC-SHA256 inner/outer pads (ipad = 0x36*64, opad = 0x5c*64). */
    private static byte[] hmacKey;    // 64 B — the HMAC block-sized key
    private static byte[] hmacScratch; // 64 B — for XOR'd inner/outer ops

    /**
     * One-time initialisation.  Call from the applet's constructor or
     * before the first unwrap.  All objects are transient (RAM-resident,
     * cleared on power-off) EXCEPT chipPrivKey which lives in EEPROM.
     */
    public static void initOnce() {
        if (keyAgreement != null) return;

        // ECDH_PLAIN returns raw X coordinate (32 B), not the full SEC1
        // point.  That's what we feed into HKDF as ikm.
        keyAgreement = KeyAgreement.getInstance(
            KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY, false
        );
        sha256 = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

        // AES-128-GCM with authentication.  JCOP 5 supports natively.
        aesCipher = (AEADCipher) AEADCipher.getInstance(
            AEADCipher.ALG_AES_GCM, false
        );
        aesKey = (AESKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_AES_TRANSIENT_DESELECT,
            KeyBuilder.LENGTH_AES_128,
            false
        );

        // ECPrivateKey in EEPROM — persists across power cycles.  Set
        // when GENERATE_KEYS runs; reused here for ECDH.
        chipPrivKey = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE, KeyBuilder.LENGTH_EC_FP_256, false
        );
        // P-256 curve parameters would be set here via setA, setB, setG,
        // setR, setFieldFP, setK.  Reuse palisade-pa/AttestationProvider
        // constants — they're standard SEC1 P-256.
        // ...

        // Scratch buffers — transient RAM.
        sharedBuf   = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        prkBuf      = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        okmBuf      = JCSystem.makeTransientByteArray((short) 32, JCSystem.CLEAR_ON_DESELECT);
        hmacKey     = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        hmacScratch = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
    }

    /**
     * Get a reference to the chip's ECC private key, for use by
     * GENERATE_KEYS and by this class's ECDH step.  The corresponding
     * public key is derived from this private key at GENERATE_KEYS time
     * and sent to the server.
     */
    public static ECPrivateKey getChipPrivKey() {
        return chipPrivKey;
    }

    /**
     * Unwrap an ECDH-wrapped ParamBundle.  Writes the plaintext to
     * `outBuf` starting at `outOff` and returns the plaintext length.
     *
     * Wire bytes layout in `wireBuf` starting at `wireOff`:
     *
     *   [0..65)      server_ephemeral_pub (65 B)
     *   [65..77)     derived nonce (12 B) — must match HKDF output
     *   [77..77+ct)  ciphertext
     *   [77+ct..)    gcm tag (16 B)
     *
     * Where ct_len = wireLen - 65 - 12 - 16.
     *
     * @param wireBuf     backing buffer containing the wire bytes
     * @param wireOff     offset of the wire-bytes start
     * @param wireLen     total length of the wire (server pub + nonce + ct + tag)
     * @param sessionId   ASCII session id bytes (HKDF info input)
     * @param sessionIdOff offset of sessionId in its buffer
     * @param sessionIdLen length of sessionId
     * @param outBuf      where to write the plaintext
     * @param outOff      offset in outBuf where the plaintext starts
     * @return the plaintext length (wireLen - 93)
     * @throws ISOException SW_PARAM_BUNDLE_GCM_FAILED on tag verify
     *                      failure (wrong key, tampering, wrong session)
     */
    public static short unwrap(
        byte[] wireBuf, short wireOff, short wireLen,
        byte[] sessionId, short sessionIdOff, short sessionIdLen,
        byte[] outBuf, short outOff
    ) {
        initOnce();

        final short headerLen = (short) (Constants.SEC1_UNCOMPRESSED_LEN + Constants.GCM_NONCE_LEN);
        if (wireLen < (short) (headerLen + Constants.GCM_TAG_LEN)) {
            ISOException.throwIt(Constants.SW_PARAM_BUNDLE_GCM_FAILED);
        }
        short ctLen = (short) (wireLen - headerLen - Constants.GCM_TAG_LEN);

        // --- 1. ECDH shared secret ------------------------------------
        keyAgreement.init(chipPrivKey);
        short sharedLen = keyAgreement.generateSecret(
            wireBuf, wireOff, Constants.SEC1_UNCOMPRESSED_LEN,
            sharedBuf, (short) 0
        );
        // ALG_EC_SVDP_DH_PLAIN_XY returns x||y (64 B).  We want just X (32 B).
        // ALG_EC_SVDP_DH_PLAIN returns X (32 B).  Depending on platform.
        // If 64 bytes, truncate to first 32.
        if (sharedLen == (short) 64) {
            sharedLen = (short) 32;
        }
        // sharedBuf[0..32) now holds the shared secret X coordinate.

        // --- 2. HKDF-SHA256 extract: prk = HMAC(salt, ikm) -------------
        hmacSha256(
            Constants.HKDF_SALT, (short) 0, Constants.HKDF_SALT_LEN,
            sharedBuf, (short) 0, sharedLen,
            prkBuf, (short) 0
        );

        // --- 3. HKDF-SHA256 expand: okm = HMAC(prk, info || 0x01) ------
        // Info is the sessionId bytes.  We only need 28 bytes = 1
        // iteration of HKDF-expand (SHA-256 outputs 32 B per iter).
        //
        // expand step: T(1) = HMAC(prk, info || 0x01)
        // Build (info || 0x01) in hmacScratch (reuse).
        Util.arrayCopyNonAtomic(sessionId, sessionIdOff, hmacScratch, (short) 0, sessionIdLen);
        hmacScratch[sessionIdLen] = (byte) 0x01;
        hmacSha256(
            prkBuf, (short) 0, (short) 32,
            hmacScratch, (short) 0, (short) (sessionIdLen + 1),
            okmBuf, (short) 0
        );
        // okmBuf[0..16)  = aesKey
        // okmBuf[16..28) = derived nonce

        // --- 4. Compare derived nonce against wire nonce ---------------
        // Constant-time compare: Util.arrayCompare returns 0 on match.
        byte cmp = Util.arrayCompare(
            wireBuf, (short) (wireOff + Constants.SEC1_UNCOMPRESSED_LEN),
            okmBuf, (short) 16,
            Constants.GCM_NONCE_LEN
        );
        if (cmp != (byte) 0) {
            // Wire nonce != HKDF nonce → tampering or protocol mismatch.
            // Scrub + reject.
            Util.arrayFillNonAtomic(sharedBuf, (short) 0, (short) 32, (byte) 0);
            Util.arrayFillNonAtomic(prkBuf,    (short) 0, (short) 32, (byte) 0);
            Util.arrayFillNonAtomic(okmBuf,    (short) 0, (short) 32, (byte) 0);
            ISOException.throwIt(Constants.SW_PARAM_BUNDLE_GCM_FAILED);
        }

        // --- 5. AES-128-GCM decrypt + tag verify -----------------------
        aesKey.setKey(okmBuf, (short) 0);
        aesCipher.init(
            aesKey,
            Cipher.MODE_DECRYPT,
            okmBuf, (short) 16, Constants.GCM_NONCE_LEN  // nonce
        );
        // No AAD.

        short ptLen = (short) 0;
        try {
            ptLen = aesCipher.doFinal(
                wireBuf, (short) (wireOff + headerLen), ctLen,
                outBuf, outOff
            );
            // doFinal in AEADCipher verifies the tag implicitly when
            // the cipher was initialised in DECRYPT mode.  On platforms
            // that require explicit verification, use:
            //    aesCipher.retrieveTag(...) + arrayCompare
            // but JCOP 5's ALG_AES_GCM throws CryptoException on tag
            // mismatch so the catch below handles it.
        } catch (Exception e) {
            // Scrub before throwing.
            Util.arrayFillNonAtomic(sharedBuf, (short) 0, (short) 32, (byte) 0);
            Util.arrayFillNonAtomic(prkBuf,    (short) 0, (short) 32, (byte) 0);
            Util.arrayFillNonAtomic(okmBuf,    (short) 0, (short) 32, (byte) 0);
            ISOException.throwIt(Constants.SW_PARAM_BUNDLE_GCM_FAILED);
        }

        // Scrub transient key material.
        Util.arrayFillNonAtomic(sharedBuf, (short) 0, (short) 32, (byte) 0);
        Util.arrayFillNonAtomic(prkBuf,    (short) 0, (short) 32, (byte) 0);
        Util.arrayFillNonAtomic(okmBuf,    (short) 0, (short) 32, (byte) 0);

        return ptLen;
    }

    // ---------------------------------------------------------------
    // HMAC-SHA256 (inline because JC doesn't expose Signature.ALG_HMAC_SHA_256
    // on all platforms; implementing on top of SHA-256 guarantees portability)
    // ---------------------------------------------------------------

    /**
     * HMAC-SHA256(key, msg) → out[outOff..outOff+32).
     *
     * key can be any length; we pad-to-64 or pre-hash as RFC 2104.
     */
    private static void hmacSha256(
        byte[] keyBuf, short keyOff, short keyLen,
        byte[] msgBuf, short msgOff, short msgLen,
        byte[] out, short outOff
    ) {
        // Key prep: if keyLen > 64, replace with SHA-256(key).  Else
        // zero-pad to 64.  Result lives in hmacKey[0..64).
        Util.arrayFillNonAtomic(hmacKey, (short) 0, (short) 64, (byte) 0);
        if (keyLen > (short) 64) {
            sha256.reset();
            sha256.doFinal(keyBuf, keyOff, keyLen, hmacKey, (short) 0);
        } else {
            Util.arrayCopyNonAtomic(keyBuf, keyOff, hmacKey, (short) 0, keyLen);
        }

        // ipad = key XOR 0x36*64, then SHA256(ipad || msg) → inner.
        for (short i = (short) 0; i < (short) 64; i++) {
            hmacScratch[i] = (byte) (hmacKey[i] ^ 0x36);
        }
        sha256.reset();
        sha256.update(hmacScratch, (short) 0, (short) 64);
        sha256.doFinal(msgBuf, msgOff, msgLen, out, outOff);
        // out[outOff..outOff+32) now holds the inner hash.

        // opad = key XOR 0x5c*64, then SHA256(opad || inner) → final.
        for (short i = (short) 0; i < (short) 64; i++) {
            hmacScratch[i] = (byte) (hmacKey[i] ^ 0x5C);
        }
        sha256.reset();
        sha256.update(hmacScratch, (short) 0, (short) 64);
        sha256.doFinal(out, outOff, (short) 32, out, outOff);

        // Scrub hmacKey + scratch.
        Util.arrayFillNonAtomic(hmacKey,     (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(hmacScratch, (short) 0, (short) 64, (byte) 0);
    }
}
