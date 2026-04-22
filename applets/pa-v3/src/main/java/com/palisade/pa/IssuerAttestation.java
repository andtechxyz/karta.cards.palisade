package com.palisade.pa;

import javacard.framework.ISOException;
import javacard.framework.Util;
import javacard.security.ECPrivateKey;
import javacard.security.KeyBuilder;
import javacard.security.Signature;

/**
 * Patent claims C16 + C23: per-card issuer-controlled attestation.
 *
 * Loaded at personalisation via STORE_ATTESTATION (INS=0xEC) with
 * three sub-DGIs:
 *
 *   DGI A001  32-byte raw P-256 private scalar  (attestation priv key)
 *   DGI A002  card cert blob                    (card_pubkey(65) || cplc(42) || sig(DER))
 *   DGI A003  42-byte NXP CPLC                  (chip identity bytes)
 *
 * At GENERATE_KEYS time (Phase B, wired in rca as a subsequent step)
 * signAttestation(iccPubkey || cplc) produces a DER ECDSA-SHA256
 * signature.  The verifier (services/rca/src/services/attestation-
 * verifier.ts) walks the chain:
 *
 *   Karta Root CA pubkey (env-pinned)
 *       │  signs
 *       ▼
 *   Issuer cert blob (env; rca loads once at boot)
 *       │  signs
 *       ▼
 *   card cert blob (returned via GET_ATTESTATION_CHAIN — this class's
 *                   loaded DGI A002 emitted verbatim)
 *       │  holds card_pubkey, which verifies
 *       ▼
 *   attestSig over (iccPubkey || cplc) — produced by signAttestation
 *
 * No EL2GO.  No NXP relationship.  Karta owns the root.  See
 * attestation-verifier.ts's block comment for the full design.
 *
 * STATE MACHINE:
 *
 *   The applet's STATE_IDLE is the only state that accepts STORE_
 *   ATTESTATION.  Once a keygen has been issued (STATE_KEYGEN_
 *   COMPLETE or later) the applet refuses further loads — prevents
 *   mid-session material swap.  A WIPE resets everything back to
 *   STATE_IDLE so a re-perso can load fresh material.
 *
 * RAM/NVM BUDGET:
 *
 *   attestPriv     ECPrivateKey (P-256)         — EEPROM, ~96 B
 *   signer         Signature.ALG_ECDSA_SHA_256  — EEPROM, ~128 B incl bundled MD
 *   cardCert       byte[ATTEST_CARD_CERT_MAX]   — EEPROM, 192 B
 *   cplc           byte[ATTEST_CPLC_LEN]        — EEPROM, 42 B
 *
 * Total EEPROM footprint ≈ 460 B per installed applet.  The Signature
 * fits alongside EcdhUnwrapper's MessageDigest because the JCOP 5
 * per-applet ceiling is on TRANSIENT (CLEAR_ON_DESELECT) RAM, not on
 * SHA-engine count; see ProvisioningAgentV3 buffer-sizing comment.
 */
public final class IssuerAttestation {

    private ECPrivateKey attestPriv;
    private Signature signer;

    /** Card cert blob (card_pubkey || cplc || sig) loaded at perso. */
    private byte[] cardCert;
    private short  cardCertLen;

    /** 42-byte CPLC loaded at perso — used as the second half of the
     *  attestation signing body. */
    private byte[] cplc;
    private short  cplcLen;

    /** True once all three DGIs have been loaded at least once.  Guards
     *  signAttestation from running against half-loaded state. */
    private boolean privLoaded;
    private boolean cardCertLoaded;
    private boolean cplcLoaded;

    /**
     * One-time init.  Call from the applet constructor.  All EEPROM
     * allocations happen here so no later code path tries to allocate
     * persistent memory inside a transaction.
     */
    public void initOnce() {
        if (attestPriv != null) return;
        // Standalone ECPrivateKey — no corresponding ECPublicKey needed
        // on-card because we never ECDH with this key (it only signs
        // per-session iccPubkey attestation trailers).  Saves one
        // ECPublicKey slot vs. the KeyPair-wrapper approach.
        attestPriv = (ECPrivateKey) KeyBuilder.buildKey(
            KeyBuilder.TYPE_EC_FP_PRIVATE,
            KeyBuilder.LENGTH_EC_FP_256,
            false
        );
        // Curve params must be set before setS() can write the scalar;
        // piggyback on ProvisioningAgentV3's curve constants so the
        // icc keypair and the attestation key agree on domain bits.
        ProvisioningAgentV3.initP256Params(attestPriv);

        // Eager Signature allocation — fail-fast at INSTALL if the
        // applet ever exceeds the JCOP 5 per-applet TRANSIENT RAM cap
        // (the real ceiling, not a SHA-engine quota — empirically
        // verified by FIDO running MD + Sig + KeyAgreement happily on
        // the same card SKU).  Lazy-init would defer the same failure
        // to the first attested GENERATE_KEYS, much harder to diagnose.
        signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        cardCert = new byte[Constants.ATTEST_CARD_CERT_MAX];
        cplc     = new byte[Constants.ATTEST_CPLC_LEN];
    }

    /**
     * Load the 32-byte raw P-256 private scalar (STORE_ATTESTATION P1
     * = ATTEST_P1_PRIV_KEY).  The scalar lives in EEPROM inside the
     * ECPrivateKey; callers must wipe their own copy of the input
     * buffer afterwards.
     */
    public void loadPrivKey(byte[] buf, short off, short len) {
        if (len != Constants.ATTEST_PRIV_KEY_LEN) {
            ISOException.throwIt(Constants.SW_DBG_ATTEST_BAD_LEN);
        }
        attestPriv.setS(buf, off, len);
        privLoaded = true;
    }

    /**
     * Load the card cert blob (STORE_ATTESTATION P1 = ATTEST_P1_CARD_CERT).
     * Stored verbatim in EEPROM; returned verbatim on GET_ATTESTATION_
     * CHAIN.  The applet never parses this blob — rca does the ECDSA
     * chain walk against it.
     */
    public void loadCardCert(byte[] buf, short off, short len) {
        if (len <= 0 || len > Constants.ATTEST_CARD_CERT_MAX) {
            ISOException.throwIt(Constants.SW_DBG_ATTEST_BAD_LEN);
        }
        Util.arrayCopyNonAtomic(buf, off, cardCert, (short) 0, len);
        cardCertLen = len;
        cardCertLoaded = true;
    }

    /**
     * Load the 42-byte NXP CPLC (STORE_ATTESTATION P1 = ATTEST_P1_CPLC).
     * Used both as the second half of the attestation signing body
     * (paired with iccPubkey) and emitted verbatim inside the card
     * cert at verification time.  Note the chip ALSO exposes its own
     * CPLC via GET DATA (80 CA 9F 7F) at the ISD level; we accept it
     * loaded here to avoid the self-issue APDU round-trip at
     * GENERATE_KEYS time.
     */
    public void loadCplc(byte[] buf, short off, short len) {
        if (len != Constants.ATTEST_CPLC_LEN) {
            ISOException.throwIt(Constants.SW_DBG_ATTEST_BAD_LEN);
        }
        Util.arrayCopyNonAtomic(buf, off, cplc, (short) 0, len);
        cplcLen = len;
        cplcLoaded = true;
    }

    /**
     * Sign (prefix || cplc) with the attestation private key.  Returns
     * the DER ECDSA-SHA256 signature length written to out[outOff..].
     *
     * `prefix` in practice is the 65-byte ephemeral iccPubkey from the
     * active GENERATE_KEYS call; this method concatenates internally
     * via `signer.update` + `signer.sign` so we never have to allocate
     * a Buffer.concat-style intermediate.
     */
    public short signAttestation(
        byte[] prefixBuf, short prefixOff, short prefixLen,
        byte[] out, short outOff
    ) {
        if (!privLoaded || !cplcLoaded) {
            ISOException.throwIt(Constants.SW_DBG_ATTEST_NOT_LOADED);
        }
        // signer is eager-allocated in initOnce — no lazy branch needed.
        signer.init(attestPriv, Signature.MODE_SIGN);
        signer.update(prefixBuf, prefixOff, prefixLen);
        return signer.sign(cplc, (short) 0, cplcLen, out, outOff);
    }

    /**
     * Copy the loaded card cert blob into `out[outOff..]`.  Returns
     * the cert byte length.  Used by GET_ATTESTATION_CHAIN.
     */
    public short getCardCert(byte[] out, short outOff) {
        if (!cardCertLoaded) {
            ISOException.throwIt(Constants.SW_DBG_ATTEST_NOT_LOADED);
        }
        Util.arrayCopyNonAtomic(cardCert, (short) 0, out, outOff, cardCertLen);
        return cardCertLen;
    }

    /** Copy the loaded CPLC into `out[outOff..]`.  Returns 42. */
    public short getCplc(byte[] out, short outOff) {
        if (!cplcLoaded) {
            ISOException.throwIt(Constants.SW_DBG_ATTEST_NOT_LOADED);
        }
        Util.arrayCopyNonAtomic(cplc, (short) 0, out, outOff, cplcLen);
        return cplcLen;
    }

    /** True iff all three DGIs have been loaded. */
    public boolean isFullyLoaded() {
        return privLoaded && cardCertLoaded && cplcLoaded;
    }
}
