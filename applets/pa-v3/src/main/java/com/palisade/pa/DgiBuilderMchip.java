package com.palisade.pa;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * MChip CVN 18 DGI builder — the on-chip mirror of
 * {@code simulateMChipChipBuild()} in packages/emv/src/scheme-mchip.ts.
 *
 * Given a parsed (but not yet stored) ParamBundle, assemble the four
 * DGIs that make up an MChip CVN 18 perso image and write them to
 * NVM.  The byte-parity test in
 * packages/emv/src/byte-parity.test.ts proves the output of this
 * function (once ported to Java) matches what the legacy server-side
 * SADBuilder produces today.
 *
 * DGI LAYOUT (same as simulateMChipChipBuild):
 *
 *   DGI 0x0101  Application Data
 *     TLV 82 AIP, 94 AFL, 9F07 AUC, 5A PAN,
 *     5F24 Expiry YYMMDD, 5F25 Effective YYMMDD,
 *     57 Track 2, 5F34 PSN, 84 AID, 9F08 App version,
 *     9F42 Currency code, 9F44 Currency exponent,
 *     5F28 Country code, 50 App label (optional)
 *
 *   DGI 0x0102  AFL duplicate — 94 AFL only
 *
 *   DGI 0x8201  Key slots
 *     9F52 MK-AC, 9F53 MK-SMI, 9F54 MK-SMC,
 *     9F46 ICC PK Certificate, DF73 ICC RSA priv (proprietary slot)
 *
 *   DGI 0x9201  MChip scheme data
 *     9F52 CVR-Default (5 zero bytes — proprietary overload of 9F52
 *                        inside 9201 context),
 *     9F0D IAC-Default, 9F0E IAC-Denial, 9F0F IAC-Online,
 *     8E CVM List,
 *     DF74 iCVV (proprietary slot for CVN 18 Track 2 offline verify)
 *
 * NVM LAYOUT:
 *
 * Each DGI is stored as raw TLV bytes in a dedicated EEPROM buffer.
 * The applet-level "EMV tag table" that GET_DATA (at POS time) reads
 * is built by walking the DGI payloads — each TLV inside a DGI maps
 * to a named NVM slot.
 *
 * Scope: this class only ASSEMBLES DGI byte streams into a provided
 * output buffer.  The caller (ProvisioningAgentV3.processTransferParams)
 * is responsible for calling JCSystem.beginTransaction() before
 * writing to NVM + commitTransaction() after.
 */
public final class DgiBuilderMchip {

    private DgiBuilderMchip() { /* static only */ }

    // -----------------------------------------------------------------
    // Track 2 Equivalent Data (Tag 57) — recomputed from ParamBundle
    // params.  Format: PAN(F-padded) || 0xD || Expiry(YYMM) || Service(3)
    // || "000000000000" (discretionary, 12 zeros) || padding 0xF to
    // even length.
    //
    // Two scratch buffers, both lazy-init on the first buildDgi0101
    // call (we can't allocate from the <clinit> of a static-only class
    // since JCSystem.makeTransientByteArray needs a JC runtime context):
    //   track2Scratch (24 B) — packed Track 2 bytes, destination of
    //                          buildTrack2.  Consumed by buildDgi0101's
    //                          emitTlv2(TAG_TRACK2, ...) call.
    //   nibbleScratch (40 B) — intermediate nibble accumulator used by
    //                          buildTrack2.  Was previously allocated
    //                          per-call with `new byte[]`, which on JC
    //                          3.0.4 leaks transient RAM every tap
    //                          (no GC by default on JCOP 5) — after
    //                          enough provisioning attempts the
    //                          makeTransientByteArray call would throw
    //                          SystemException(NO_TRANSIENT_SPACE).
    //                          Hoisted to a static now: allocated once,
    //                          auto-cleared on deselect.
    // -----------------------------------------------------------------
    private static byte[] track2Scratch;
    private static byte[] nibbleScratch;

    /**
     * Allocate all transient scratch used by the four DGI builders.
     * MUST be called from the applet's constructor (or otherwise
     * outside any JCSystem.beginTransaction block) — JCSystem.
     * makeTransientByteArray throws TransactionException.IN_PROGRESS
     * when invoked inside a transaction, and on JCOP 5 that's one of
     * the errors that can mute the contactless interface rather than
     * raise a catchable exception.  Lazy-init inside buildTrack2 was
     * the root cause of silent-on-final-APDU crashes before this
     * eager init was added.
     */
    public static void initOnce() {
        if (track2Scratch != null) return;
        track2Scratch = JCSystem.makeTransientByteArray(
            (short) 24, JCSystem.CLEAR_ON_DESELECT
        );
        nibbleScratch = JCSystem.makeTransientByteArray(
            (short) 40, JCSystem.CLEAR_ON_DESELECT
        );
    }

    /**
     * Build DGI 0x0101 (Application Data) into outBuf starting at
     * outOff.  Returns the number of bytes written.
     *
     * Expects the caller to have already located each ParamBundle tag
     * and populated `offsets` + `lens` with the [offset, length] for
     * each tag in the positions given by the PB_* constants — a
     * lookup index, basically.  That way the loop below doesn't
     * re-scan the bundle for every tag.
     */
    public static short buildDgi0101(
        byte[] bundleBuf, short bundleOff, short bundleLen,
        short[] scratch,
        byte[] outBuf, short outOff
    ) {
        short writeOff = outOff;

        // --- Tag 82 AIP (2 bytes) ---
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_AIP,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_AIP, scratch),
            scratch[1]);

        // --- Tag 94 AFL (var) ---
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_AFL,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_AFL, scratch),
            scratch[1]);

        // --- Tag 9F07 AUC (2 bytes) ---
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_AUC,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_AUC, scratch),
            scratch[1]);

        // --- Tag 5A PAN (var) ---
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_PAN,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_PAN, scratch),
            scratch[1]);

        // --- Tag 5F24 Expiry YYMMDD (expiry(2) || 0x31) ---
        short expOff = findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_EXPIRY, scratch);
        writeOff = emitTag2(outBuf, writeOff, Constants.TAG_EXPIRY_YYMMDD);
        outBuf[writeOff++] = (byte) 3;
        Util.arrayCopyNonAtomic(bundleBuf, expOff, outBuf, writeOff, (short) 2);
        outBuf[(short) (writeOff + 2)] = (byte) 0x31;
        writeOff += 3;

        // --- Tag 5F25 Effective YYMMDD (effective(2) || 0x01) ---
        short effOff = findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_EFFECTIVE, scratch);
        writeOff = emitTag2(outBuf, writeOff, Constants.TAG_EFFECTIVE_YYMMDD);
        outBuf[writeOff++] = (byte) 3;
        Util.arrayCopyNonAtomic(bundleBuf, effOff, outBuf, writeOff, (short) 2);
        outBuf[(short) (writeOff + 2)] = (byte) 0x01;
        writeOff += 3;

        // --- Tag 57 Track 2 (recomputed) ---
        // Compose PAN || 0xD || expiryYYMM || serviceCode(3) ||
        //         discretionary(12 zero digits) || pad 0xF to even
        //
        // Buffer size: PAN max 10 B + 0xD + expiry 2 B + service 2 B +
        // discretionary 6 B ≈ 22 B worst case.  Buffer is pre-allocated
        // by initOnce() so we never hit JCSystem.makeTransientByteArray
        // inside the beginTransaction of processTransferParams.
        short t2Len = buildTrack2(
            bundleBuf, bundleOff, bundleLen, scratch,
            track2Scratch, (short) 0
        );
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_TRACK2, track2Scratch, (short) 0, t2Len);

        // --- Tag 5F34 PSN (1 byte) ---
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_PSN,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_PSN, scratch),
            scratch[1]);

        // --- Tag 84 AID (var) ---
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_AID,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_AID, scratch),
            scratch[1]);

        // --- Tag 9F08 App version (2 bytes) ---
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_APP_VERSION,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_APP_VERSION, scratch),
            scratch[1]);

        // --- Tag 9F42 Currency code (2 bytes) ---
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_CURRENCY_CODE,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_CURRENCY_CODE, scratch),
            scratch[1]);

        // --- Tag 9F44 Currency exponent (1 byte) ---
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_CURRENCY_EXP,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_CURRENCY_EXPONENT, scratch),
            scratch[1]);

        // --- Tag 5F28 Country code (2 bytes) ---
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_COUNTRY_CODE,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_COUNTRY_CODE, scratch),
            scratch[1]);

        // --- Tag 50 App label (optional) ---
        if (ParamBundleParser.findTag(bundleBuf, bundleOff, bundleLen,
                                      Constants.PB_APP_LABEL, scratch)) {
            writeOff = emitTlv2(outBuf, writeOff,
                Constants.TAG_APP_LABEL,
                bundleBuf, scratch[0], scratch[1]);
        }

        return (short) (writeOff - outOff);
    }

    /** Build DGI 0x0102 (AFL duplicate). */
    public static short buildDgi0102(
        byte[] bundleBuf, short bundleOff, short bundleLen,
        short[] scratch,
        byte[] outBuf, short outOff
    ) {
        short writeOff = emitTlv2(outBuf, outOff,
            Constants.TAG_AFL,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_AFL, scratch),
            scratch[1]);
        return (short) (writeOff - outOff);
    }

    /** Build DGI 0x8201 (Key slots). */
    public static short buildDgi8201(
        byte[] bundleBuf, short bundleOff, short bundleLen,
        short[] scratch,
        byte[] outBuf, short outOff
    ) {
        short writeOff = outOff;

        // 9F52 MK-AC (16 B)
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_MC_MK_AC,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_MK_AC, scratch),
            scratch[1]);

        // 9F53 MK-SMI
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_MC_MK_SMI,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_MK_SMI, scratch),
            scratch[1]);

        // 9F54 MK-SMC
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_MC_MK_SMC,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_MK_SMC, scratch),
            scratch[1]);

        // 9F46 ICC PK Certificate
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_ICC_PK_CERT,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_ICC_PK_CERT, scratch),
            scratch[1]);

        // DF73 ICC RSA priv (proprietary)
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_ICC_RSA_PRIV_SLOT,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_ICC_RSA_PRIV, scratch),
            scratch[1]);

        return (short) (writeOff - outOff);
    }

    /** Build DGI 0x9201 (MChip scheme data). */
    public static short buildDgi9201(
        byte[] bundleBuf, short bundleOff, short bundleLen,
        short[] scratch,
        byte[] outBuf, short outOff
    ) {
        short writeOff = outOff;

        // 9F52 CVR-Default — 5 zero bytes (scheme-mchip.ts makes this
        // a static all-zero buffer).
        writeOff = emitTag2(outBuf, writeOff, Constants.TAG_MC_MK_AC);
        outBuf[writeOff++] = (byte) 5;
        Util.arrayFillNonAtomic(outBuf, writeOff, (short) 5, (byte) 0x00);
        writeOff += 5;

        // 9F0D IAC-Default
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_IAC_DEFAULT,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_IAC_DEFAULT, scratch),
            scratch[1]);

        // 9F0E IAC-Denial
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_IAC_DENIAL,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_IAC_DENIAL, scratch),
            scratch[1]);

        // 9F0F IAC-Online
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_IAC_ONLINE,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_IAC_ONLINE, scratch),
            scratch[1]);

        // 8E CVM List
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_CVM_LIST,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_CVM_LIST, scratch),
            scratch[1]);

        // DF74 iCVV (proprietary)
        writeOff = emitTlv2(outBuf, writeOff,
            Constants.TAG_ICVV_SLOT,
            bundleBuf, findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_ICVV, scratch),
            scratch[1]);

        return (short) (writeOff - outOff);
    }

    // -----------------------------------------------------------------
    // TLV emission helpers
    // -----------------------------------------------------------------

    /**
     * Emit a 2-byte big-endian EMV tag to outBuf starting at outOff,
     * coping with 1-byte tags (high byte == 0).  Returns the new
     * write offset.
     *
     * Examples:
     *   TAG_AIP    = 0x0082 → outBuf[writeOff] = 0x82  (1 byte)
     *   TAG_EXPIRY = 0x5F24 → outBuf[writeOff] = 0x5F, [writeOff+1] = 0x24
     */
    private static short emitTag2(byte[] outBuf, short outOff, short tag) {
        if ((tag & (short) 0xFF00) != 0) {
            // Two-byte tag.
            outBuf[outOff++] = (byte) ((tag >> 8) & 0xFF);
            outBuf[outOff++] = (byte) (tag & 0xFF);
        } else {
            // One-byte tag.
            outBuf[outOff++] = (byte) (tag & 0xFF);
        }
        return outOff;
    }

    /**
     * Emit a full TLV (tag + short-form length + value) to outBuf.
     * Len is BER-TLV short-form for now (assumes value ≤ 127 bytes).
     * For longer values (ICC PK Cert > 127), use {@link #emitTlv2Long}.
     */
    private static short emitTlv2(
        byte[] outBuf, short outOff,
        short tag,
        byte[] srcBuf, short srcOff, short len
    ) {
        outOff = emitTag2(outBuf, outOff, tag);
        if (len < (short) 0x80) {
            outBuf[outOff++] = (byte) len;
        } else {
            // Long form 0x81 LL (assumes len <= 255)
            outBuf[outOff++] = (byte) 0x81;
            outBuf[outOff++] = (byte) (len & 0xFF);
        }
        Util.arrayCopyNonAtomic(srcBuf, srcOff, outBuf, outOff, len);
        return (short) (outOff + len);
    }

    // -----------------------------------------------------------------
    // Track 2 builder — see format note at top of class
    // -----------------------------------------------------------------

    /**
     * Build Track 2 Equivalent Data from the PAN, expiry, service
     * code.  Writes nibble-packed BCD bytes to outBuf; returns the
     * number of bytes written.
     *
     * Format (nibbles):
     *   [PAN digits, F-padded to even] 0xD [expiry YYMM (4)]
     *   [serviceCode (3)]
     *   [discretionary = 12 zeros]
     *   [pad 0xF to even nibble count]
     *
     * Matches @palisade/emv/src/track2.ts.
     */
    private static short buildTrack2(
        byte[] bundleBuf, short bundleOff, short bundleLen, short[] scratch,
        byte[] outBuf, short outOff
    ) {
        // Scratch builder working in nibbles — accumulate digits as
        // ASCII '0'..'9', 'D', 'F' then pack.  For simplicity use
        // temp byte array of nibble count, then pack-to-bytes at end.
        //
        // Conservative max: 10 B PAN × 2 + 1 separator + 4 expiry + 3 sc
        //                   + 12 disc = 40 nibbles → 20 bytes packed.
        //
        // Pre-allocated by initOnce() called from the applet
        // constructor.  See class-level notes on why this can't be a
        // `new byte[]` local and why it can't be lazy-initialised
        // inside the processTransferParams transaction.
        byte[] nibbles = nibbleScratch;
        short nibCount = (short) 0;

        // PAN: 8 bytes stored as 16 nibbles (F-padded for 17-digit
        // PAN).  We decompose each byte into two nibbles.
        short panOff = findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_PAN, scratch);
        short panLen = scratch[1];
        for (short i = (short) 0; i < panLen; i++) {
            byte b = bundleBuf[(short) (panOff + i)];
            byte hi = (byte) ((b >> 4) & 0x0F);
            byte lo = (byte) (b & 0x0F);
            nibbles[nibCount++] = hi;
            // PAN may be F-padded at the tail; include up through
            // the first 'F' encountered as the "real" PAN length.
            // Track 2 needs PAN without the F pad.
            if (hi == (byte) 0x0F) { nibCount--; break; }
            nibbles[nibCount++] = lo;
            if (lo == (byte) 0x0F) { nibCount--; break; }
        }

        // Field separator 'D'
        nibbles[nibCount++] = (byte) 0x0D;

        // Expiry YYMM — 4 nibbles from 2 BCD bytes.
        short expOff2 = findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_EXPIRY, scratch);
        nibbles[nibCount++] = (byte) ((bundleBuf[expOff2]     >> 4) & 0x0F);
        nibbles[nibCount++] = (byte) ( bundleBuf[expOff2]           & 0x0F);
        nibbles[nibCount++] = (byte) ((bundleBuf[(short) (expOff2 + 1)] >> 4) & 0x0F);
        nibbles[nibCount++] = (byte) ( bundleBuf[(short) (expOff2 + 1)]       & 0x0F);

        // Service code — 3 digits.  Stored as 4-nibble 2-byte
        // (leading-zero-padded in ParamBundle), so we skip the
        // leading zero.
        short scOff = findOrThrow(bundleBuf, bundleOff, bundleLen, Constants.PB_SERVICE_CODE, scratch);
        // Skip high nibble of first byte (the leading zero pad)
        nibbles[nibCount++] = (byte) (bundleBuf[scOff] & 0x0F);
        nibbles[nibCount++] = (byte) ((bundleBuf[(short) (scOff + 1)] >> 4) & 0x0F);
        nibbles[nibCount++] = (byte) ( bundleBuf[(short) (scOff + 1)]       & 0x0F);

        // Discretionary: 12 zero digits (placeholder).  Real MChip
        // inserts the ATC counter; at perso time we zero it.
        for (short i = (short) 0; i < (short) 12; i++) {
            nibbles[nibCount++] = (byte) 0x00;
        }

        // Pad to even nibble count with 0xF.
        if ((nibCount & 1) == 1) {
            nibbles[nibCount++] = (byte) 0x0F;
        }

        // Pack nibbles → bytes.
        short byteLen = (short) (nibCount >> 1);
        for (short i = (short) 0; i < byteLen; i++) {
            byte hi = nibbles[(short) (i * 2)];
            byte lo = nibbles[(short) (i * 2 + 1)];
            outBuf[(short) (outOff + i)] = (byte) (((hi & 0x0F) << 4) | (lo & 0x0F));
        }

        return byteLen;
    }

    // -----------------------------------------------------------------
    // Bundle-scan helper
    // -----------------------------------------------------------------

    /**
     * Lookup a required ParamBundle tag and return its value offset.
     * Populates `scratch` with [offset, length] as a side effect.
     * Throws SW_PARAM_BUNDLE_INCOMPLETE if the tag is missing.
     */
    private static short findOrThrow(
        byte[] bundleBuf, short bundleOff, short bundleLen,
        byte tag, short[] scratch
    ) {
        if (!ParamBundleParser.findTag(bundleBuf, bundleOff, bundleLen, tag, scratch)) {
            javacard.framework.ISOException.throwIt(
                Constants.SW_PARAM_BUNDLE_INCOMPLETE
            );
        }
        return scratch[0];
    }
}
