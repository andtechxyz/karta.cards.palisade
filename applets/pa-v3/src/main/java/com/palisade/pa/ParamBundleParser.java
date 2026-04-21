package com.palisade.pa;

import javacard.framework.ISOException;
import javacard.framework.Util;

/**
 * TLV parser for the ParamBundle (mirror of parseParamBundle() in
 * packages/emv/src/param-bundle-builder.ts).
 *
 * Wire format (flat TLV):
 *
 *   [tag(1)] [len(1 or 2)] [value(len bytes)] *
 *
 * Where len is:
 *   - Short form: single byte &lt; 0x80
 *   - Long form:  0x81 then one byte (128..255)
 *
 * Any other length prefix throws SW_PARAM_BUNDLE_INCOMPLETE — the
 * applet does not handle 0x82+ (per the TS-side MAX_FIELD_LEN=255
 * cap in param-bundle-builder.ts).
 *
 * The parser is index-based — it doesn't build an intermediate data
 * structure.  Callers request a specific tag via {@link #findTag}
 * which returns the offset into the plaintext buffer (or -1 if not
 * present).  This keeps the applet's heap allocations to zero — we
 * reuse the same plaintext buffer for the whole parse.
 */
public final class ParamBundleParser {

    private ParamBundleParser() { /* static only */ }

    /**
     * Required-tag list for MChip CVN 18 validation.  Hoisted out of
     * {@link #validateMChipCvn18} because inline `byte[] x = {...}`
     * literals inside a method body allocate a fresh EEPROM array on
     * every call in JavaCard 3.0.4 (no GC on JCOP 5 by default), which
     * slowly exhausts persistent memory.  Single static initialiser
     * here; the array lives for the applet's lifetime.
     */
    private static final byte[] MCHIP_CVN18_REQUIRED_TAGS = {
        Constants.PB_PAN,
        Constants.PB_PSN,
        Constants.PB_EXPIRY,
        Constants.PB_EFFECTIVE,
        Constants.PB_SERVICE_CODE,
        Constants.PB_AID,
        Constants.PB_MK_AC,
        Constants.PB_MK_SMI,
        Constants.PB_MK_SMC,
        Constants.PB_AIP,
        Constants.PB_AFL,
        Constants.PB_AUC,
        Constants.PB_IAC_DEFAULT,
        Constants.PB_IAC_DENIAL,
        Constants.PB_IAC_ONLINE,
        Constants.PB_CVM_LIST,
        Constants.PB_ICC_RSA_PRIV,
        Constants.PB_ICC_PK_CERT,
        Constants.PB_APP_VERSION,
        Constants.PB_CURRENCY_CODE,
        Constants.PB_CURRENCY_EXPONENT,
        Constants.PB_COUNTRY_CODE,
        Constants.PB_ICVV,
    };

    /**
     * Find the value of a tag inside a ParamBundle plaintext.
     *
     * @param buf       backing buffer holding the decrypted bundle bytes
     * @param bundleOff offset of the bundle's first byte within `buf`
     * @param bundleLen length of the bundle
     * @param tag       the 1-byte tag to look up
     * @param outOff    2-element short[] populated on hit with
     *                  [valueOff, valueLen].  Unchanged on miss.
     * @return true if the tag was found
     */
    public static boolean findTag(
        byte[] buf,
        short bundleOff,
        short bundleLen,
        byte tag,
        short[] outOff
    ) {
        short end = (short) (bundleOff + bundleLen);
        short pos = bundleOff;

        while (pos < end) {
            if ((short) (pos + 2) > end) {
                ISOException.throwIt(Constants.SW_PARAM_BUNDLE_INCOMPLETE);
            }
            byte curTag = buf[pos];
            pos += 1;

            byte lenByte = buf[pos];
            short len;
            if ((lenByte & 0x80) == 0) {
                // Short form — length in low 7 bits.
                len = (short) (lenByte & 0x7F);
                pos += 1;
            } else if (lenByte == (byte) 0x81) {
                // Long form 0x81 — one extra byte.
                if ((short) (pos + 2) > end) {
                    ISOException.throwIt(Constants.SW_PARAM_BUNDLE_INCOMPLETE);
                }
                len = (short) (buf[(short) (pos + 1)] & 0xFF);
                pos += 2;
            } else {
                // 0x82+ unsupported.
                ISOException.throwIt(Constants.SW_PARAM_BUNDLE_INCOMPLETE);
                return false; // unreachable
            }

            if ((short) (pos + len) > end) {
                ISOException.throwIt(Constants.SW_PARAM_BUNDLE_INCOMPLETE);
            }

            if (curTag == tag) {
                outOff[0] = pos;
                outOff[1] = len;
                return true;
            }

            pos += len;
        }

        return false;
    }

    /**
     * Read a tag value and assert its length matches the expected.
     * Throws SW_PARAM_BUNDLE_INCOMPLETE if the tag is missing or the
     * length is wrong.  Returns the offset of the tag's value.
     */
    public static short requireTagExact(
        byte[] buf,
        short bundleOff,
        short bundleLen,
        byte tag,
        short expectedLen,
        short[] scratch
    ) {
        if (!findTag(buf, bundleOff, bundleLen, tag, scratch)) {
            ISOException.throwIt(Constants.SW_PARAM_BUNDLE_INCOMPLETE);
        }
        if (scratch[1] != expectedLen) {
            ISOException.throwIt(Constants.SW_PARAM_BUNDLE_INCOMPLETE);
        }
        return scratch[0];
    }

    /**
     * Read a tag value with no length constraint.  Throws if the tag
     * is missing.  Returns the offset of the tag's value; caller
     * reads scratch[1] for the length.
     */
    public static short requireTag(
        byte[] buf,
        short bundleOff,
        short bundleLen,
        byte tag,
        short[] scratch
    ) {
        if (!findTag(buf, bundleOff, bundleLen, tag, scratch)) {
            ISOException.throwIt(Constants.SW_PARAM_BUNDLE_INCOMPLETE);
        }
        return scratch[0];
    }

    /**
     * Validate that a ParamBundle has all the tags PA v3 needs for
     * MChip CVN 18.  Called early in processTransferParams so we fail
     * fast before doing any NVM writes.
     *
     * @return SW_NO_ERROR (0x9000) on success, or a specific SW error
     *         code the caller should throw.  Returning vs throwing
     *         here because on-applet debugging is easier with explicit
     *         return paths.
     */
    public static short validateMChipCvn18(
        byte[] buf,
        short bundleOff,
        short bundleLen,
        short[] scratch
    ) {
        // Scheme must be MChip.
        if (!findTag(buf, bundleOff, bundleLen, Constants.PB_SCHEME, scratch)) {
            return Constants.SW_PARAM_BUNDLE_INCOMPLETE;
        }
        if (scratch[1] != (short) 1
            || buf[scratch[0]] != Constants.SCHEME_MCHIP) {
            return Constants.SW_PARAM_BUNDLE_UNSUPPORTED;
        }

        // CVN must be 18 (0x12) for prototype.  Future: accept 10/17 too.
        if (!findTag(buf, bundleOff, bundleLen, Constants.PB_CVN, scratch)) {
            return Constants.SW_PARAM_BUNDLE_INCOMPLETE;
        }
        if (scratch[1] != (short) 1
            || buf[scratch[0]] != Constants.CVN_MCHIP_18) {
            return Constants.SW_PARAM_BUNDLE_UNSUPPORTED;
        }

        // Check for required tags.  The validation list is the
        // authoritative "what does the applet need to build DGIs" —
        // keep in sync with scheme-mchip.ts's mapMChipToParamBundle
        // required-fields loop.
        for (short i = (short) 0; i < (short) MCHIP_CVN18_REQUIRED_TAGS.length; i++) {
            if (!findTag(buf, bundleOff, bundleLen, MCHIP_CVN18_REQUIRED_TAGS[i], scratch)) {
                return Constants.SW_PARAM_BUNDLE_INCOMPLETE;
            }
        }

        return (short) 0x9000;
    }
}
