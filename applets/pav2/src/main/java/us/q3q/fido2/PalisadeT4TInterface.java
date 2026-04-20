/*
 * Shareable Interface for PalisadeT4T — called by FIDO2Applet during WebAuthn.
 *
 * Must be in the same package (us.q3q.fido2) as FIDO2Applet for SIO to work
 * without cross-package issues on JCOP 5.
 */
package us.q3q.fido2;

import javacard.framework.Shareable;

public interface PalisadeT4TInterface extends Shareable {

    /**
     * Update the base URL stored in the T4T applet's EEPROM.
     * Called by FIDO2Applet after successful makeCredential when the RP ID
     * contains the trigger substring.
     *
     * Sets card state to ACTIVATED. Subsequent NDEF reads will generate
     * SUN parameters appended to this new URL on every tap (no more
     * odd/even suppression).
     *
     * @param url buffer containing the new URL bytes (ASCII, no scheme prefix)
     * @param off offset into the buffer
     * @param len length of the URL
     */
    void setUrl(byte[] url, short off, short len);

    /**
     * Update the base URL with CMAC authentication.
     *
     * The buffer contains: url(N) + cmac(16). T4T computes AES-CMAC(MAC_KEY, url)
     * and compares it with the provided CMAC. If the CMAC matches, the URL is
     * stored and the card is activated. If not, the operation is rejected with
     * SW_SECURITY_STATUS_NOT_SATISFIED.
     *
     * This prevents URL injection: only the backend (which holds MAC_KEY via
     * AWS PC) can produce a valid CMAC. Compromised JavaScript or NFC relay
     * attacks cannot forge it.
     *
     * Called by FIDO2Applet during U2F Authenticate when the key handle carries
     * appended URL + CMAC bytes from the backend's authenticate-options response.
     *
     * @param buf buffer containing url(N) + cmac(16)
     * @param off offset into the buffer
     * @param len total length (url + cmac; url length = len - 16)
     */
    void setUrlWithMac(byte[] buf, short off, short len);

    /**
     * Activate the card without changing the URL.
     * Called by FIDO2Applet after successful U2F Authenticate (getAssertion)
     * over NFC, where the RP ID is only available as a hash.
     *
     * Sets card state from BLANK to ACTIVATED. No-op if already activated.
     */
    void activate();

    /**
     * Get the current card activation state.
     *
     * @return 0x00 = BLANK (not yet activated), 0x01 = ACTIVATED
     */
    byte getCardState();

    /**
     * Force the counter to an odd value so the next NDEF read serves
     * a full SUN URL instead of empty NDEF.
     *
     * Use case: FIDO2 ceremony failed, card is on an even counter,
     * and the user needs a fresh SUN URL without wasting a tap.
     * FIDO2Applet can call this before returning the error.
     */
    void forceSunOnNextRead();
}
