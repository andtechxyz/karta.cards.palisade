/**
 * Logging redaction helpers.
 *
 * Cuid-style session IDs (25-char) are not secret by themselves but
 * combined with a leaked WS token they give full auth against RCA /
 * card-ops.  PCI 10.5.4 + audit S-4: log only enough to correlate,
 * not enough to replay.
 */

/**
 * Reduce a session ID (or any opaque token) to a `first4...last4`
 * sample for logs.  Keeps log correlation via prefix match while
 * limiting exposure if a log stream is scraped.
 *
 * For strings shorter than 10 characters returns the input unchanged
 * (no redaction value; shorter strings are typically not secrets).
 */
export function redactSid(sid: string | null | undefined): string {
  if (!sid) return '<none>';
  if (sid.length < 10) return sid;
  return `${sid.slice(0, 4)}...${sid.slice(-4)}`;
}
