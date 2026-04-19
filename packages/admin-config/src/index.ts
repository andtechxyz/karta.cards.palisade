/**
 * @palisade/admin-config — shared admin allowlist.
 *
 * A single source of truth for the list of Cognito-authenticated users
 * permitted to drive admin-only card operations (install/wipe/reset).
 * The mobile app (build-time) and server-side (runtime) both read the
 * same env var so a single ops change propagates everywhere.
 *
 * Env var:
 *   ADMIN_EMAIL_ALLOWLIST  (CSV, case-insensitive)
 *     e.g. "alice@karta.cards,bob@karta.cards"
 *
 * Empty / unset → empty list.  Callers MUST treat an empty list as
 * "no admins configured"; server-side routes should reject all traffic
 * in that state rather than silently allowing everyone through.
 */

function parseCsv(raw: string | undefined): string[] {
  if (!raw) return [];
  return raw
    .split(',')
    .map((s) => s.trim().toLowerCase())
    .filter((s) => s.length > 0);
}

/**
 * Read the current allowlist from `process.env.ADMIN_EMAIL_ALLOWLIST`.
 *
 * Evaluated lazily (on each call) so tests can flip the env between cases
 * without restarting the host process.  The cost is negligible — parsing
 * a short CSV on every auth check is cheap vs. the JWT verify that
 * immediately precedes it.
 */
export function getAdminEmails(): string[] {
  return parseCsv(process.env.ADMIN_EMAIL_ALLOWLIST);
}

/**
 * Lowercased snapshot at module load — convenient for static contexts
 * (e.g. middleware factories that build a closure once).  Prefer
 * `getAdminEmails()` when the caller may run before the env is fully
 * populated or in long-lived processes where ops may flip the env.
 */
export const ADMIN_EMAILS: readonly string[] = Object.freeze(
  parseCsv(process.env.ADMIN_EMAIL_ALLOWLIST),
);

/** Case-insensitive membership test. */
export function isAdminEmail(email: string | undefined | null): boolean {
  if (!email) return false;
  const list = getAdminEmails();
  if (list.length === 0) return false;
  return list.includes(email.toLowerCase());
}
