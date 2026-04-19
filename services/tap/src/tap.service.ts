import { prisma } from '@palisade/db';
import { decrypt, badRequest, notFound, gone, unauthorized } from '@palisade/core';
import { signHandoff, type HandoffPayload } from '@palisade/handoff';
import { verifySunUrl, type SunVerificationResult } from './sun/index.js';
import { getTapConfig } from './env.js';
import { getCardFieldKeyProvider } from './key-provider.js';

// SUN-tap handler — invoked by the cardholder's phone after the card emits
// its NDEF URL.  Verifies the SUN signature, advances the monotonic read
// counter atomically (replay defence), and mints a short-lived signed handoff
// token that the activation service can verify without a shared session store.
//
// The handoff token IS the opaque bearer redirected to the activation frontend
// (`/activate#hand=<token>`).  Fragment so Cloudflare logs don't capture it.

export type HandoffPurpose = HandoffPayload['purpose'];

export interface HandleSunTapInput {
  cardRef: string;
  /** Full URL the card emitted (scheme + host + path + query). */
  fullUrl: string;
  ip?: string;
  ua?: string;
  /**
   * Purpose of the minted handoff token.
   *   - 'activation'   (default) — default SUN-tap verify → activation flow.
   *     If the card is already ACTIVATED the handler still falls back to
   *     'provisioning' for backwards-compatibility with the /activate URL
   *     baked into in-field cards.
   *   - 'provisioning' — post-activation /tap/:cardRef route; mints a token
   *     the mobile app can exchange at activation's /api/provisioning/start.
   *   - 'payment'      — post-provisioning tap for payment initiation.
   */
  purpose?: HandoffPurpose;
}

export interface HandleSunTapResult {
  /** Signed handoff token — 30 second TTL. */
  handoffToken: string;
  /** Current card status — lets the route handler pick the right redirect. */
  cardStatus:
    | 'BLANK'
    | 'SHIPPED'
    | 'PERSONALISED'
    | 'ACTIVATED'
    | 'PROVISIONED'
    | 'SUSPENDED'
    | 'REVOKED';
}

export async function handleSunTap(input: HandleSunTapInput): Promise<HandleSunTapResult> {
  const card = await prisma.card.findUnique({
    where: { cardRef: input.cardRef },
    select: {
      id: true,
      status: true,
      lastReadCounter: true,
      uidEncrypted: true,
      sdmMetaReadKeyEncrypted: true,
      sdmFileReadKeyEncrypted: true,
      keyVersion: true,
    },
  });
  if (!card) throw notFound('card_not_found', 'Unknown cardRef');
  if (card.status === 'REVOKED' || card.status === 'SUSPENDED') {
    throw unauthorized('card_disabled', `Card is ${card.status}`);
  }

  const cardFieldKp = getCardFieldKeyProvider();
  const sdmMetaReadKey = Buffer.from(
    decrypt({ ciphertext: card.sdmMetaReadKeyEncrypted, keyVersion: card.keyVersion }, cardFieldKp),
    'hex',
  );
  const sdmFileReadKey = Buffer.from(
    decrypt({ ciphertext: card.sdmFileReadKeyEncrypted, keyVersion: card.keyVersion }, cardFieldKp),
    'hex',
  );

  let result: SunVerificationResult;
  try {
    result = verifySunUrl({
      url: input.fullUrl,
      sdmMetaReadKey,
      sdmFileReadKey,
    });
  } finally {
    sdmMetaReadKey.fill(0);
    sdmFileReadKey.fill(0);
  }

  if (!result.valid) {
    throw badRequest('sun_invalid', `SUN verification failed: ${result.errors.join('; ')}`);
  }

  // Atomic counter advance — only succeeds if the new counter is strictly
  // greater than the stored one.  Replay or out-of-order tap → count === 0.
  const advance = await prisma.card.updateMany({
    where: { id: card.id, lastReadCounter: { lt: result.counter } },
    data: { lastReadCounter: result.counter },
  });
  if (advance.count !== 1) {
    throw gone(
      'sun_counter_replay',
      `Counter ${result.counter} is not greater than stored ${card.lastReadCounter} (replay or stale tap)`,
    );
  }

  const config = getTapConfig();

  // Purpose resolution:
  //   - If the caller explicitly passes a purpose, honour it verbatim.  The
  //     post-activation /tap/:cardRef route uses this to always mint
  //     'provisioning' tokens regardless of card state.
  //   - Otherwise (legacy /activate URL baked into in-field cards), derive
  //     purpose from card.status: ACTIVATED cards get a provisioning token
  //     because their next action is mobile provisioning, all other states
  //     get an activation token.
  const purpose: HandoffPurpose =
    input.purpose ?? (card.status === 'ACTIVATED' ? 'provisioning' : 'activation');

  const handoffToken = signHandoff(
    {
      sub: card.id,
      purpose,
      iss: 'tap',
      ttlSeconds: 30,
      ctx: { readCounter: result.counter },
    },
    config.TAP_HANDOFF_SECRET,
  );

  return { handoffToken, cardStatus: card.status };
}
