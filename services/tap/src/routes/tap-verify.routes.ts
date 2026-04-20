import { Router, type Response } from 'express';
import { z } from 'zod';
import { prisma } from '@palisade/db';
import { badRequest, gone, notFound, unauthorized, validateBody } from '@palisade/core';
import { signHandoff } from '@palisade/handoff';
import { findCardByPicc } from '../sun/find-card.js';
import {
  deriveSessionKeys,
  extractSdmmacInput,
  verifySdmmac,
} from '../sun/index.js';
import { getTapConfig } from '../env.js';
import { getCardFieldKeyProvider } from '../key-provider.js';
import { getSdmDeriver } from '../sdm-deriver.js';
import { metrics } from '../metrics.js';

// Mobile-app facing entry point for cardRef-less SUN URLs.  Given the raw
// SUN params the chip emits — `?e=<picc-hex>&m=<mac-hex>` — verify the tap
// is authentic and (if so) mint a 30s `provisioning` handoff token the app
// can swap at /api/provisioning/start.
//
//   POST /api/tap/verify/:urlCode
//
// The urlCode comes from the chip's stored NDEF URL:
//   https://mobile.karta.cards/t/<urlCode>?e=<picc>&m=<cmac>
// The mobile app (apps/mobile/src/screens/tap/TapVerifyScreen.tsx) parses
// the path segment and POSTs it back to us; we use it to (a) scope trial-
// decrypt to one program, (b) reconstruct the MAC input to match exactly
// what the chip signed.
//
// Key derivation is O(N) per tap where N = cards in the program: the URL
// carries no cardRef, only the encrypted PICC, so find-card must trial-
// decrypt against each candidate's HSM-derived metaRead key (UID-in-URL is
// a hard-no for privacy).  See services/tap/src/sun/find-card.ts for the
// full trade-off analysis and scaling notes.
//
// Auth is the SUN signature itself — no Cognito.  Rate-limited upstream.

const HEX_32 = /^[0-9a-fA-F]{32}$/;
const HEX_16 = /^[0-9a-fA-F]{16}$/;

const verifySchema = z.object({
  e: z.string().regex(HEX_32, 'e must be 32 hex chars (encrypted PICC)'),
  m: z.string().regex(HEX_16, 'm must be 16 hex chars (truncated SDM MAC)'),
});

const URL_CODE_RE = /^[a-z0-9]{2,8}$/;

const router: Router = Router();

router.post('/verify/:urlCode', validateBody(verifySchema), async (req, res) => {
  const urlCode = req.params.urlCode;
  if (!URL_CODE_RE.test(urlCode)) {
    throw badRequest('invalid_url_code', 'urlCode must be 2-8 chars [a-z0-9]');
  }
  const { e: piccHex, m: macHex } = req.body as { e: string; m: string };

  // Resolve program first — narrows trial-decrypt scope, and lets us reject
  // unknown urlCodes upfront with a distinct error code.
  const program = await prisma.program.findUnique({
    where: { urlCode },
    select: { id: true, urlCode: true },
  });
  if (!program) {
    throw notFound('program_not_found', `No program with urlCode "${urlCode}"`);
  }

  await runVerify(res, {
    piccHex,
    macHex,
    programId: program.id,
    urlCode: program.urlCode!,
  });
});

// ---------------------------------------------------------------------------
// Shared body
// ---------------------------------------------------------------------------
interface RunVerifyInput {
  piccHex: string;
  macHex: string;
  programId: string;
  urlCode: string;
}

async function runVerify(
  res: Response,
  input: RunVerifyInput,
): Promise<void> {
  const kp = getCardFieldKeyProvider();
  const sdmDeriver = getSdmDeriver();
  const match = await findCardByPicc({
    programId: input.programId,
    piccHex: input.piccHex,
    keyProvider: kp,
    sdmDeriver,
  });
  if (!match) {
    metrics().counter('tap.verify.fail', 1, { reason: 'card_not_found' });
    throw notFound(
      'card_not_found',
      'No card decrypted the PICC bytes — wrong key, revoked card, or bogus tap',
    );
  }

  let valid = false;
  let macSessionKey: Buffer | null = null;
  try {
    // Reconstruct the exact URL the chip signed.  Per AN14683 the MAC
    // covers host+path through `&m=`; host+path is fixed to
    // `mobile.karta.cards/t/<urlCode>` by the program template.
    const fullUrl =
      `https://mobile.karta.cards/t/${input.urlCode}` +
      `?e=${input.piccHex.toUpperCase()}&m=${input.macHex.toUpperCase()}`;
    const macInput = extractSdmmacInput(fullUrl);
    ({ mac: macSessionKey } = deriveSessionKeys(
      match.sdmFileReadKey,
      match.uid,
      Buffer.from([
        match.counter & 0xff,
        (match.counter >> 8) & 0xff,
        (match.counter >> 16) & 0xff,
      ]),
    ));
    valid = verifySdmmac(macSessionKey, macInput, input.macHex);
  } finally {
    // Zero all plaintext key material + UID on the way out.  The UID is
    // stored only in encrypted form at rest and should not linger on the
    // heap for GC to eventually collect (PCI 3.3/3.5).  The derived
    // session MAC key is derived from the per-card file-read key and is
    // itself a tag-of-knowledge that proves access to the root — scrub it
    // too.
    match.sdmMetaReadKey.fill(0);
    match.sdmFileReadKey.fill(0);
    match.uid.fill(0);
    macSessionKey?.fill(0);
  }

  if (!valid) {
    metrics().counter('tap.verify.fail', 1, { reason: 'sun_invalid' });
    throw unauthorized('sun_invalid', 'SDMMAC mismatch — URL was tampered with');
  }

  // Atomic counter advance — replay defence.
  const advanceStart = Date.now();
  const advance = await prisma.card.updateMany({
    where: { id: match.cardId, lastReadCounter: { lt: match.counter } },
    data: { lastReadCounter: match.counter },
  });
  metrics().timing('tap.counter.advance', Date.now() - advanceStart);
  if (advance.count !== 1) {
    metrics().counter('tap.verify.fail', 1, { reason: 'sun_counter_replay' });
    throw gone(
      'sun_counter_replay',
      `Counter ${match.counter} not greater than stored ${match.lastReadCounter} (replay)`,
    );
  }
  metrics().counter('tap.verify.ok', 1);

  // Mint handoff IFF the card is in a state that allows provisioning.
  const config = getTapConfig();
  let handoff: string | null = null;
  let reason: string | null = null;
  if (match.cardStatus === 'ACTIVATED' || match.cardStatus === 'PROVISIONED') {
    handoff = signHandoff(
      {
        sub: match.cardId,
        purpose: 'provisioning',
        iss: 'tap',
        ttlSeconds: 30,
        ctx: { readCounter: match.counter },
      },
      config.TAP_HANDOFF_SECRET,
    );
  } else {
    reason = 'card_not_ready';
  }

  res.json({
    cardId: match.cardId,
    cardStatus: match.cardStatus,
    handoff,
    reason,
  });
}

export default router;
