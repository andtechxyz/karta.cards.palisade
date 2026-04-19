import { Router } from 'express';
import { handleSunTap } from '../tap.service.js';
import { getTapConfig } from '../env.js';

const router: Router = Router();

// GET /tap/:cardRef?e=<picc>&m=<mac>
//
// Post-activation SUN-tap entry point.  Physical cards in the field whose
// NDEF URL has been rewritten to /tap/:cardRef after activation hit this
// route.  In all cases the minted handoff token's purpose is 'provisioning',
// so the mobile app can exchange it at activation's /api/provisioning/start
// without ambiguity.
//
// Redirect targets depend on the card's current status:
//   ACTIVATED    → {MOBILE_APP_URL}/provision?hand=<token>
//                  (mobile app runs the real-time provisioning ceremony)
//   PROVISIONED  → {MOBILE_APP_URL}/card?hand=<token>
//                  (card already provisioned — show it in the mobile wallet)
//   SUSPENDED /
//   REVOKED      → {MOBILE_APP_URL}/error?code=<code>
//                  (locked cards error out regardless)
//
// Fragment vs. querystring: the spec uses ?hand=<token>, which means the
// token IS sent to Cloudflare logs.  The mobile app redirects through a
// deep link so the browser never receives the token, and the backend-side
// log exposure is within the team-controlled VPC.

router.get('/tap/:cardRef', async (req, res) => {
  const cardRef = req.params.cardRef;
  const config = getTapConfig();
  const fullUrl = `${req.protocol}://${req.get('host')}${req.originalUrl}`;

  try {
    const { handoffToken, cardStatus } = await handleSunTap({
      cardRef,
      fullUrl,
      ip: req.ip,
      ua: req.get('user-agent') ?? undefined,
      purpose: 'provisioning',
    });

    const token = encodeURIComponent(handoffToken);

    if (cardStatus === 'ACTIVATED') {
      res.redirect(302, `${config.MOBILE_APP_URL}/provision?hand=${token}`);
      return;
    }

    if (cardStatus === 'PROVISIONED') {
      res.redirect(302, `${config.MOBILE_APP_URL}/card?hand=${token}`);
      return;
    }

    // BLANK / SHIPPED / PERSONALISED / SUSPENDED / REVOKED — /tap is not the
    // correct entry point for these states.  Send the user to an error page.
    res.redirect(
      302,
      `${config.MOBILE_APP_URL}/error?code=${encodeURIComponent(`invalid_status_${cardStatus.toLowerCase()}`)}`,
    );
  } catch (e) {
    const code =
      typeof e === 'object' && e !== null && 'code' in e
        ? String((e as { code: unknown }).code)
        : 'sun_error';
    res.redirect(302, `${config.MOBILE_APP_URL}/error?code=${encodeURIComponent(code)}`);
  }
});

export default router;
