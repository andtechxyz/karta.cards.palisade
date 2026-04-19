import { Router } from 'express';

// GET /api/capabilities — unauthenticated.  Shape parity with Vera admin's
// own /api/capabilities.  The shared admin SPA always asks Vera first, but
// if a caller ever points the SPA directly at Palisade, the probe still
// answers.  A Palisade deployment always claims hasVera=true because
// Palisade is useless without Vera (card.vaultToken points at Vera's vault).
const router: Router = Router();

router.get('/', (_req, res) => {
  res.json({
    hasVera: true,
    hasPalisade: true,
  });
});

export default router;
