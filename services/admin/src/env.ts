import { defineEnv, baseEnvShape, hexKey, originList } from '@palisade/core';
import { z } from 'zod';

// Admin service handles program CRUD, card admin, embossing, microsites,
// partner credentials/ingestion, and provisioning monitoring.  Vault + pay
// proxying stays on Vera's side of the split (Vera owns vault + tx data).
const { get: getAdminConfig, reset: _resetAdminConfig } = defineEnv({
  ...baseEnvShape,
  CORS_ORIGINS: originList,
  // 3009 (not 3005) so Palisade admin and Vera admin can both run on the
  // same dev box.  The shared admin SPA's Vite proxy targets 3009 for the
  // /palisade-api/* path prefix; 3009 also keeps clear of Palisade's
  // existing data-prep (3006), rca (3007), and batch-processor (3008).
  PORT: z.coerce.number().int().positive().default(3009),
  WEBAUTHN_ORIGIN: z.string().url().default('https://manage.karta.cards'),
  // Activation leg — batch CSV ingestion HMAC-signs calls to
  // activation's /api/cards/register as keyId='admin'.
  ACTIVATION_SERVICE_URL: z.string().url().default('http://localhost:3002'),
  SERVICE_AUTH_ADMIN_SECRET: hexKey(32),
  // Cognito — browser-facing auth.  MFA enforced at the pool level;
  // 'admin' group membership gates access at the middleware level.
  COGNITO_USER_POOL_ID: z.string().default('ap-southeast-2_Db4d1vpIV'),
  COGNITO_CLIENT_ID: z.string().default('7pj9230obhsa6h6vrvk9tru7do'),
  // --- Microsites ---------------------------------------------------------
  // S3 bucket that backs microsite.karta.cards (served via CloudFront OAC).
  // Admin uploads zips here; the CDN rewrites /programs/<id>/... to the
  // currently-active MicrositeVersion's S3 prefix.
  MICROSITE_BUCKET: z.string().default('karta-microsites-600743178530'),
  MICROSITE_CDN_URL: z.string().url().default('https://microsite.karta.cards'),
  // --- Embossing ----------------------------------------------------------
  // S3 bucket storing encrypted raw embossing batch files (SSE-KMS) and the
  // AES-256-GCM DEK for per-FI template-file encryption at rest in the DB.
  EMBOSSING_BUCKET: z.string().default('karta-embossing-files-600743178530'),
  EMBOSSING_KMS_KEY_ARN: z.string().default(''),
  EMBOSSING_KEY_V1: hexKey(32).default('0'.repeat(64)),
  EMBOSSING_KEY_ACTIVE_VERSION: z.coerce.number().int().positive().default(1),
});

export { getAdminConfig, _resetAdminConfig };
