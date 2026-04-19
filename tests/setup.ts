// Vitest global setup.  Provides deterministic env defaults so getConfig()
// validates and crypto-keyed helpers produce stable outputs across runs.
//
// Tests that need a different config can override process.env and call
// _resetConfigCache() before exercising the SUT.

// Distinct hex constants per key so a test that leaks across keyspaces fails
// loudly instead of silently passing because two services share a secret.
const HEX32_A = '0'.repeat(64);
const HEX32_B = '1'.repeat(64);
const HEX32_C = '2'.repeat(64);
const HEX32_D = '3'.repeat(64);
const HEX32_E = '4'.repeat(64);
const HEX32_F = '5'.repeat(64);
const HEX32_G = '6'.repeat(64);
const HEX32_H = '7'.repeat(64);
const HEX32_I = '8'.repeat(64);
const HEX32_J = '9'.repeat(64);

const defaults: Record<string, string> = {
  NODE_ENV: 'test',
  // DATABASE_URL is required by the schema but unit tests never connect.
  DATABASE_URL: 'postgresql://test:test@localhost:5432/vera_test?schema=public',
  WEBAUTHN_RP_ID: 'pay.karta.cards',
  WEBAUTHN_ORIGIN: 'https://pay.karta.cards',
  WEBAUTHN_ORIGINS: 'https://pay.karta.cards,https://tap.karta.cards,https://activation.karta.cards,https://manage.karta.cards,https://vault.karta.cards',
  WEBAUTHN_RP_NAME: 'Palisade Pay',
  // Vault PAN keyspace (vault service only).
  VAULT_PAN_DEK_V1: HEX32_A,
  VAULT_PAN_DEK_ACTIVE_VERSION: '1',
  VAULT_PAN_FINGERPRINT_KEY: HEX32_B,
  // Card-field keyspace (activation + tap).
  CARD_FIELD_DEK_V1: HEX32_D,
  CARD_FIELD_DEK_ACTIVE_VERSION: '1',
  CARD_UID_FINGERPRINT_KEY: HEX32_E,
  VERA_ROOT_ARQC_SEED: HEX32_C,
  PAYMENT_PROVIDER: 'mock',
  TRANSACTION_TTL_SECONDS: '300',
  RETRIEVAL_TOKEN_TTL_SECONDS: '60',
  // Tap / handoff service
  TAP_HANDOFF_SECRET: HEX32_A,
  ACTIVATION_URL: 'https://activation.karta.cards',
  // Service URLs
  PAY_URL: 'https://pay.karta.cards',
  VAULT_SERVICE_URL: 'http://localhost:3004',
  // Service-to-service HMAC — distinct secret per caller; vault's map must
  // carry the same values under each caller's keyId.
  SERVICE_AUTH_PAY_SECRET: HEX32_F,
  SERVICE_AUTH_ACTIVATION_SECRET: HEX32_G,
  SERVICE_AUTH_ADMIN_SECRET: HEX32_H,
  SERVICE_AUTH_KEYS: JSON.stringify({ pay: HEX32_F, activation: HEX32_G, admin: HEX32_H }),
  // Provisioning-agent HMAC keys (activation inbound).
  PROVISION_AUTH_KEYS: JSON.stringify({ 'provision-agent': HEX32_I }),
  // Admin browser-facing auth — must differ from PROVISION_AUTH_KEYS to catch
  // accidental key-swap bugs.
  ADMIN_API_KEY: HEX32_J,
  // Admin proxy to pay service (admin UI's transaction tab)
  PAY_SERVICE_URL: 'http://localhost:3003',
  PAY_ADMIN_API_KEY: HEX32_J,
  // CORS — all test origins.
  CORS_ORIGINS: 'https://pay.karta.cards,https://activation.karta.cards,https://manage.karta.cards',
  // data-prep UDK backend — default to the mock backend for unit tests.
  // Individual tests that want real EMV Method A swap to the 'local' backend
  // (DEV_UDK_ROOT_SEED below) before constructing EmvDerivationService.
  DATA_PREP_UDK_BACKEND: 'mock',
  DEV_UDK_ROOT_SEED: HEX32_A,
};

for (const [k, v] of Object.entries(defaults)) {
  if (process.env[k] === undefined) process.env[k] = v;
}
