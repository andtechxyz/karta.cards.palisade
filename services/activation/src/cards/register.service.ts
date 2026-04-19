import { CardStatus } from '@prisma/client';
import { prisma } from '@palisade/db';
import { encrypt, ApiError, conflict, internal } from '@palisade/core';
import { createVaultClient, VaultClientError, type VaultClient } from '@palisade/vault-client';
import { createProvisioningClient, ProvisioningClientError, type ProvisioningClient } from '@palisade/provisioning-client';
import { getActivationConfig } from '../env.js';
import { fingerprintUid } from './fingerprint.js';
import { getCardFieldKeyProvider } from './key-provider.js';

// Card registration — entry point for Palisade's provisioning-agent.
// Lands a Card in SHIPPED with a linked VaultEntry; first cardholder
// SUN-tap (separate flow) flips it to ACTIVATED and registers the passkey.
//
// PANs go over HTTP to the vault service (never persisted directly from
// activation).  UID + SDM keys are still encrypted inline — those are part of
// the Card row, not the VaultEntry, and vault-service doesn't own them.
// Audit attribution on the vault side comes from the HMAC keyId ('activation');
// this service does not self-report an actor.

export interface RegisterCardInput {
  cardRef: string;
  uid: string;
  chipSerial?: string;
  sdmMetaReadKey: string;
  sdmFileReadKey: string;
  programId?: string;
  batchId?: string;
  card: {
    pan: string;
    cvc?: string;
    expiryMonth: string;
    expiryYear: string;
    cardholderName: string;
  };
  ip?: string;
  ua?: string;
}

export interface RegisterCardResult {
  cardId: string;
  cardRef: string;
  status: CardStatus;
  vaultToken: string;
  panLast4: string;
}

// Lazy singleton — resolved on first call so tests can override env before import.
let vaultClient: VaultClient | null = null;
function getVaultClient(): VaultClient {
  if (!vaultClient) {
    const config = getActivationConfig();
    vaultClient = createVaultClient(config.VAULT_SERVICE_URL, {
      keyId: 'activation',
      secret: config.SERVICE_AUTH_ACTIVATION_SECRET,
    });
  }
  return vaultClient;
}

/** Test hook — swap the vault client (or reset to env-derived default). */
export function _setVaultClient(client: VaultClient | null): void {
  vaultClient = client;
}

// Lazy singleton — same pattern as vaultClient above.
let provisioningClient: ProvisioningClient | null = null;
function getProvisioningClient(): ProvisioningClient {
  if (!provisioningClient) {
    const config = getActivationConfig();
    provisioningClient = createProvisioningClient(config.DATA_PREP_SERVICE_URL, {
      keyId: 'activation',
      secret: config.SERVICE_AUTH_PROVISIONING_SECRET,
    });
  }
  return provisioningClient;
}

export async function registerCard(input: RegisterCardInput): Promise<RegisterCardResult> {
  const uidNormalised = input.uid.toLowerCase();
  const uidFingerprint = fingerprintUid(uidNormalised);

  const [byRef, byUid] = await Promise.all([
    prisma.card.findUnique({ where: { cardRef: input.cardRef }, select: { id: true } }),
    prisma.card.findUnique({ where: { uidFingerprint }, select: { id: true } }),
  ]);
  if (byRef) throw conflict('card_ref_taken', 'cardRef already registered');
  if (byUid) throw conflict('card_uid_taken', 'A card with this UID is already registered');

  // Retail programs ship cards to retailers in an inactive state — the tap
  // flow routes to info-only until the card is marked SOLD.  All other
  // programs leave retailSaleStatus NULL (activation works on first tap).
  let retailSaleStatus: 'SHIPPED' | null = null;
  if (input.programId) {
    const prog = await prisma.program.findUnique({
      where: { id: input.programId },
      select: { programType: true },
    });
    if (prog?.programType === 'RETAIL') retailSaleStatus = 'SHIPPED';
  }

  // Encrypt BEFORE the vault call so a key-version drift fails fast without
  // creating an orphaned VaultEntry we can't link a Card to.  These fields
  // live under the card-field DEK (distinct from vault's PAN DEK).
  const cardFieldKp = getCardFieldKeyProvider();
  const uidEnc = encrypt(uidNormalised, cardFieldKp);
  const metaKeyEnc = encrypt(input.sdmMetaReadKey.toLowerCase(), cardFieldKp);
  const fileKeyEnc = encrypt(input.sdmFileReadKey.toLowerCase(), cardFieldKp);
  if (
    uidEnc.keyVersion !== metaKeyEnc.keyVersion ||
    metaKeyEnc.keyVersion !== fileKeyEnc.keyVersion
  ) {
    throw internal('vault_key_drift', 'vault key version drift mid-call');
  }

  let vaulted;
  try {
    // cardRef as the idempotency key — already unique per Card row.  Retries
    // of registerCard for the same cardRef converge on the same vaultToken
    // without creating a duplicate vault entry.
    vaulted = await getVaultClient().registerCard({
      pan: input.card.pan,
      cvc: input.card.cvc,
      expiryMonth: input.card.expiryMonth,
      expiryYear: input.card.expiryYear,
      cardholderName: input.card.cardholderName,
      idempotencyKey: input.cardRef,
      ip: input.ip,
      ua: input.ua,
    });
  } catch (err) {
    if (err instanceof VaultClientError) {
      // Preserve the vault's HTTP status so the caller sees the real failure
      // mode (409 duplicate, 400 validation, 500 internal, etc.) rather than
      // having everything flattened to 409.
      throw new ApiError(err.status, err.code, err.message);
    }
    throw err;
  }

  const panBin = input.card.pan.replace(/[\s-]/g, '').slice(0, 6);
  const expYear =
    input.card.expiryYear.length === 4
      ? input.card.expiryYear.slice(2)
      : input.card.expiryYear;

  const card = await prisma.card.create({
    data: {
      cardRef: input.cardRef,
      status: CardStatus.SHIPPED,
      uidEncrypted: uidEnc.ciphertext,
      uidFingerprint,
      chipSerial: input.chipSerial,
      sdmMetaReadKeyEncrypted: metaKeyEnc.ciphertext,
      sdmFileReadKeyEncrypted: fileKeyEnc.ciphertext,
      keyVersion: uidEnc.keyVersion,
      programId: input.programId,
      batchId: input.batchId,
      vaultToken: vaulted.vaultToken,
      panLast4: vaulted.panLast4,
      panBin,
      cardholderName: input.card.cardholderName,
      panExpiryMonth: input.card.expiryMonth,
      panExpiryYear: expYear,
      retailSaleStatus,
    },
    select: { id: true, cardRef: true, status: true },
  });

  // Stage SAD for provisioning (non-blocking — registration succeeds even if data-prep is down)
  if (input.programId) {
    try {
      const sadResult = await getProvisioningClient().prepareSad({
        cardId: card.id,
        pan: input.card.pan,
        expiryYymm: input.card.expiryYear.slice(-2) + input.card.expiryMonth.padStart(2, '0'),
        programId: input.programId,
        chipSerial: input.chipSerial,
      });
      await prisma.card.update({
        where: { id: card.id },
        data: { proxyCardId: sadResult.proxyCardId },
      });
    } catch (err) {
      console.warn(`[activation] SAD staging failed for card ${card.cardRef}:`, err instanceof ProvisioningClientError ? err.message : err);
    }
  }

  return {
    cardId: card.id,
    cardRef: card.cardRef,
    status: card.status,
    vaultToken: vaulted.vaultToken,
    panLast4: vaulted.panLast4,
  };
}
