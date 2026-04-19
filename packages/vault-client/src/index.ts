import { request } from 'undici';
import { signRequest } from '@palisade/service-auth';

// -----------------------------------------------------------------------------
// @palisade/vault-client — typed HTTP client for the vault service.
//
// Pay and activation import this instead of calling vault internals directly.
// Every request is HMAC-signed with the caller's keyId + shared secret; the
// vault service rejects anything unsigned, tampered, or outside the replay
// window (PCI-DSS 7.1/7.2/8.2).
// -----------------------------------------------------------------------------

// Every request carries the caller identity implicitly via the HMAC `keyId`
// on the signed-request envelope — the vault records that as the VaultAccessLog
// actor, so the body never carries a self-reported `actor`.  Only `purpose`
// (free-form context) travels in the body.

export interface StoreCardInput {
  pan: string;
  cvc?: string;
  expiryMonth: string;
  expiryYear: string;
  cardholderName: string;
  purpose: string;
  /** If set, vault links the new VaultEntry onto this Card row atomically. */
  cardId?: string;
  onDuplicate?: 'error' | 'reuse';
  ip?: string;
  ua?: string;
}

export interface StoreCardResult {
  vaultEntryId: string;
  panLast4: string;
  deduped: boolean;
}

// Palisade's preferred entry point post-split: the vault returns an opaque
// `vaultToken` we persist on Card.vaultToken.  No FK back into Vera.
// `idempotencyKey` is caller-supplied (we pass `cardRef`) so retries collapse
// onto the same token.  Vera runs fingerprint dedup underneath — two cards
// with the same PAN converge on one vaultToken.
export interface RegisterCardInput {
  pan: string;
  cvc?: string;
  expiryMonth: string;
  expiryYear: string;
  cardholderName: string;
  idempotencyKey: string;
  ip?: string;
  ua?: string;
}

export interface RegisterCardResult {
  vaultToken: string;
  panLast4: string;
}

export interface MintTokenInput {
  vaultEntryId: string;
  amount: number;
  currency: string;
  purpose: string;
  transactionId?: string;
  ip?: string;
  ua?: string;
}

export interface MintTokenResult {
  token: string;
  retrievalTokenId: string;
  expiresAt: string;
}

export interface ConsumeTokenInput {
  token: string;
  expectedAmount: number;
  expectedCurrency: string;
  purpose: string;
  transactionId?: string;
  ip?: string;
  ua?: string;
}

export interface DecryptedCard {
  pan: string;
  cvc?: string;
  expMonth: string;
  expYear: string;
  cardholderName: string | null;
  last4: string;
  bin: string;
}

export interface ConsumeTokenResult {
  retrievalTokenId: string;
  vaultEntryId: string;
  card: DecryptedCard;
}

export interface ProxyInput {
  retrievalToken: string;
  destination: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  expectedAmount: number;
  expectedCurrency: string;
  purpose: string;
  transactionId?: string;
  ip?: string;
  ua?: string;
}

export interface ProxyResult {
  status: number;
  responseHeaders: Record<string, string>;
  responseBody: string;
}

export class VaultClientError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'VaultClientError';
  }
}

export interface VaultClientOptions {
  /** This service's caller identity on the vault (e.g. 'pay', 'activation'). */
  keyId: string;
  /** 32-byte hex secret shared with the vault's SERVICE_AUTH_KEYS[keyId]. */
  secret: string;
}

async function sendSigned<T>(
  baseUrl: string,
  pathAndQuery: string,
  method: string,
  bodyBytes: Buffer,
  auth: VaultClientOptions,
): Promise<T> {
  const url = `${baseUrl.replace(/\/$/, '')}${pathAndQuery}`;
  const authorization = signRequest({
    method,
    pathAndQuery,
    body: bodyBytes,
    keyId: auth.keyId,
    secret: auth.secret,
  });
  // content-type is only meaningful when we're sending a body; GET paths omit
  // it so the vault doesn't try to JSON-parse an empty buffer.
  const headers: Record<string, string> = { authorization };
  if (bodyBytes.length > 0) headers['content-type'] = 'application/json';
  const { statusCode, body: responseBody } = await request(url, {
    method,
    headers,
    body: bodyBytes.length > 0 ? bodyBytes : undefined,
  });
  const text = await responseBody.text();
  if (statusCode >= 400) {
    let code = 'vault_error';
    let message = `Vault service returned ${statusCode}`;
    try {
      const parsed = JSON.parse(text) as { error?: { code?: string; message?: string } };
      if (parsed.error?.code) code = parsed.error.code;
      if (parsed.error?.message) message = parsed.error.message;
    } catch {
      // non-JSON error body
    }
    throw new VaultClientError(statusCode, code, message);
  }
  return JSON.parse(text) as T;
}

function vaultPost<T>(
  baseUrl: string,
  path: string,
  body: unknown,
  auth: VaultClientOptions,
): Promise<T> {
  return sendSigned<T>(baseUrl, path, 'POST', Buffer.from(JSON.stringify(body), 'utf8'), auth);
}

function vaultGet<T>(
  baseUrl: string,
  pathAndQuery: string,
  auth: VaultClientOptions,
): Promise<T> {
  return sendSigned<T>(baseUrl, pathAndQuery, 'GET', Buffer.alloc(0), auth);
}

// --- List endpoints (admin-only, read-only) ---------------------------------

export interface ListCardRow {
  id: string;
  cardRef: string;
  status: string;
  retailSaleStatus: string | null;
  retailSoldAt: string | null;
  chipSerial: string | null;
  programId: string | null;
  program: { id: string; name: string; currency: string; programType: string } | null;
  batchId: string | null;
  createdAt: string;
  updatedAt: string;
  vaultEntry: { id: string; panLast4: string; panBin: string; cardholderName: string | null } | null;
  credentials: { id: string; kind: string; deviceName: string | null; createdAt: string; lastUsedAt: string | null }[];
  activationSessions: {
    id: string;
    expiresAt: string;
    consumedAt: string | null;
    consumedDeviceLabel: string | null;
    createdAt: string;
  }[];
}

export interface ListAuditRow {
  id: string;
  eventType: string;
  result: 'SUCCESS' | 'FAILURE';
  actor: string;
  purpose: string;
  createdAt: string;
  errorMessage: string | null;
  vaultEntry: { panLast4: string; panBin: string; cardholderName: string | null } | null;
}

export interface ListAuditInput {
  limit?: number;
  offset?: number;
}

export function createVaultClient(baseUrl: string, auth: VaultClientOptions) {
  return {
    /** Vault a PAN.  The verified caller identity (HMAC keyId) is the audit actor. */
    async storeCard(input: StoreCardInput): Promise<StoreCardResult> {
      return vaultPost<StoreCardResult>(baseUrl, '/api/vault/store', input, auth);
    },

    /**
     * Register a PAN at card-issue time and receive an opaque vaultToken.
     * Idempotent on `idempotencyKey` — retries return the same token without
     * creating a duplicate entry.  This is the cross-service boundary: Vera
     * does not know about Palisade's Card rows.
     */
    async registerCard(input: RegisterCardInput): Promise<RegisterCardResult> {
      return vaultPost<RegisterCardResult>(baseUrl, '/api/vault/register', input, auth);
    },

    /** Mint a single-use retrieval token for a vaulted entry. */
    async mintToken(input: MintTokenInput): Promise<MintTokenResult> {
      return vaultPost<MintTokenResult>(baseUrl, '/api/vault/tokens/mint', input, auth);
    },

    /** Atomically consume a retrieval token and return decrypted card data. */
    async consumeToken(input: ConsumeTokenInput): Promise<ConsumeTokenResult> {
      return vaultPost<ConsumeTokenResult>(baseUrl, '/api/vault/tokens/consume', input, auth);
    },

    /** Forward a request through the vault proxy (PAN substitution). */
    async proxy(input: ProxyInput): Promise<ProxyResult> {
      return vaultPost<ProxyResult>(baseUrl, '/api/vault/proxy', input, auth);
    },

    /** Admin read: full card list with vault + credential + activation state. */
    async listCards(): Promise<ListCardRow[]> {
      return vaultGet<ListCardRow[]>(baseUrl, '/api/vault/cards', auth);
    },

    /** Admin read: vault audit log tail. */
    async listAudit(input: ListAuditInput = {}): Promise<ListAuditRow[]> {
      const params = new URLSearchParams();
      if (input.limit !== undefined) params.set('limit', String(input.limit));
      if (input.offset !== undefined) params.set('offset', String(input.offset));
      const qs = params.toString();
      return vaultGet<ListAuditRow[]>(baseUrl, `/api/vault/audit${qs ? `?${qs}` : ''}`, auth);
    },
  };
}

export type VaultClient = ReturnType<typeof createVaultClient>;
