/**
 * @palisade/provisioning-client — typed HMAC-signed HTTP client for the data-prep service.
 *
 * Activation and admin services import this to stage SAD, retrieve SAD, and
 * revoke SAD records.  Follows the same HMAC-signed pattern as @palisade/vault-client.
 */

import { request } from 'undici';
import { signRequest } from '@palisade/service-auth';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface PrepareSadInput {
  cardId: string;
  pan: string;
  expiryYymm: string;
  serviceCode?: string;
  cardSequenceNumber?: string;
  chipSerial?: string;
  programId: string;
}

export interface PrepareSadResult {
  proxyCardId: string;
  sadRecordId: string;
  status: string;
}

export interface GetSadResult {
  proxyCardId: string;
  cardId: string;
  sadEncrypted: string; // base64
  sadKeyVersion: number;
  chipSerial: string | null;
  status: string;
  expiresAt: string;
}

export interface RevokeSadResult {
  proxyCardId: string;
  status: string;
}

export class ProvisioningClientError extends Error {
  constructor(
    public readonly status: number,
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ProvisioningClientError';
  }
}

export interface ProvisioningClientOptions {
  /** This service's caller identity (e.g. 'activation', 'admin'). */
  keyId: string;
  /** 32-byte hex secret shared with data-prep's PROVISION_AUTH_KEYS[keyId]. */
  secret: string;
}

// ---------------------------------------------------------------------------
// Internal
// ---------------------------------------------------------------------------

async function sendSigned<T>(
  baseUrl: string,
  pathAndQuery: string,
  method: string,
  bodyBytes: Buffer,
  auth: ProvisioningClientOptions,
): Promise<T> {
  const url = `${baseUrl.replace(/\/$/, '')}${pathAndQuery}`;
  const authorization = signRequest({
    method,
    pathAndQuery,
    body: bodyBytes,
    keyId: auth.keyId,
    secret: auth.secret,
  });

  const headers: Record<string, string> = { authorization };
  if (bodyBytes.length > 0) headers['content-type'] = 'application/json';

  const { statusCode, body: responseBody } = await request(url, {
    method,
    headers,
    body: bodyBytes.length > 0 ? bodyBytes : undefined,
  });

  const text = await responseBody.text();

  if (statusCode >= 400) {
    let code = 'provisioning_error';
    let message = `Data-prep service returned ${statusCode}`;
    try {
      const parsed = JSON.parse(text) as { error?: { code?: string; message?: string } };
      if (parsed.error?.code) code = parsed.error.code;
      if (parsed.error?.message) message = parsed.error.message;
    } catch {
      // non-JSON error body
    }
    throw new ProvisioningClientError(statusCode, code, message);
  }

  return JSON.parse(text) as T;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

export function createProvisioningClient(baseUrl: string, auth: ProvisioningClientOptions) {
  return {
    /**
     * Stage SAD for a card.  Called by the activation service after card
     * registration.  Returns the proxyCardId used by the RCA.
     */
    async prepareSad(input: PrepareSadInput): Promise<PrepareSadResult> {
      const bodyBytes = Buffer.from(JSON.stringify(input), 'utf8');
      return sendSigned<PrepareSadResult>(baseUrl, '/api/data-prep/prepare', 'POST', bodyBytes, auth);
    },

    /**
     * Retrieve a staged SAD record by proxyCardId.  Called by the RCA
     * at the start of a provisioning session.
     */
    async getSad(proxyCardId: string): Promise<GetSadResult> {
      return sendSigned<GetSadResult>(
        baseUrl,
        `/api/data-prep/sad/${encodeURIComponent(proxyCardId)}`,
        'GET',
        Buffer.alloc(0),
        auth,
      );
    },

    /**
     * Revoke a SAD record (soft-delete).  Called by admin when a card
     * is suspended/revoked before provisioning.
     */
    async revokeSad(proxyCardId: string): Promise<RevokeSadResult> {
      return sendSigned<RevokeSadResult>(
        baseUrl,
        `/api/data-prep/sad/${encodeURIComponent(proxyCardId)}`,
        'DELETE',
        Buffer.alloc(0),
        auth,
      );
    },
  };
}

export type ProvisioningClient = ReturnType<typeof createProvisioningClient>;
