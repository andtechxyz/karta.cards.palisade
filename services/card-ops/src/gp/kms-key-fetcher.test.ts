/**
 * Unit tests for fetchGpKey — verifies:
 *   - SecretBinary → raw bytes path
 *   - SecretString → hex-decoded bytes path
 *   - Per-ARN caching (second call doesn't hit AWS)
 *   - Empty ARN rejected
 *   - Bad-length secret rejected
 *   - SDK failure propagates
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import {
  _resetGpKeyCache,
  _setSecretsManagerClientFactory,
  fetchGpKey,
} from './kms-key-fetcher.js';

// ---------------------------------------------------------------------------
// Mocks
// ---------------------------------------------------------------------------

// We avoid calling the real SDK by injecting a factory that returns a
// client with a scripted send().  Each test scripts the responses.

let sendMock: ReturnType<typeof vi.fn>;

beforeEach(() => {
  _resetGpKeyCache();
  sendMock = vi.fn();
  _setSecretsManagerClientFactory(() => ({ send: sendMock } as any));
});

// A 16-byte AES-128 key used across tests.
const KEY16 = Buffer.from('00112233445566778899AABBCCDDEEFF', 'hex');
const HEX32 = KEY16.toString('hex');

describe('fetchGpKey', () => {
  it('returns raw bytes from SecretBinary', async () => {
    sendMock.mockResolvedValueOnce({ SecretBinary: new Uint8Array(KEY16) });
    const result = await fetchGpKey('arn:aws:secretsmanager:us-east-1:acc:secret:a1');
    expect(result.equals(KEY16)).toBe(true);
  });

  it('decodes hex-encoded SecretString', async () => {
    sendMock.mockResolvedValueOnce({ SecretString: HEX32 });
    const result = await fetchGpKey('arn:aws:secretsmanager:us-east-1:acc:secret:a2');
    expect(result.equals(KEY16)).toBe(true);
  });

  it('trims whitespace from SecretString', async () => {
    sendMock.mockResolvedValueOnce({ SecretString: `  ${HEX32}\n` });
    const result = await fetchGpKey('arn:aws:secretsmanager:us-east-1:acc:secret:a3');
    expect(result.equals(KEY16)).toBe(true);
  });

  it('caches per-ARN — second call does not hit AWS', async () => {
    sendMock.mockResolvedValueOnce({ SecretBinary: new Uint8Array(KEY16) });
    const arn = 'arn:aws:secretsmanager:us-east-1:acc:secret:cached';
    const first = await fetchGpKey(arn);
    const second = await fetchGpKey(arn);
    expect(first.equals(KEY16)).toBe(true);
    expect(second.equals(KEY16)).toBe(true);
    expect(sendMock).toHaveBeenCalledTimes(1);
  });

  it('different ARNs get different fetches (no cross-contamination)', async () => {
    const KEY_A = Buffer.alloc(16, 0x11);
    const KEY_B = Buffer.alloc(16, 0x22);
    sendMock
      .mockResolvedValueOnce({ SecretBinary: new Uint8Array(KEY_A) })
      .mockResolvedValueOnce({ SecretBinary: new Uint8Array(KEY_B) });

    const a = await fetchGpKey('arn::A');
    const b = await fetchGpKey('arn::B');
    expect(a.equals(KEY_A)).toBe(true);
    expect(b.equals(KEY_B)).toBe(true);
    expect(sendMock).toHaveBeenCalledTimes(2);
  });

  it('empty ARN throws', async () => {
    await expect(fetchGpKey('')).rejects.toThrow(/ARN is empty/);
    expect(sendMock).not.toHaveBeenCalled();
  });

  it('rejects wrong-length secret', async () => {
    sendMock.mockResolvedValueOnce({ SecretBinary: new Uint8Array(8) });
    await expect(fetchGpKey('arn::short')).rejects.toThrow(/8 bytes, expected 16/);
  });

  it('rejects non-hex SecretString', async () => {
    sendMock.mockResolvedValueOnce({ SecretString: 'not hex at all' });
    await expect(fetchGpKey('arn::badhex')).rejects.toThrow(/not hex/);
  });

  it('rejects missing SecretBinary and SecretString', async () => {
    sendMock.mockResolvedValueOnce({});
    await expect(fetchGpKey('arn::empty')).rejects.toThrow(/SecretBinary or SecretString/);
  });

  it('propagates SDK error', async () => {
    sendMock.mockRejectedValueOnce(new Error('AccessDeniedException'));
    await expect(fetchGpKey('arn::denied')).rejects.toThrow(/AccessDeniedException/);
  });
});
