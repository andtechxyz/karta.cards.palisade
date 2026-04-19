import { createCipheriv } from 'node:crypto';

// AES-128-CMAC per NIST SP 800-38B.
//
// Used for:
//   - SUN/SDM MAC verification on tap (karta.cards tap service)
//   - Building the URL+CMAC tail baked into WebAuthn extended credential
//     IDs so the T4T applet can accept a URL update mid-assertion
//
// Hand-rolled on top of node:crypto's AES-128-ECB single-block primitive
// because Node has no first-class CMAC API.  Verified byte-for-byte
// against NIST SP 800-38B Appendix D test vectors.

const BLOCK_SIZE = 16;
const ZERO_BLOCK = Buffer.alloc(BLOCK_SIZE);
const RB = 0x87; // GF(2^128) reduction polynomial constant for 128-bit blocks

function aesEcbEncryptBlock(key: Buffer, block: Buffer): Buffer {
  const cipher = createCipheriv('aes-128-ecb', key, null);
  cipher.setAutoPadding(false);
  return Buffer.from(Buffer.concat([cipher.update(block), cipher.final()]));
}

function leftShiftOneBit(input: Buffer): Buffer {
  const out = Buffer.alloc(input.length);
  let carry = 0;
  for (let i = input.length - 1; i >= 0; i--) {
    const v = (input[i] << 1) | carry;
    out[i] = v & 0xff;
    carry = (v >> 8) & 1;
  }
  return out;
}

function deriveSubkeys(key: Buffer): { K1: Buffer; K2: Buffer } {
  const L = aesEcbEncryptBlock(key, ZERO_BLOCK);
  const K1 = leftShiftOneBit(L);
  if (L[0] & 0x80) K1[BLOCK_SIZE - 1] ^= RB;
  const K2 = leftShiftOneBit(K1);
  if (K1[0] & 0x80) K2[BLOCK_SIZE - 1] ^= RB;
  return { K1, K2 };
}

function xorInto(dst: Buffer, src: Buffer): void {
  for (let i = 0; i < dst.length; i++) dst[i] ^= src[i];
}

/**
 * AES-128-CMAC.
 *
 * @param key   16-byte symmetric key
 * @param data  arbitrary-length message
 * @returns     16-byte MAC
 */
export function aesCmac(key: Buffer, data: Buffer): Buffer {
  if (key.length !== 16) {
    throw new Error('AES-128-CMAC requires a 16-byte key');
  }

  const { K1, K2 } = deriveSubkeys(key);

  const blockCount = Math.max(1, Math.ceil(data.length / BLOCK_SIZE));
  const lastBlockComplete = data.length > 0 && data.length % BLOCK_SIZE === 0;

  const lastBlock = Buffer.alloc(BLOCK_SIZE);
  if (lastBlockComplete) {
    data.copy(lastBlock, 0, (blockCount - 1) * BLOCK_SIZE, blockCount * BLOCK_SIZE);
    xorInto(lastBlock, K1);
  } else {
    const remainder = data.length - (blockCount - 1) * BLOCK_SIZE;
    if (remainder > 0) {
      data.copy(lastBlock, 0, (blockCount - 1) * BLOCK_SIZE, data.length);
    }
    lastBlock[remainder] = 0x80;
    xorInto(lastBlock, K2);
  }

  let x: Buffer = ZERO_BLOCK;
  const xored = Buffer.alloc(BLOCK_SIZE);
  for (let i = 0; i < blockCount - 1; i++) {
    const block = data.subarray(i * BLOCK_SIZE, (i + 1) * BLOCK_SIZE);
    for (let j = 0; j < BLOCK_SIZE; j++) xored[j] = x[j] ^ block[j];
    x = aesEcbEncryptBlock(key, xored);
  }
  for (let j = 0; j < BLOCK_SIZE; j++) xored[j] = x[j] ^ lastBlock[j];
  return aesEcbEncryptBlock(key, xored);
}
