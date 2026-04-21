/**
 * @palisade/emv-ecdh — ECDH + HKDF + AES-128-CBC + HMAC-SHA256 wrapper
 * for ParamBundle transport to the PA v3 applet.
 *
 * Protocol (matches PA v3 applet's processTransferParams):
 *
 *   1. Server generates an ephemeral P-256 keypair.
 *   2. Server computes shared = ECDH(server_eph_priv, chip_pub) where
 *      chip_pub came from the chip's GENERATE_KEYS response (65-byte
 *      uncompressed SEC1: 0x04 || X || Y).
 *   3. Server derives (aesKey, iv, hmacKey) via HKDF-SHA256:
 *        salt = "paramBundleV1" ASCII
 *        ikm  = shared.X (32 bytes)
 *        info = sessionId (ASCII, variable length)
 *        okm  = 16 bytes AES key || 16 bytes IV || 32 bytes HMAC key
 *   4. Server AES-128-CBC encrypts the ParamBundle TLV blob with
 *      (aesKey, iv) using PKCS#7 padding.
 *   5. Server computes tag = HMAC-SHA256(hmacKey, iv || ciphertext)
 *      truncated to the leftmost 16 bytes.
 *   6. Wire format:
 *        [0x04 || server_eph_pub.X (32) || server_eph_pub.Y (32)]  // 65B SEC1 uncompressed
 *        || iv (16)
 *        || ciphertext (variable, multiple of 16 after PKCS#7 pad)
 *        || tag (16)  // HMAC-SHA256 truncated
 *
 * Chip mirrors the derivation using chip_priv + received server_eph_pub.
 * It re-derives (aesKey, iv, hmacKey) via the same HKDF, recomputes
 * HMAC over (iv || ct), constant-time compares with the received tag,
 * then AES-CBC decrypts + removes PKCS#7 padding.
 *
 * Security choices:
 *   - HKDF salt fixed per protocol version ("paramBundleV1") so a future
 *     revision can bump the salt to reject old-format bundles.
 *   - sessionId in HKDF info binds the bundle to a specific provisioning
 *     session — a bundle issued for session A cannot be replayed to a
 *     chip expecting session B (HKDF output differs → AES key + IV +
 *     HMAC key all diverge, HMAC tag won't verify).
 *   - AES-128-CBC + HMAC-SHA256 (encrypt-then-MAC) instead of AES-GCM
 *     because JavaCard 3.0.4 Classic SDK has AES-CBC + SHA-256 but
 *     no AEADCipher (GCM was added in JC 3.1).  Security-equivalent
 *     when implemented correctly: the tag is computed over IV || CT
 *     and verified BEFORE decryption.
 *   - Ephemeral server keypair per ParamBundle build — forward secrecy.
 *     Even if the KMS-wrapped ParamBundle-at-rest is stolen, the
 *     attacker cannot re-derive the AES/HMAC keys without the chip's
 *     private key (which never leaves the SE).
 */

import {
  createECDH,
  createHmac,
  createCipheriv,
  createDecipheriv,
  timingSafeEqual,
  randomBytes,
  type BinaryLike,
} from 'node:crypto';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** HKDF salt — bump on protocol revision. */
const HKDF_SALT = Buffer.from('paramBundleV1', 'ascii');

const AES_KEY_LEN = 16;   // AES-128
const AES_IV_LEN  = 16;   // AES block size
const HMAC_KEY_LEN = 32;  // SHA-256 internal state; "right-sized" HMAC key
const HMAC_TAG_LEN = 16;  // truncated HMAC-SHA256 (leftmost 16 of 32 bytes)

/** HKDF output: AES key || IV || HMAC key = 64 bytes. */
const HKDF_OUTPUT_LEN = AES_KEY_LEN + AES_IV_LEN + HMAC_KEY_LEN;

/** Uncompressed SEC1 P-256 pubkey: 0x04 || X(32) || Y(32). */
const SEC1_UNCOMPRESSED_LEN = 65;

/** SEC1 P-256 curve name — Node's `createECDH('prime256v1')`. */
const CURVE = 'prime256v1';

// ---------------------------------------------------------------------------
// HKDF-SHA256 (RFC 5869)
// ---------------------------------------------------------------------------
//
// We reimplement HKDF rather than import from @palisade/core because this
// package must be self-contained (JavaCard dev may reference it as the
// canonical reference implementation for the applet-side code).  Keeps the
// logic in one place.

/**
 * HKDF-SHA256 extract: produces a pseudo-random key (PRK) from the input
 * keying material (IKM) and an optional salt.
 */
function hkdfExtract(salt: Buffer, ikm: Buffer): Buffer {
  return createHmac('sha256', salt).update(ikm).digest();
}

/**
 * HKDF-SHA256 expand: produces output keying material (OKM) of `length`
 * bytes from a PRK and optional info context string.
 */
function hkdfExpand(prk: Buffer, info: Buffer, length: number): Buffer {
  const hashLen = 32; // SHA-256 output
  const n = Math.ceil(length / hashLen);
  if (n > 255) {
    throw new Error(`hkdfExpand: requested length ${length} exceeds HKDF max (255 * 32 = 8160)`);
  }
  const out = Buffer.alloc(n * hashLen);
  let t = Buffer.alloc(0);
  for (let i = 0; i < n; i++) {
    const counter = Buffer.from([i + 1]);
    t = createHmac('sha256', prk).update(t).update(info).update(counter).digest();
    t.copy(out, i * hashLen);
  }
  return out.subarray(0, length);
}

/**
 * HKDF-SHA256: convenience wrapper that extract-then-expand in one call.
 *
 * This is the canonical derivation used by both server (here) and the
 * PA v3 applet.  Any divergence between the two implementations
 * breaks interop — if you change salt/info/output-length, update
 * applets/pa/.../EcdhUnwrap.java in the same commit.
 */
export function hkdfSha256(
  ikm: BinaryLike,
  salt: BinaryLike,
  info: BinaryLike,
  length: number,
): Buffer {
  const saltBuf = Buffer.isBuffer(salt) ? salt : Buffer.from(salt as Uint8Array);
  const ikmBuf = Buffer.isBuffer(ikm) ? ikm : Buffer.from(ikm as Uint8Array);
  const infoBuf = Buffer.isBuffer(info) ? info : Buffer.from(info as Uint8Array);
  const prk = hkdfExtract(saltBuf, ikmBuf);
  return hkdfExpand(prk, infoBuf, length);
}

// ---------------------------------------------------------------------------
// ECDH + HKDF + AES-GCM wrap/unwrap
// ---------------------------------------------------------------------------

export interface WrapInput {
  /**
   * Chip's P-256 public key, uncompressed SEC1 (65 bytes: 0x04 || X || Y).
   * Returned by the chip in the GENERATE_KEYS APDU response.
   */
  chipPubUncompressed: Buffer;
  /** Plaintext ParamBundle (TLV-encoded bytes). */
  plaintext: Buffer;
  /**
   * Session identifier mixed into the HKDF info string.  Binds the
   * encrypted bundle to a specific provisioning session so a bundle
   * intended for session A cannot be replayed to a chip in session B.
   * Typically the ProvisioningSession.id (cuid string).
   */
  sessionId: string;
}

export interface WrappedParamBundle {
  /**
   * Server's ephemeral P-256 public key, uncompressed SEC1 (65 bytes).
   * Chip uses this to compute the shared secret on its side.
   */
  serverEphemeralPub: Buffer;
  /** 16-byte AES-CBC IV (derived from HKDF; sent verbatim on the wire). */
  iv: Buffer;
  /** AES-128-CBC ciphertext (multiple of 16 bytes after PKCS#7 padding). */
  ciphertext: Buffer;
  /**
   * 16-byte HMAC-SHA256 tag, truncated to the leftmost 16 bytes.
   * Computed over (iv || ciphertext).
   */
  tag: Buffer;
}

/**
 * Wrap a ParamBundle for delivery to the chip.  Generates a fresh
 * ephemeral keypair per call (forward secrecy).  Encrypt-then-MAC:
 * encrypt with AES-128-CBC + PKCS#7, authenticate iv||ct with
 * HMAC-SHA256, truncate tag to 16 bytes.
 */
export function wrapParamBundle(input: WrapInput): WrappedParamBundle {
  if (input.chipPubUncompressed.length !== SEC1_UNCOMPRESSED_LEN) {
    throw new Error(
      `wrapParamBundle: chipPubUncompressed must be ${SEC1_UNCOMPRESSED_LEN} bytes, got ${input.chipPubUncompressed.length}`,
    );
  }
  if (input.chipPubUncompressed[0] !== 0x04) {
    throw new Error(
      `wrapParamBundle: chipPubUncompressed must start with 0x04 (SEC1 uncompressed marker)`,
    );
  }

  const ecdh = createECDH(CURVE);
  ecdh.generateKeys();
  const serverEphemeralPub = ecdh.getPublicKey(null, 'uncompressed'); // 65 bytes
  const shared = ecdh.computeSecret(input.chipPubUncompressed); // 32-byte X coord

  const okm = hkdfSha256(
    shared,
    HKDF_SALT,
    Buffer.from(input.sessionId, 'ascii'),
    HKDF_OUTPUT_LEN,
  );
  const aesKey = okm.subarray(0, AES_KEY_LEN);
  const iv = okm.subarray(AES_KEY_LEN, AES_KEY_LEN + AES_IV_LEN);
  const hmacKey = okm.subarray(AES_KEY_LEN + AES_IV_LEN);

  const cipher = createCipheriv('aes-128-cbc', aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(input.plaintext), cipher.final()]);

  // Encrypt-then-MAC: authenticate IV + ciphertext (NOT plaintext).
  const fullTag = createHmac('sha256', hmacKey)
    .update(iv)
    .update(ciphertext)
    .digest();
  const tag = fullTag.subarray(0, HMAC_TAG_LEN);

  // Copy out iv + tag BEFORE scrubbing — iv is a view into okm.
  const ivCopy  = Buffer.from(iv);
  const tagCopy = Buffer.from(tag);

  shared.fill(0);
  okm.fill(0);
  fullTag.fill(0);

  return {
    serverEphemeralPub,
    iv: ivCopy,
    ciphertext,
    tag: tagCopy,
  };
}

export interface UnwrapInput {
  /** Server's ephemeral pubkey from the wrap (65 bytes SEC1 uncompressed). */
  serverEphemeralPub: Buffer;
  /** 16-byte AES-CBC IV (from wire). */
  iv: Buffer;
  /** Ciphertext to decrypt (multiple of 16 bytes). */
  ciphertext: Buffer;
  /** 16-byte truncated HMAC-SHA256 tag (from wire). */
  tag: Buffer;
  /** Chip's private key (32-byte raw P-256 scalar). */
  chipPriv: Buffer;
  /** Same sessionId that was mixed into wrap's HKDF info. */
  sessionId: string;
}

/**
 * Unwrap a ParamBundle — mirror of `wrapParamBundle`.  Used by the
 * server-side byte-parity tests (we can verify round-trip without a
 * real chip) and by the PA v3 applet's equivalent Java implementation.
 *
 * Encrypt-then-MAC verification: re-derives (aesKey, iv, hmacKey) via
 * HKDF, recomputes HMAC-SHA256 over (iv || ct), compares against the
 * received tag with timingSafeEqual.  On tag mismatch rejects BEFORE
 * decryption (classical encrypt-then-MAC order).
 */
export function unwrapParamBundle(input: UnwrapInput): Buffer {
  if (input.serverEphemeralPub.length !== SEC1_UNCOMPRESSED_LEN) {
    throw new Error(
      `unwrapParamBundle: serverEphemeralPub must be ${SEC1_UNCOMPRESSED_LEN} bytes`,
    );
  }
  if (input.chipPriv.length !== 32) {
    throw new Error(`unwrapParamBundle: chipPriv must be 32 bytes`);
  }
  if (input.iv.length !== AES_IV_LEN) {
    throw new Error(`unwrapParamBundle: iv must be ${AES_IV_LEN} bytes`);
  }
  if (input.tag.length !== HMAC_TAG_LEN) {
    throw new Error(`unwrapParamBundle: tag must be ${HMAC_TAG_LEN} bytes`);
  }
  if (input.ciphertext.length === 0 || input.ciphertext.length % AES_IV_LEN !== 0) {
    throw new Error(
      `unwrapParamBundle: ciphertext length ${input.ciphertext.length} is not a positive multiple of ${AES_IV_LEN} (CBC block size)`,
    );
  }

  const ecdh = createECDH(CURVE);
  ecdh.setPrivateKey(input.chipPriv);
  const shared = ecdh.computeSecret(input.serverEphemeralPub);

  const okm = hkdfSha256(
    shared,
    HKDF_SALT,
    Buffer.from(input.sessionId, 'ascii'),
    HKDF_OUTPUT_LEN,
  );
  const aesKey  = okm.subarray(0, AES_KEY_LEN);
  const expIv   = okm.subarray(AES_KEY_LEN, AES_KEY_LEN + AES_IV_LEN);
  const hmacKey = okm.subarray(AES_KEY_LEN + AES_IV_LEN);

  // IV sent on the wire MUST match the HKDF-derived IV — otherwise
  // someone tampered (or the implementations disagree on HKDF info).
  if (!input.iv.equals(expIv)) {
    shared.fill(0);
    okm.fill(0);
    throw new Error(
      'unwrapParamBundle: wire IV does not match HKDF-derived IV (tampering or implementation mismatch)',
    );
  }

  // Encrypt-then-MAC verify FIRST, before attempting decrypt.  This
  // is the security-correct order — never touch the ciphertext if its
  // integrity isn't proven.
  const fullTag = createHmac('sha256', hmacKey)
    .update(input.iv)
    .update(input.ciphertext)
    .digest();
  const expectedTag = fullTag.subarray(0, HMAC_TAG_LEN);

  if (!timingSafeEqual(expectedTag, input.tag)) {
    shared.fill(0);
    okm.fill(0);
    fullTag.fill(0);
    throw new Error('unwrapParamBundle: HMAC tag verification failed');
  }

  const decipher = createDecipheriv('aes-128-cbc', aesKey, input.iv);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(input.ciphertext), decipher.final()]);
  } catch (err) {
    shared.fill(0);
    okm.fill(0);
    fullTag.fill(0);
    throw new Error(
      `unwrapParamBundle: AES-CBC decrypt/unpad failed — ${err instanceof Error ? err.message : err}`,
    );
  }

  shared.fill(0);
  okm.fill(0);
  fullTag.fill(0);

  return plaintext;
}

// ---------------------------------------------------------------------------
// Convenience: the full wire-format blob
// ---------------------------------------------------------------------------

/**
 * Serialize a WrappedParamBundle into the exact bytes the chip expects
 * in the TRANSFER_PARAMS APDU data field:
 *
 *   serverEphemeralPub(65) || iv(16) || ciphertext(var, multiple of 16) || tag(16)
 *
 * Total length: 97 + ciphertext.length.
 */
export function serializeWrappedBundle(b: WrappedParamBundle): Buffer {
  return Buffer.concat([b.serverEphemeralPub, b.iv, b.ciphertext, b.tag]);
}

/**
 * Parse the wire-format blob back into its components.  Inverse of
 * `serializeWrappedBundle`.  Useful for tests and for future tooling
 * that inspects captured APDUs.
 */
export function parseWireBundle(wire: Buffer): WrappedParamBundle {
  const minLen = SEC1_UNCOMPRESSED_LEN + AES_IV_LEN + HMAC_TAG_LEN;
  if (wire.length < minLen) {
    throw new Error(
      `parseWireBundle: wire blob too short (${wire.length} bytes, min ${minLen})`,
    );
  }
  const ctLen = wire.length - SEC1_UNCOMPRESSED_LEN - AES_IV_LEN - HMAC_TAG_LEN;
  if (ctLen === 0 || ctLen % AES_IV_LEN !== 0) {
    throw new Error(
      `parseWireBundle: ciphertext length ${ctLen} must be a positive multiple of ${AES_IV_LEN}`,
    );
  }
  const serverEphemeralPub = wire.subarray(0, SEC1_UNCOMPRESSED_LEN);
  const iv = wire.subarray(
    SEC1_UNCOMPRESSED_LEN,
    SEC1_UNCOMPRESSED_LEN + AES_IV_LEN,
  );
  const tagStart = wire.length - HMAC_TAG_LEN;
  const ciphertext = wire.subarray(
    SEC1_UNCOMPRESSED_LEN + AES_IV_LEN,
    tagStart,
  );
  const tag = wire.subarray(tagStart);
  return { serverEphemeralPub, iv, ciphertext, tag };
}

// ---------------------------------------------------------------------------
// Test helpers — NOT used in production, only by unit tests
// ---------------------------------------------------------------------------

/**
 * Generate a P-256 keypair suitable for testing (chip-side simulation).
 * Returns `{ pubUncompressed, priv }`.
 *
 * Do NOT call from production code — there's no scrubbing, no HSM, and
 * the privkey is handed out in cleartext.  Tests use this to simulate a
 * chip without flashing real silicon.
 */
export function generateTestKeypair(): { pubUncompressed: Buffer; priv: Buffer } {
  const ecdh = createECDH(CURVE);
  ecdh.generateKeys();
  // `ecdh.getPrivateKey()` returns the scalar as the minimal-length
  // big-endian buffer — if the leading byte(s) of d happen to be zero
  // (probability ~ 1 / 256 per leading byte), the buffer will be < 32 B.
  // Our contract + the P-256 scalar width are fixed at 32 B, so pad.
  const priv = ecdh.getPrivateKey();
  const priv32 = priv.length === 32 ? priv : Buffer.concat([Buffer.alloc(32 - priv.length, 0), priv]);
  return {
    pubUncompressed: ecdh.getPublicKey(null, 'uncompressed'),
    priv: priv32,
  };
}

/**
 * Deterministic AES-GCM wrap for test vectors.  Takes an explicit
 * serverEphemeralPriv (as a scalar Buffer) so the same input always
 * produces the same wire bytes.  NEVER use in production — forward
 * secrecy depends on ephemeral randomness.
 */
export function wrapParamBundleDeterministic(
  input: WrapInput & { serverEphemeralPriv: Buffer },
): WrappedParamBundle {
  if (input.serverEphemeralPriv.length !== 32) {
    throw new Error(`wrapParamBundleDeterministic: serverEphemeralPriv must be 32 bytes`);
  }
  if (input.chipPubUncompressed.length !== SEC1_UNCOMPRESSED_LEN) {
    throw new Error(
      `wrapParamBundleDeterministic: chipPubUncompressed must be ${SEC1_UNCOMPRESSED_LEN} bytes`,
    );
  }

  const ecdh = createECDH(CURVE);
  ecdh.setPrivateKey(input.serverEphemeralPriv);
  const serverEphemeralPub = ecdh.getPublicKey(null, 'uncompressed');
  const shared = ecdh.computeSecret(input.chipPubUncompressed);

  const okm = hkdfSha256(
    shared,
    HKDF_SALT,
    Buffer.from(input.sessionId, 'ascii'),
    HKDF_OUTPUT_LEN,
  );
  const aesKey  = okm.subarray(0, AES_KEY_LEN);
  const iv      = okm.subarray(AES_KEY_LEN, AES_KEY_LEN + AES_IV_LEN);
  const hmacKey = okm.subarray(AES_KEY_LEN + AES_IV_LEN);

  const cipher = createCipheriv('aes-128-cbc', aesKey, iv);
  const ciphertext = Buffer.concat([cipher.update(input.plaintext), cipher.final()]);

  const fullTag = createHmac('sha256', hmacKey)
    .update(iv)
    .update(ciphertext)
    .digest();
  const tag = fullTag.subarray(0, HMAC_TAG_LEN);

  return {
    serverEphemeralPub,
    iv: Buffer.from(iv),
    ciphertext,
    tag: Buffer.from(tag),
  };
}

/** Protocol-version constants re-exported for downstream parity checks. */
export const ECDH_PROTOCOL = {
  SALT: Buffer.from(HKDF_SALT),
  HKDF_OUTPUT_LEN,
  AES_KEY_LEN,
  AES_IV_LEN,
  HMAC_KEY_LEN,
  HMAC_TAG_LEN,
  SEC1_UNCOMPRESSED_LEN,
  CURVE,
} as const;

/**
 * Zero-fill any Buffer the caller no longer needs.  Convenience — the
 * real scrub hygiene is on the PA v3 applet side; on the server we
 * have less visibility into GC-rooted copies but can at least clean
 * up call-site buffers.
 */
export function scrub(...bufs: (Buffer | Uint8Array)[]): void {
  for (const b of bufs) {
    if (b && (b as Buffer).fill) (b as Buffer).fill(0);
  }
}

/** Random 32-byte scalar for dev / test key generation. */
export function randomP256Scalar(): Buffer {
  return randomBytes(32);
}
