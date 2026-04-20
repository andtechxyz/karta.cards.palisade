/**
 * @palisade/emv-ecdh — ECDH + HKDF + AES-128-GCM wrapper for ParamBundle
 * transport to the PA v3 applet.
 *
 * Protocol (matches PA v3 applet's processTransferParams):
 *
 *   1. Server generates an ephemeral P-256 keypair.
 *   2. Server computes shared = ECDH(server_eph_priv, chip_pub) where
 *      chip_pub came from the chip's GENERATE_KEYS response (65-byte
 *      uncompressed SEC1: 0x04 || X || Y).
 *   3. Server derives (aesKey, nonce) via HKDF-SHA256:
 *        salt = "paramBundleV1" ASCII
 *        ikm  = shared.X (32 bytes)
 *        info = sessionId (ASCII, variable length)
 *        okm  = 16 bytes key || 12 bytes nonce
 *   4. Server AES-128-GCM encrypts the ParamBundle TLV blob with
 *      (aesKey, nonce); empty AAD.
 *   5. Wire format:
 *        [0x04 || server_eph_pub.X (32)]  // 33-byte SEC1 compressed
 *                                          // OR 65-byte uncompressed —
 *                                          // prototype uses uncompressed
 *                                          // to match chip SDK.
 *        || nonce (12)
 *        || ciphertext (variable)
 *        || gcmTag (16)
 *
 * Chip mirrors the derivation using chip_priv + received server_eph_pub
 * and verifies the GCM tag before acting on any parameter.
 *
 * Security choices:
 *   - HKDF salt fixed per protocol version ("paramBundleV1") so a future
 *     revision can bump the salt to reject old-format bundles.
 *   - sessionId in HKDF info binds the bundle to a specific provisioning
 *     session so a bundle issued for session A cannot be replayed to a
 *     chip expecting session B.  Chip enforces by including its session
 *     context in its own HKDF call.
 *   - AES-128-GCM (not CCM) for authenticated encryption.  JavaCard 3.0.5+
 *     supports GCM natively on JCOP 5 / Infineon Secora hardware.
 *   - Ephemeral server keypair per ParamBundle build — forward secrecy.
 *     Even if the KMS-wrapped ParamBundle-at-rest is stolen, the
 *     attacker cannot re-derive the AES key without the chip's private
 *     key (which never leaves the SE).
 */

import {
  createECDH,
  createHmac,
  createCipheriv,
  createDecipheriv,
  randomBytes,
  type BinaryLike,
} from 'node:crypto';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** HKDF salt — bump on protocol revision. */
const HKDF_SALT = Buffer.from('paramBundleV1', 'ascii');

/** HKDF output: 16-byte AES-128 key + 12-byte GCM nonce = 28 bytes. */
const HKDF_OUTPUT_LEN = 16 + 12;
const AES_KEY_LEN = 16;
const GCM_NONCE_LEN = 12;
const GCM_TAG_LEN = 16;

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
  /** 12-byte AES-GCM nonce (randomly generated per wrap). */
  nonce: Buffer;
  /** AES-128-GCM ciphertext (same length as plaintext). */
  ciphertext: Buffer;
  /** 16-byte AES-GCM authentication tag. */
  tag: Buffer;
}

/**
 * Wrap a ParamBundle for delivery to the chip.  Generates a fresh
 * ephemeral keypair per call (forward secrecy).
 *
 * Returns the four components the chip needs: server ephemeral pubkey,
 * nonce, ciphertext, and GCM tag.  Caller concatenates these into the
 * TRANSFER_PARAMS APDU body.
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
  const nonce = okm.subarray(AES_KEY_LEN, AES_KEY_LEN + GCM_NONCE_LEN);

  const cipher = createCipheriv('aes-128-gcm', aesKey, nonce);
  const ciphertext = Buffer.concat([cipher.update(input.plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Copy out the nonce BEFORE scrubbing — `nonce` is a view into
  // `okm`, and we're about to zero the whole backing buffer.  The
  // returned nonce is the same bytes the chip will derive via HKDF on
  // its side, so it's not secret per se, but we still send it on the
  // wire for belt-and-suspenders parity.
  const nonceCopy = Buffer.from(nonce);

  // Scrub transient key material.  `shared`, `okm`, `aesKey`, `nonce`
  // views all reference the same backing Buffers — zero them before
  // returning so GC doesn't hold plaintext key bytes.  The returned
  // `serverEphemeralPub`, `nonceCopy`, `ciphertext`, and `tag` are the
  // only values that may persist.
  shared.fill(0);
  okm.fill(0);
  // aesKey and nonce are views into okm; already scrubbed.

  return {
    serverEphemeralPub,
    nonce: nonceCopy,
    ciphertext,
    tag,
  };
}

export interface UnwrapInput {
  /** Server's ephemeral pubkey from the wrap (65 bytes SEC1 uncompressed). */
  serverEphemeralPub: Buffer;
  /** 12-byte GCM nonce from the wrap. */
  nonce: Buffer;
  /** Ciphertext to decrypt. */
  ciphertext: Buffer;
  /** 16-byte GCM authentication tag. */
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
 * Throws if the GCM tag doesn't verify (tampering, wrong key, wrong
 * session).  On success returns the plaintext ParamBundle bytes.
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
  if (input.nonce.length !== GCM_NONCE_LEN) {
    throw new Error(`unwrapParamBundle: nonce must be ${GCM_NONCE_LEN} bytes`);
  }
  if (input.tag.length !== GCM_TAG_LEN) {
    throw new Error(`unwrapParamBundle: tag must be ${GCM_TAG_LEN} bytes`);
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
  const aesKey = okm.subarray(0, AES_KEY_LEN);
  // Note: we recompute the nonce from HKDF and also accept an explicit
  // nonce from the wire.  They should match.  If they don't, something
  // tampered with the wire nonce — we prefer the HKDF-derived one and
  // will fail GCM verification if the attacker tried to swap it.
  const expectedNonce = okm.subarray(AES_KEY_LEN, AES_KEY_LEN + GCM_NONCE_LEN);
  if (!input.nonce.equals(expectedNonce)) {
    // Not an immediate error — the wire-supplied nonce is what we actually
    // use in GCM.  But we log the mismatch because honest implementations
    // should send the HKDF-derived nonce verbatim.
    //
    // Note: some implementations use the wire nonce directly (random 12 B
    // per wrap, not HKDF-derived).  The PA v3 applet design uses the
    // HKDF-derived nonce to reduce RAM pressure.  Server-side, we keep
    // this check strict for now.
    throw new Error(
      'unwrapParamBundle: wire nonce does not match HKDF-derived nonce (possible tampering or wrap/unwrap version mismatch)',
    );
  }

  const decipher = createDecipheriv('aes-128-gcm', aesKey, input.nonce);
  decipher.setAuthTag(input.tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(input.ciphertext), decipher.final()]);
  } catch (err) {
    shared.fill(0);
    okm.fill(0);
    throw new Error(
      `unwrapParamBundle: GCM verification failed — ${err instanceof Error ? err.message : err}`,
    );
  }

  shared.fill(0);
  okm.fill(0);

  return plaintext;
}

// ---------------------------------------------------------------------------
// Convenience: the full wire-format blob
// ---------------------------------------------------------------------------

/**
 * Serialize a WrappedParamBundle into the exact bytes the chip expects
 * in the TRANSFER_PARAMS APDU data field:
 *
 *   serverEphemeralPub(65) || nonce(12) || ciphertext(var) || tag(16)
 *
 * Total length: 65 + 12 + plaintext.length + 16 = plaintext.length + 93.
 */
export function serializeWrappedBundle(b: WrappedParamBundle): Buffer {
  return Buffer.concat([b.serverEphemeralPub, b.nonce, b.ciphertext, b.tag]);
}

/**
 * Parse the wire-format blob back into its components.  Inverse of
 * `serializeWrappedBundle`.  Useful for tests and for future tooling
 * that inspects captured APDUs.
 */
export function parseWireBundle(wire: Buffer): WrappedParamBundle {
  if (wire.length < SEC1_UNCOMPRESSED_LEN + GCM_NONCE_LEN + GCM_TAG_LEN) {
    throw new Error(
      `parseWireBundle: wire blob too short (${wire.length} bytes, min ${
        SEC1_UNCOMPRESSED_LEN + GCM_NONCE_LEN + GCM_TAG_LEN
      })`,
    );
  }
  const serverEphemeralPub = wire.subarray(0, SEC1_UNCOMPRESSED_LEN);
  const nonce = wire.subarray(
    SEC1_UNCOMPRESSED_LEN,
    SEC1_UNCOMPRESSED_LEN + GCM_NONCE_LEN,
  );
  const tagStart = wire.length - GCM_TAG_LEN;
  const ciphertext = wire.subarray(
    SEC1_UNCOMPRESSED_LEN + GCM_NONCE_LEN,
    tagStart,
  );
  const tag = wire.subarray(tagStart);
  return { serverEphemeralPub, nonce, ciphertext, tag };
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
  return {
    pubUncompressed: ecdh.getPublicKey(null, 'uncompressed'),
    priv: ecdh.getPrivateKey(),
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
  const aesKey = okm.subarray(0, AES_KEY_LEN);
  const nonce = okm.subarray(AES_KEY_LEN, AES_KEY_LEN + GCM_NONCE_LEN);

  const cipher = createCipheriv('aes-128-gcm', aesKey, nonce);
  const ciphertext = Buffer.concat([cipher.update(input.plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();

  // Copy out before any potential scrub.  Deterministic wrap does not
  // scrub (test code) but keep the pattern identical to production wrap.
  const nonceCopy = Buffer.from(nonce);

  return {
    serverEphemeralPub,
    nonce: nonceCopy,
    ciphertext,
    tag,
  };
}

/** Protocol-version constants re-exported for downstream parity checks. */
export const ECDH_PROTOCOL = {
  SALT: Buffer.from(HKDF_SALT),
  HKDF_OUTPUT_LEN,
  AES_KEY_LEN,
  GCM_NONCE_LEN,
  GCM_TAG_LEN,
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
