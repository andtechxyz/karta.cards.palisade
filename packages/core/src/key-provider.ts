// -----------------------------------------------------------------------------
// KeyProvider — abstract source of AES-256-GCM data-encryption keys by version.
//
// There is no cross-service singleton.  Each service that encrypts or
// decrypts data owns its own KeyProvider instance wired to its own keyspace
// (PCI-DSS 3.5/3.6 — keys scoped to the data they protect).  Activation, tap
// and vault each construct a local `EnvKeyProvider` and pass it explicitly to
// `encrypt`/`decrypt` — there is no default.
//
// Swapping env-backed keys for AWS KMS or an HSM is a one-class change:
// implement KeyProvider against kms.Decrypt and construct it in the same
// place the service currently instantiates EnvKeyProvider.
// -----------------------------------------------------------------------------

export interface KeyProvider {
  /** Current active key version for new writes. */
  readonly activeVersion: number;
  /** Returns the raw DEK bytes for a given version. Throws if unknown. */
  getKey(version: number): Buffer;
}

export interface EnvKeyProviderInput {
  activeVersion: number;
  /** Map from key version → hex-encoded DEK.  Must contain `activeVersion`. */
  keys: Record<number, string>;
}

export class EnvKeyProvider implements KeyProvider {
  readonly activeVersion: number;
  private readonly keys = new Map<number, Buffer>();

  constructor(input: EnvKeyProviderInput) {
    this.activeVersion = input.activeVersion;
    for (const [version, hex] of Object.entries(input.keys)) {
      this.keys.set(Number(version), Buffer.from(hex, 'hex'));
    }
    if (!this.keys.has(this.activeVersion)) {
      throw new Error(
        `activeVersion=${this.activeVersion} but no key for that version was provided`,
      );
    }
  }

  getKey(version: number): Buffer {
    const key = this.keys.get(version);
    if (!key) throw new Error(`Unknown key version: ${version}`);
    return key;
  }
}
