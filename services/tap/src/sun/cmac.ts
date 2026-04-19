// Re-export AES-128-CMAC from @palisade/core.  The implementation lives in
// core now because activation service also needs it (building the URL+CMAC
// tail baked into WebAuthn extended credential IDs).  Keeping the
// re-export so SUN callers (verify.ts, verify.test.ts) don't need to
// change their imports.
export { aesCmac } from '@palisade/core';
