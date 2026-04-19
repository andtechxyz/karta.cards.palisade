export {
  buildNfcCardRegistrationOptions,
  buildPlatformRegistrationOptions,
  buildAuthenticationOptions,
} from './config.js';
export type {
  RegInputCommon,
  AuthInput,
  AuthenticatorTransportFuture,
} from './config.js';
export { verifyRegistration, verifyAuthentication } from './verify.js';
export type {
  VerifyRegistrationInput,
  VerifyAuthenticationInput,
} from './verify.js';
export { getWebAuthnConfig, _resetWebAuthnConfig } from './env.js';
