// User-agent device detection.  Used by the merchant page (mobile-detect for
// redirect vs. desktop hand-off), the customer page (tier ↔ ceremony picker),
// and the admin page (device-name default for newly registered passkeys).

export type Device = 'ios' | 'android' | 'desktop';

export function detectDevice(): Device {
  const ua = navigator.userAgent;
  if (/iPhone|iPad|iPod/.test(ua)) return 'ios';
  if (/Android/.test(ua)) return 'android';
  return 'desktop';
}

export function isMobile(): boolean {
  return detectDevice() !== 'desktop';
}

/** Friendly label for the device-name field on a newly registered credential. */
export function deviceNameGuess(): string {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua)) return 'iPhone';
  if (/iPad/.test(ua)) return 'iPad';
  if (/Android/.test(ua)) return 'Android phone';
  if (/Mac/.test(ua)) return 'Mac';
  if (/Windows/.test(ua)) return 'Windows PC';
  return 'Device';
}

/** Per-platform copy for biometric prompts (Face ID vs fingerprint vs Hello). */
export function biometricHint(d: Device): string {
  if (d === 'ios') return 'Face ID / Touch ID';
  if (d === 'android') return 'fingerprint or face unlock';
  return 'Touch ID / Windows Hello';
}
