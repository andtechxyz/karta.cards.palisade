import { useCallback, useEffect, useMemo, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { api, errorMsg } from '../utils/api';
import { biometricHint, detectDevice, deviceNameGuess, type Device } from '../utils/device';
import { activateWithSession } from '../utils/webauthn';

// /activate — identity-blind activation page.  After the tap service
// redirects here, we run a WebAuthn ceremony (assertion in the common case
// of preregistered FIDO credentials, registration as a fallback) to flip
// the card to ACTIVATED.  The assertion also pushes a fresh baseUrl + CMAC
// to the T4T applet via an extended credential ID — chip self-updates on
// the same tap.

type Phase = 'idle' | 'exchanging' | 'busy' | 'done';

function extractHandToken(): string | null {
  const hash = window.location.hash;
  if (!hash.startsWith('#hand=')) return null;
  return decodeURIComponent(hash.slice('#hand='.length)) || null;
}

export default function Activate() {
  const [params] = useSearchParams();
  const sunError = params.get('error');

  const [sessionToken, setSessionToken] = useState<string | null>(null);
  const [phase, setPhase] = useState<Phase>('idle');
  const [err, setErr] = useState<string | null>(null);
  const [micrositeUrl, setMicrositeUrl] = useState<string | null>(null);

  const device = useMemo(detectDevice, []);

  // Exchange the handoff token for an activation session on mount.
  useEffect(() => {
    const handToken = extractHandToken();
    if (!handToken) return;

    setPhase('exchanging');
    api
      .post<{ sessionToken: string }>('/activation/handoff', { token: handToken })
      .then(({ sessionToken: tok }) => {
        setSessionToken(tok);
        history.replaceState(null, '', window.location.pathname + window.location.search);
        setPhase('idle');
      })
      .catch((e) => {
        setErr(errorMsg(e));
        setPhase('idle');
      });
  }, []);

  const onActivate = useCallback(async () => {
    if (!sessionToken) return;
    setPhase('busy');
    setErr(null);
    try {
      const result = await activateWithSession({ sessionToken, deviceLabel: deviceNameGuess() });
      if (result.micrositeUrl) {
        setMicrositeUrl(result.micrositeUrl);
      }
      setPhase('done');
    } catch (e) {
      setErr(errorMsg(e));
      setPhase('idle');
    }
  }, [sessionToken]);

  useEffect(() => {
    if (phase === 'done' && micrositeUrl) {
      const t = setTimeout(() => {
        window.location.href = micrositeUrl;
      }, 2000);
      return () => clearTimeout(t);
    }
  }, [phase, micrositeUrl]);

  // NOTE: no auto-fire.  iOS Safari refuses navigator.credentials.get()
  // outside a user-activation handler ("The document is not focused").
  // Requiring a button tap satisfies that on every platform + gives the
  // user a clear "I'm about to be prompted for NFC" signal.

  if (sunError) return <ErrorPanel title="Tap not recognised" code={sunError} />;

  if (phase === 'exchanging') {
    return (
      <Page title="Starting activation…">
        <p className="small">Verifying your tap…</p>
      </Page>
    );
  }

  if (!sessionToken && !err) {
    return (
      <Page title="Tap your card">
        <p className="small">
          Hold your card flat against the back of your phone to start
          activation.
        </p>
      </Page>
    );
  }

  if (!sessionToken && err) {
    return (
      <Page title="Activation failed" tone="err">
        <p className="small">{err}</p>
        <p className="small">Tap the card to your phone again to retry.</p>
      </Page>
    );
  }

  if (phase === 'done') {
    return (
      <Page title="Card activated" tone="ok">
        {micrositeUrl ? (
          <p className="small">
            Redirecting you to your card's welcome page…
          </p>
        ) : (
          <p className="small">
            You can now use the card for payments. {biometricHint(device)} can be added
            at first checkout.
          </p>
        )}
      </Page>
    );
  }

  // --- Pre-activation: prominent button + per-platform copy --------------
  return (
    <Page title="Activate your card">
      <p className="small" style={{ marginBottom: 16 }}>
        {prePromptCopy(device)}
      </p>
      <button
        className="btn primary"
        onClick={onActivate}
        disabled={phase === 'busy'}
        style={{ width: '100%', padding: '14px 16px', fontSize: 16 }}
      >
        {phase === 'busy' ? 'Waiting for tap…' : 'Activate'}
      </button>
      {err && (
        <div style={{ marginTop: 16 }}>
          <p className="tag err" style={{ marginBottom: 8 }}>
            {friendlyError(err, device)}
          </p>
          <p className="small" style={{ opacity: 0.6 }}>
            Technical: <span className="mono">{err}</span>
          </p>
        </div>
      )}
    </Page>
  );
}

/**
 * Short, platform-tuned line that appears above the Activate button.
 * Rough on intent: on iOS, the user will see a native sheet + security key
 * icon; on Android they'll see a Chrome NFC prompt.  Desktop is dead-end
 * until hybrid transport on the phone is set up.
 */
function prePromptCopy(device: Device): string {
  if (device === 'ios') {
    return 'When you tap Activate, iOS will ask you to hold your card near the top of your iPhone.';
  }
  if (device === 'android') {
    return 'When you tap Activate, Chrome will ask you to hold your card against the back of your phone.';
  }
  return 'Open this link on the phone you just tapped the card with — desktop browsers can\'t complete the NFC step.';
}

/**
 * Translate raw WebAuthn browser errors into actionable language.  Most
 * mobile WebAuthn failures fall into a small set of well-known DOMExceptions;
 * each has a platform-specific cause/remedy.
 */
function friendlyError(raw: string, device: Device): string {
  const r = raw.toLowerCase();

  // "The document is not focused" — iOS Safari + Chrome both throw this when
  // the WebAuthn call wasn't initiated by a user gesture.
  if (r.includes('document is not focused') || r.includes('not focused')) {
    return device === 'ios'
      ? 'Tap the Activate button to start the NFC prompt. iOS needs a button tap before it opens the security-key reader.'
      : 'Tap the Activate button to start the NFC prompt.';
  }

  // AbortError / NotAllowedError — user cancelled, ceremony timed out, or
  // no matching credential on the card.
  if (r.includes('notallowed') || r.includes('aborterror')) {
    return 'The tap was cancelled or timed out. Try again and hold the card against the phone until it vibrates / the prompt closes.';
  }

  // InvalidStateError — usually a stale credential.
  if (r.includes('invalidstateerror')) {
    return 'This card doesn\'t match the stored credential. Contact support if this persists.';
  }

  // Generic NFC / reader failure.
  if (r.includes('nfc') || r.includes('reader')) {
    return device === 'ios'
      ? 'iPhone couldn\'t read the card. Hold it flat across the top of the phone, screen up.'
      : 'Couldn\'t read the card over NFC. Make sure NFC is on and the card is against the back of the phone.';
  }

  // Fall-through.
  return device === 'desktop'
    ? 'Desktop browsers can\'t complete the NFC step. Open the same link on your phone.'
    : 'Activation hit an unexpected error. Tap Activate to try again.';
}

function Page({
  title,
  tone,
  children,
}: {
  title: string;
  tone?: 'ok' | 'err';
  children: React.ReactNode;
}) {
  return (
    <div className="page">
      <h1>{title}</h1>
      <div className="panel">
        {tone && <p className={`tag ${tone}`} style={{ marginBottom: 12 }}>{title}</p>}
        {children}
      </div>
    </div>
  );
}

function ErrorPanel({ title, code }: { title: string; code: string }) {
  return (
    <Page title={title} tone="err">
      <p className="small">
        Reason: <span className="mono">{code}</span>
      </p>
      <p className="small">Tap the card to your phone again to retry.</p>
    </Page>
  );
}
