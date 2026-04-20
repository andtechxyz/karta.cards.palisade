import { timingSafeEqual } from 'node:crypto';

// VerifyAuthChallengeResponse — checks the magic link code using a
// constant-time comparison.  PCI 8.3.1: comparing authentication secrets
// with === can leak the prefix length of the correct code via timing
// (every byte compared before the first mismatch costs measurable µs).
// timingSafeEqual runs in time dependent only on buffer length, not content.
// We also pad both sides to the max of their byte lengths so the buffer
// length itself doesn't leak the expected code length — the pad is then
// compared but cannot equal the padded-out expected unless the caller
// matched length-for-length.
export const handler = async (event) => {
  const expected = event.request.privateChallengeParameters.code ?? '';
  const answer = event.request.challengeAnswer ?? '';

  const a = Buffer.from(String(expected), 'utf8');
  const b = Buffer.from(String(answer), 'utf8');

  // Pad shorter side to match length so timingSafeEqual doesn't throw.
  // The length-mismatch case still has to return false; pad with a byte
  // guaranteed not to equal any character in the other buffer's position.
  const len = Math.max(a.length, b.length, 1);
  const aPad = Buffer.alloc(len, 0);
  const bPad = Buffer.alloc(len, 1); // different fill => mismatch on pad
  a.copy(aPad);
  b.copy(bPad);

  const equalLen = a.length === b.length;
  const equalBytes = timingSafeEqual(aPad, bPad);
  event.response.answerCorrect = equalLen && equalBytes;

  return event;
};
