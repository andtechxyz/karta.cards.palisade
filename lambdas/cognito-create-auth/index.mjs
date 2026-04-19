// CreateAuthChallenge — generates a magic link code and sends it via SES.
// Also handles auto-signup: if the user doesn't exist, Cognito's CUSTOM_AUTH
// with a PreSignUp trigger will auto-create + auto-confirm them.
import { SESClient, SendEmailCommand } from '@aws-sdk/client-ses';
import { randomBytes } from 'node:crypto';

const ses = new SESClient({ region: process.env.AWS_REGION || 'ap-southeast-2' });
const MOBILE_URL = process.env.MOBILE_URL || 'https://mobile.karta.cards';
const FROM_EMAIL = process.env.FROM_EMAIL || 'noreply@karta.cards';

export const handler = async (event) => {
  const email = event.request.userAttributes.email;
  const code = randomBytes(32).toString('hex');

  // Store the code as the expected answer
  event.response.privateChallengeParameters = { code };
  event.response.publicChallengeParameters = { email };
  event.response.challengeMetadata = `MAGIC_LINK_${code}`;

  // Send magic link email via SES
  const magicLink = `${MOBILE_URL}/auth/verify?code=${code}`;
  try {
    await ses.send(new SendEmailCommand({
      Source: FROM_EMAIL,
      Destination: { ToAddresses: [email] },
      Message: {
        Subject: { Data: 'Sign in to Vera Wallet' },
        Body: {
          Html: {
            Data: `
              <div style="font-family: -apple-system, sans-serif; max-width: 480px; margin: 0 auto; padding: 40px 20px;">
                <h2 style="color: #111827; margin-bottom: 8px;">Sign in to Vera Wallet</h2>
                <p style="color: #6b7280; font-size: 16px; line-height: 24px;">
                  Tap the button below to sign in. This link expires in 10 minutes.
                </p>
                <a href="${magicLink}"
                   style="display: inline-block; margin-top: 16px; padding: 14px 28px;
                          background-color: #111827; color: #fff; text-decoration: none;
                          border-radius: 10px; font-size: 16px; font-weight: 600;">
                  Sign in
                </a>
                <p style="color: #9ca3af; font-size: 13px; margin-top: 24px;">
                  If you didn't request this, you can ignore this email.
                </p>
              </div>
            `,
          },
          Text: { Data: `Sign in to Vera Wallet: ${magicLink}` },
        },
      },
    }));
  } catch (err) {
    console.error('SES send failed:', err);
    // Don't fail the challenge — code is still set for testing via logs
  }

  return event;
};
