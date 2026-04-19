// PreSignUp — auto-confirm new users so magic link flow works for first-time users.
// Without this, Cognito rejects unknown emails during CUSTOM_AUTH.
export const handler = async (event) => {
  event.response.autoConfirmUser = true;
  // Auto-verify email since that's how they signed up
  event.response.autoVerifyEmail = true;
  return event;
};
