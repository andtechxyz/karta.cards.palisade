// DefineAuthChallenge — routes the custom auth flow.
// First call: issue CUSTOM_CHALLENGE. After correct answer: succeed.
export const handler = async (event) => {
  const session = event.request.session;

  if (session.length === 0) {
    // No challenges yet — issue one
    event.response.issueTokens = false;
    event.response.failAuthentication = false;
    event.response.challengeName = 'CUSTOM_CHALLENGE';
  } else if (
    session.length === 1 &&
    session[0].challengeName === 'CUSTOM_CHALLENGE' &&
    session[0].challengeResult === true
  ) {
    // Challenge answered correctly — issue tokens
    event.response.issueTokens = true;
    event.response.failAuthentication = false;
  } else {
    // Wrong answer or too many attempts
    event.response.issueTokens = false;
    event.response.failAuthentication = true;
  }

  return event;
};
