// VerifyAuthChallengeResponse — checks the magic link code.
export const handler = async (event) => {
  const expected = event.request.privateChallengeParameters.code;
  const answer = event.request.challengeAnswer;

  event.response.answerCorrect = expected === answer;

  return event;
};
