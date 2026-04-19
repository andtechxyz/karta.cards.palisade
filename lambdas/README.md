# Lambdas

Cognito custom-auth triggers for the karta.cards mobile app's magic-link flow.

| Function                        | Cognito hook                  | Purpose                                                              |
|---------------------------------|-------------------------------|----------------------------------------------------------------------|
| `cognito-pre-signup/`           | PreSignUp                     | Auto-confirm + auto-verify email so first-time users skip the OTP step. |
| `cognito-define-auth/`          | DefineAuthChallenge           | State machine: issue CUSTOM_CHALLENGE → succeed on correct answer.  |
| `cognito-create-auth/`          | CreateAuthChallenge           | Generates a 32-byte hex code, sends magic-link email via SES.       |
| `cognito-verify-auth/`          | VerifyAuthChallengeResponse   | Constant-time-equality check between expected code and submitted answer. |

Each is a single ESM file (`index.mjs`) deployed as `palisade-<dir-name>` in `ap-southeast-2`, runtime `nodejs22.x`.

## Deploy / update

These are NOT in the main ECS deploy pipeline.  Update one by hand when its source changes:

```bash
cd lambdas/cognito-create-auth
zip -r function.zip index.mjs
aws lambda update-function-code \
  --region ap-southeast-2 \
  --function-name palisade-cognito-create-auth \
  --zip-file fileb://function.zip
rm function.zip
```

`cognito-create-auth` is the only one with a runtime dependency (`@aws-sdk/client-ses`).  AWS Lambda's Node 22 image bundles AWS SDK v3 — no `node_modules/` needed.

## Cognito wiring

The User Pool's Lambda triggers reference these by ARN.  Pool ID: `ap-southeast-2_Db4d1vpIV`.  Don't change the function names without updating the pool config first.

## Runtime upgrades

AWS deprecates Node.js Lambda runtimes ~6 months after the underlying Node EOL.  When a new LTS lands:

```bash
for fn in palisade-cognito-define-auth palisade-cognito-verify-auth \
          palisade-cognito-create-auth palisade-cognito-pre-signup; do
  aws lambda update-function-configuration \
    --region ap-southeast-2 --function-name "$fn" \
    --runtime nodejs<NN>.x
done
```

In-place runtime bumps are safe between Node LTS majors for these handlers — none use a removed API.
