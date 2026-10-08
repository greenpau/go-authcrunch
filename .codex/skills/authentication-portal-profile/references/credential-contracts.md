# Credential records and diagnostics

Profile API-key upload trims content and requires 64–72 ASCII letters/digits.
Local enrollment stores a cost-10 bcrypt verifier, a random 40-character record
ID and the raw secret's first 24 characters as a database-wide lookup prefix.
The authenticated owner can retrieve the verifier; fetch/list are not secret
redaction APIs. Disabled records are filtered, but expired alone does not hide
one. Record timestamps, including zero-time values, follow the stored serializer.

The no-explicit-prefix database enrollment path retries a prefix collision
without replacing the supplied key. Identical uploads, a shared 24-character
prefix and collisions across accounts can therefore stall under its database
lock. Do not document a clean HTTP 400 duplicate response or automatic safe
retry. The trusted explicit-prefix provisioning branch behaves differently.
This is an existing runtime behavior documented by source review.

The owned-ID diagnostic compares untrimmed input directly to bcrypt. Success is
HTTP 200 with `entry: "OK"`; mismatch/missing/disabled/foreign ID is HTTP 500.
A 72-byte secret plus suffix can pass bcrypt's comparison, while local login
rejects secrets longer than 72 bytes. Diagnostics are not login-policy checks.
Deletion removes the lookup prefix and stops new raw-key logins; it does not
advance credential generation or revoke a previously issued stateless JWT.

TOTP save uses SHA-1 and does not require or verify a passcode. Unknown algorithm
or passcode fields cannot change this behavior. Exact duplicate raw secrets or
exact titles are rejected, including disabled records. Enrollment advances
credential generation; complete fresh password/MFA login before another profile
operation. Secrets are literal ASCII bytes; QR construction Base32-encodes them
for authenticator applications. Periods/digits are numeric, with current profile
float-to-integer truncation documented in the YAML.

The passcode diagnostic rejects surrounding whitespace and accepts 4–8 digit
strings before applying the stored factor's count/time checks. Its window covers
the current and two preceding steps. It does not consume a code or advance the
login replay counter. Well-formed wrong codes return HTTP 200/success=false;
malformed codes return 400 and absent/foreign/disabled IDs return 500. It performs
no explicit factor-type admission check.

Returned password verifiers require algorithm-dependent meanings: bcrypt cost
is logarithmic; Argon2id v19 encodes memory in KiB, passes and lanes in its PHC
string while the stored algorithm label is `argon2`. Follow the
[password hashing owner](../../local-password-authentication/references/password-hashing.md)
for trusted import limits and canonical encodings. The OpenAPI named hash models
preserve these units, syntax and cross-parameter constraints.

`pkg/authn/openapi_credentials_e2e_test.go` drives real TLS enrollment,
diagnostics, raw-key login/deletion, retained JWT use and fresh TOTP login.
`internal/openapi/credential_contract_test.go` compares the validators and actual
stored verifier encodings with schemas. No diagnostic substitutes for the
independent login, replay, persistence or ownership suites.
