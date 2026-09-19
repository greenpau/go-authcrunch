---
name: authentication-portal-mfa
description: Maintain portal TOTP and WebAuthn login checkpoints and enrollment, server-side challenges, factor-specific verification, replay prevention, and real TLS MFA journeys.
---

# Authentication Portal MFA

`handle_http_sandbox.go` and `handle_json_login.go` own login checkpoints;
`webauthn_enrollment.go` and the profile U2F API handlers own registration state.
`pkg/identity` owns credential validation, durable TOTP consumption and mutation.
Use [local database transactions](../local-identity-database/SKILL.md) and
[canonical login evidence](../refresh-token-identity/SKILL.md) at those boundaries.

Use [authentication challenge policies](../authentication-portal-challenges/SKILL.md)
for conditional selection, user-transform/parser APIs, and AMR issuance. Successful
verification sets the server-only `Checkpoint.Method`; enrollment never does.
JSON hardware authentication must retain its server challenge and pass the actual
assertion to the backend, including when U2F is the first checkpoint.
After generating a JSON WebAuthn assertion challenge, return immediately and
wait for its signed response. Do not visit later password/TOTP checkpoints or
set authentication evidence during challenge issuance. Cover WebAuthn before,
after, and between other factors through HTML and JSON, including generic MFA
selection and additive password requirements.

Keep required factor types distinct. A totp checkpoint cannot pass with U2F,
and a u2f checkpoint cannot pass with TOTP; only generic mfa permits selection.
Seed every MFA backend operation with the original server-held LoginEvidence,
including lockout check/increment/reset and TOTP consumption. Authentication can
clear request evidence on failure; restore the original proof before counting a
failure. A password reset, role change, revocation or replacement must prevent
old sandboxes from consuming codes or mutating the current account's lockout.

Cross-realm lockout E2E tests must establish fresh password evidence for each
attempt: refreshing a database alias can invalidate its older sandbox epoch.
Keep separate stale-sandbox tests proving rejected evidence cannot consume a
code or increment current lockout state. Invalid TOTP fixtures must exclude
accepted neighboring time steps as well as the current code.

Login TOTP uses atomic `ConsumeMfaTOTP`, not stateless diagnostic passcode checks.
A test reusing the same accepted step must fail. Successful sequential fixture
logins need a fresh step; do not weaken persistent replay protection for tests.
Login WebAuthn requires the server challenge and exact expected origin, RP hash,
client-data type, signature and user presence. Trusted request metadata derives
the origin; forwarded-header normalization belongs to the embedding server.

The current `u2f` route supports account-first WebAuthn, including as the sole
authentication checkpoint. It requests `user_verification: "discouraged"` and
requires user presence; it does not require the authenticator's UV flag. Do not
describe factor-only selection as username-free/discoverable-credential login
or a guarantee of PIN/biometric verification. Those capabilities need separate
protocol/configuration work and browser/authenticator validation.

Enrollment is a credential mutation, never authentication with the new factor.
Sandbox first-factor enrollment requires no enabled existing factor and current
identity evidence. After successful enrollment require a new completed login;
never advance the original sandbox's evidence version to allow token issuance.

Keep `mfa_add_app.js` and `sandbox_mfa_add_app.js` aligned when changing TOTP
enrollment rendering. Encode each OTP label/query component independently and
the QR payload as one URL path segment. Resolve the QR endpoint against the
portal origin and require same-origin HTTP(S) before assigning the image URL.
DOM text must remain data throughout link and image construction. Cover both
scripts with the MFA DOM client tests and the real Chrome rendering fixture.

WebAuthn enrollment state is local to the portal: 5-minute expiry, 4096-entry
bound, single use, discarded on Close/restart. Bind it to realm, canonical account,
immutable ID, backend/credential versions, session, origin and profile/sandbox
scope. Creation uses a random server challenge. Profile registration pins the
validated payload digest and requires a signature over a separate server-issued
proof challenge before final save. Atomically claim verification, verify outside
the state lock, then recheck entry identity/expiry. Consume before persistence;
a failed write requires restarting the ceremony.

The legacy profile client carries the original creation challenge in later
requests while the signed proof contains the distinct proof challenge. Preserve
that wire contract. `identity.ValidateWebAuthnRegistration` validates creation
client data, RP hash, flags, credential IDs and typed COSE input before key
construction; it does not verify an attestation statement. Its compatibility
allowance for the known legacy nested credential-ID truncation is exact, not an
arbitrary-prefix exemption. Trusted provisioning constructors remain separate.

Unit tests cover state phases, clock boundaries, concurrency, digest/binding
changes and malformed creation data. TLS enrollment tests cover direct-save
rejection, wrong user/session/origin/challenge, replay, changed identity, transformed
claims, renewed sessions, persistent key ownership and a fresh signed hardware
login. Browser hardware/attestation certification needs separate evidence;
synthetic signatures do not establish it.
