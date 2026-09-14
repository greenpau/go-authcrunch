---
name: identity-public-keys
description: Maintain user-owned GPG and SSH public-key parsing, profile API registration, identity database persistence, format compatibility, and maintained OpenPGP dependencies. Excludes portal signing-key publication and admin private-key export.
---

# Identity Public Keys

## Ownership and Input Boundary

`pkg/identity/public_key.go` owns `NewPublicKey` and format parsing.
`User.AddPublicKey` rejects duplicate keys; `Database.AddPublicKey` checks the
username/email identity pair under its lock and commits the identity data.
`pkg/ids/local/store.go` and `authenticator.go` dispatch `AddKeyGPG`/`AddKeySSH`.
These user-owned public keys are distinct from JWT signing keys in `pkg/kms`.

The portal profile API calls `AddUserGPGKey` in
`pkg/authn/api_add_user_gpg_key.go`. `handle_api_profile.go` requires a valid
authenticated session, an allowed user/admin role, and a local identity store
before dispatching a parsed operation. Its request body limit is one MiB.
The backend identity comes from the authenticated session; request fields must
not choose another user's inventory. Direct Go callers of the identity database
own authorization and input-size limits; the database itself is not an HTTP
authorization boundary.

## OpenPGP Compatibility

Use the maintained `github.com/ProtonMail/go-crypto/openpgp` package pinned by
`go.mod`; do not reintroduce `golang.org/x/crypto/openpgp`. The latter import
predates v1.1.41 and is covered by
[GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932), which lists no fixed version
of that unmaintained package. Other `x/crypto` packages remain dependencies.
Review the current advisory and maintained package guidance for future changes.
Check the replacement's transitive dependencies too: ProtonMail v1.4.1 selects
CIRCL v1.6.2, so this repository pins CIRCL v1.6.3 to include the fix for
[GO-2026-4550](https://pkg.go.dev/vuln/GO-2026-4550). A maintained direct
dependency alone does not establish that its selected dependency graph is current.

The repository uses `ReadArmoredKeyRing` to inspect public-key metadata. It
does not call OpenPGP message decryption, encryption, signing, or detached
signature verification. A broad advisory or interface-based scan trace does
not establish an authentication bypass or an exploitable cryptographic operation.
An authenticated user can supply parsing input through the profile API, and
library callers may supply it directly; retain strict errors and bounded HTTP
input. Package maintenance is necessary without claiming an exploit.

Preserve the actual public format contract:

- Accepted dispatches are RSA public PEM, `ssh-rsa` authorized-key text, and
  ASCII-armored `PGP PUBLIC KEY BLOCK` data with matching boundaries.
- OpenPGP parsing requires one entity, a primary public key, and identities.
  Keep the existing RSA/DSA/ECDH/ECDSA algorithm policy, key ID, lowercase
  fingerprint, comment, normalized payload, and persisted fields stable.
- Raw binary OpenPGP and private-key armor are not accepted by `NewPublicKey`.
  Do not describe a dependency's broader API as existing repository support.
- This path records a public key; it does not establish external trust,
  ownership, revocation status, or suitability for a new cryptographic use.
  Preserve historical fixture import behavior, including older public keys.

Persisted `PublicKey` data is an identity record, not directive configuration;
the migration adds no new configuration fields or parser grammar. Existing
parser-package requirements apply if configurable policy is introduced later.

## Validation

`pkg/identity/public_key_pgp_test.go` checks the legacy armored fixture's exact
metadata and rejects malformed armor, invalid packets, multiple entities,
private armor, and unsupported binary input. Retain existing RSA/SSH tests.
`server_public_key_e2e_test.go` uses the public root server and real TLS login
for profile upload/list, duplicate rejection, database reopen, runtime reload,
and another user's empty inventory. Do not inject an authenticated user into
that fixture or replace it with an in-memory parser-only test.

```sh
make test TEST_DIR='./pkg/identity .' TEST='PublicKey|PGP' COVERAGE_DIR=.coverage/identity-public-keys
make ci-check
```

Run a versioned vulnerability scan after dependency changes, using the selected
patched Go build toolchain. Separate inherited dependency findings from newly
introduced code defects, and retain the scanner output and format compatibility
evidence. Never log uploaded key payloads or unrelated identity credentials.
