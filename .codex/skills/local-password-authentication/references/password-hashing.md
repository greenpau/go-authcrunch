# Password hashing contracts

## Representations and compatibility

Configuration imports use these exact forms:

- `bcrypt:<cost>:<bcrypt hash>` (existing format).
- `argon2:$argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>`.

Argon2id v19 is the supported Argon2 variant. Reject Argon2i, Argon2d, older
versions, reordered/duplicate/unknown parameters, missing fields, signed or
noncanonical decimal numbers, padded/noncanonical Base64, extra fields and
unsupported resource requirements. Salt/hash use standard unpadded Base64.
The outer prefix is `argon2:`, not `argon2id:`; there is no outer bcrypt-like
cost field. `ParseHashedPassword` accepts only the complete prefixed form.
`NewPassword` and creation/replacement constructors trim outer whitespace.
Authentication treats the submitted candidate solely as plaintext.

The persisted `identity.Password` uses `Algorithm: "argon2"`, the complete PHC
string in `Hash`, and no `Cost`. Parameters remain in the PHC string so serialized
JSON/XML/YAML records do not depend on a second copy of work factors. Bcrypt
records keep their format; omitted algorithm means historical bcrypt. Imported
bcrypt hashes must be structurally valid and match the outer cost. Malformed
imports return errors without credential material or partially usable records.
Bcrypt imports require canonical decimal outer cost, two encoded cost digits,
exact separators, known `$2$`/`$2a$`/`$2b$`/`$2x$`/`$2y$` headers, and canonical
bcrypt Base64 salt/checksum encodings. `bcrypt.Cost` alone does not validate
that grammar. Import validation must not run the expensive comparison.

`Password.Match` dispatches by algorithm. Database authentication additionally
pads every lookup to the store-wide schedule; do not replace it with Match or
User.VerifyPassword. Reusing a hash does not bypass credential-version updates.

Default creation (`NewPassword`, a new user or bcrypt user's plaintext
replacement) remains bcrypt cost 10. Argon2 is explicit through generation
options or prefixed import. An Argon2 user's plaintext password change/reset
retains Argon2 with current defaults, even when its imported parameters were
weaker. Explicit imports can switch algorithms. Login does not automatically
rehash. API key generation and verification remain bcrypt.

A valid encoded import is not subject to plaintext length policy; the plaintext
is unavailable and its compliance cannot be proved from a hash. Plaintext
creation/replacement still uses the database policy. Bcrypt's 72-byte generation
limit does not apply to Argon2. Existing login transport whitespace rules remain
unchanged.

Imports are a trusted provisioning operation. Public registration and identity-bound
self-service password changes reject reserved `bcrypt:`/`argon2:` prefixes,
including malformed imports and surrounding whitespace, through
`identity.IsPasswordHashImport`. Do not let these inputs choose a stored work
profile: the database pads every account's login to the shared profile schedule.
The generic database creation/change/update/reset APIs remain import-capable for
trusted callers. Login still compares raw plaintext, even when a stored password's
plaintext contains a reserved prefix. Rejected self-service imports must leave
credentials, revision and authentication evidence unchanged.

`Database.CheckPasswordPolicyCompliance` checks only password policy, independently
of username constraints. It uses the same outer-whitespace normalization as
password creation. Hash generation consumers should use this method instead of
passing a placeholder username to `CheckPolicyCompliance`.

## Public generation APIs

`identity.PasswordHashConfig` in `pkg/identity/password_hash_config.go` owns:

| Field | Meaning | Default |
| --- | --- | --- |
| `Algorithm` | `bcrypt` or `argon2` | `bcrypt` |
| `Cost` | bcrypt work factor | 10 for bcrypt |
| `Memory` | Argon2 memory, KiB | 65536 |
| `Iterations` | Argon2 passes | 3 |
| `Parallelism` | Argon2 lanes | 4 |

`Validate` applies zero-value defaults and enforces bounds and algorithm-specific
settings. `NewPasswordWithConfig(plaintext, purpose, config)` validates a copy,
then imports or generates a password. `Password.EncodedHash()` formats its
configuration import representation. Configured generation uses cryptographic
random 16-byte salts and 32-byte output, and constant-time derived-key comparison.
These defaults follow the second recommendation in
[RFC 9106 section 4](https://www.rfc-editor.org/rfc/rfc9106.html#section-4), using
`golang.org/x/crypto/argon2.IDKey` from the existing pinned dependency.

`NewPasswordWithOptions` remains compatible with its existing signature.
Its parameter map accepts `int` values: `cost` for bcrypt, or `memory`,
`iterations`, `parallelism` for Argon2. Reject unsupported names/types and invalid
Argon2 values without panic. Recognized imports carry their own algorithm and
parameters; generation options do not rewrite an import.

## Dedicated directive parser

Package: `github.com/greenpau/go-authcrunch/pkg/identity/password/parser`.
Constructor: `NewPasswordHashConfigFromDirectives(statements []string)` returns
`(*identity.PasswordHashConfig, error)`.

It accepts a block body, with no enclosing header or braces:

```text
algorithm argon2
memory 65536
iterations 3
parallelism 4
```

Bcrypt uses `algorithm bcrypt` and optional `cost 10`. Each setting takes exactly
one argument and occurs once. Adapters encode each tokenized statement using
`cfgutil.EncodeArgs`; the parser uses `DecodeArgs`, rejects raw CR/LF and invalid
arity/duplicates, and delegates normalization to `PasswordHashConfig.Validate`.
An empty list selects bcrypt cost 10. Explicit numeric values must be positive;
inapplicable settings are errors. Parsing never generates credentials or starts
workers. Apply the typed result through `NewPasswordWithConfig`.

## Resource limits

Both generation and import enforce:

- Memory at least `8 * parallelism` KiB and at most 262144 KiB (256 MiB).
- Iterations 1–10 and parallelism 1–16.
- Memory times iterations at most 1048576 KiB-passes.
- Imported salt 8–64 bytes, output 16–64 bytes, PHC string at most 256 bytes.

Validate the complete string before calling the KDF, including for persisted
records. Do not allocate based on unchecked numbers or perform work at rejected
costs. Custom parameters within these bounds can be weak: bounds prevent invalid
or excessive work, not enforce password strength. Prefer generation defaults and
measure latency before tuning. The RFC's 2 GiB option is outside this server's
supported import bound and is intentionally rejected.

Mixed work profiles add sequential hashing per attempt to preserve the existing
account-enumeration defense. Locks remain held across schedule construction and
verification. This is expensive-work equalization, not a guarantee of identical
wall-clock time or process-wide memory admission across independent stores.

## CLI and validation

`authdbctl generate password hash --algorithm argon2` prompts without echo and
prints a quoted `password "argon2:..."` line. Optional `--memory`, `--iterations`
and `--parallelism` map through the shared parser. `--cost` is bcrypt-only.
`--db-path` selects plaintext policy and does not override requested work factors.
Do not print supplied plaintext fragments. See the CLI owner for executable and
terminal test rules.

```sh
make test TEST_DIR='./pkg/identity/... ./pkg/ids/local ./pkg/authn ./cmd/authdbctl'
go test -mod=readonly ./pkg/identity -run '^$' -fuzz '^FuzzParseArgon2$' -fuzztime 10s
make ci-check
```

`PasswordHashConfig` is registered in `internal/tag/tag_test.go`; its dedicated
unit test also round-trips JSON, XML and YAML. The PHC tests include independent
Argon2 reference vectors. Scheduling tests
instrument completed bcrypt comparisons and Argon2 derivations, including profile
lengths, success without early return, missing/disabled/expired identities and
matching dummies. Keep these deterministic work assertions alongside actual
cryptographic matching, persistence and consumer E2E tests.
