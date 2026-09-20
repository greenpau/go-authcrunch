---
name: refresh-token-implementation
description: Implement or change AuthCrunch portal refresh configuration, opaque token families, atomic rotation, replay revocation, issuance claims, store adapters, and portal lifecycle. Use for portal refresh tokens, not upstream OAuth token renewal.
---

# Refresh Token Implementation

The implementation is opt-in under `authn.PortalConfig.RefreshTokens`. The
reusable token/session engine lives at `pkg/authn/token_refresh`, with Go package
identifier `tokenrefresh`. Use that import path and qualifier in consumers. Read
[configuration and client contract](references/configuration-and-clients.md)
when exposing settings, integrating clients, or changing public behavior.
Use `refresh-token-identity` for login proof and identity revalidation, and
`refresh-token-transports` for HTTP, cookies, browser coordination, and logout.
These are distinct boundaries; a change may require more than one owner.

Directive support here is the public parser package and its portal
integration. The block example in the client contract describes an embedding
parser's input; it does not establish implemented Caddyfile support. Keep the
parser and its unit/E2E coverage in this module. Never modify sibling
directories for consumer integration; those repositories are updated separately.

## Ownership

- `pkg/authn/token_refresh_config.go`: serializable config, defaults, canonical HTTPS
  origin/mount validation, cookie naming, durations, and capacity bounds.
  The public type is `authn.TokenRefreshConfig`. An empty `CookieName` inherits
  the portal cookie factory; validation must leave it empty. An enabled explicit
  override feeds `cookie_config.refresh_token_cookie_name` before the factory's
  defaults and collision checks. The factory owns the effective runtime name.
- `pkg/authn/token_refresh/parser`: public
  `NewTokenRefreshConfigFromDirectives([]string) (*authn.TokenRefreshConfig, error)`,
  using `cfgutil.DecodeArgs` for encoded statements from `token refresh` blocks.
  Directive keys use separate words; states use `enabled`/`disabled` keywords.
  Construction opts in, rejects
  duplicate/unknown/malformed directives, and delegates normalization to
  `authn.TokenRefreshConfig.Validate`. This package owns the parser implementation and
  its external-package unit tests; the portal model remains in `pkg/authn`.
  Additional `authn.TokenRefreshConfig` settings need corresponding grammar in
  this constructor and consumer coverage through `PortalConfig.RefreshTokens`.
- `pkg/authn/portal.go`: configured-realm capability checks, manager creation,
  failed-construction cleanup, and `Portal.Close()`.
- `pkg/authn/token_issuer.go`: shared access/refresh issuance. HTTP and JSON
  sandbox login must call the same issuer; `grantAccess` only delivers signed output.
- `pkg/authn/token_refresh_runtime.go`: portal adapters, current transformations,
  challenge checks, and KMS signing.
- `pkg/authn/token_refresh/{token,store,memory,manager}.go`: opaque encoding, store
  contract, bounded in-memory families, and staged issuance/rotation.
- `pkg/kms/crypto_keystore.go`: actual access signing-key lifetime selection.

## Issuance and State

A refresh family originates only from a completed, single-use local login.
An access JWT, user-supplied method list, or refresh token from an OAuth provider
cannot create that evidence. Disabled refresh allocates no store and preserves
existing access-token lifetime behavior. Unsupported or ambiguous configured
realms fail portal construction; never silently claim renewal support.

Raw refresh credentials use `acr1_` plus 32 random bytes in canonical unpadded
base64url. Persist only their SHA-256 digests. Public `sid` and `jti` values
are independently random and do not encode credentials. Session snapshots must
copy owned slices; caller mutation must not change stored grants.

Keep the family binding fixed: portal, exact origin, mount, and transport.
Retain immutable backend/user identity, original authentication evidence,
original audience/scope grant, current and spent digests, revision, and idle and
absolute deadlines. Every renewal has a new `jti`, `iat`, `nbf`, and `exp`;
`sid`, `sub`, `iss`, `auth_time`, and verified `amr` stay bound to the login.
Rebuild roles from current identity and transformations. Audiences and scopes
can shrink but cannot expand, and transformations cannot invent `acr` or
replace the authentication event. Losing all originally granted audiences
requires login. Cap access expiry by both refresh config and the selected
access signing key, ignoring system-only signing keys.

Stage identity revalidation, the next opaque token, and JWT signing before
committing. `Store.Rotate` must atomically recheck current digest, revision,
revocation, idle/absolute deadlines, and staged JWT expiry. Return credentials
only after commit. A signing or transient backend failure leaves the current
credential unspent; a definitive identity denial revokes the family.

A known spent token with the correct binding revokes its entire family,
including the current descendant. Unknown tokens or wrong bindings cannot
revoke another family. Keep every spent digest while a descendant remains live.
A terminal family may be removed in full; never drop only its replay history.
Strict concurrent reuse can return one success followed by family revocation;
there is no grace period or transparent retry of an ambiguous exchange.

`Manager.RefreshForSession` accepts a required expected SID and checks it after
credential lookup, before signing or rotation. A valid credential for a different
family is left unspent. `Manager.Refresh` remains the compatible unconditioned
entry point. `Manager.GetSessionID` returns only the family ID without issuance
or identity revalidation; it retains normal lookup replay checks. These methods
do not relax the Store contract or turn a SID into authentication evidence.
Use the transport owner for browser bootstrap, the session metadata endpoint,
and rules against looking up an uncertain credential.

## Lifetime and Extension

The portal constructs its bounded `MemoryStore`. Capacity fails closed; exhausted
rotation limits require login. Cleanup occurs on creation, not through an extra
refresh goroutine. Without `Config.State`, restart, portal replacement, and local
identity database reload require fresh authentication. Opt-in
[runtime-state](../runtime-state/SKILL.md) attaches durable snapshots before use,
retaining complete live families and spent history, with a matching local identity
epoch. Storage errors fail closed; Close discards memory but preserves snapshots. Quiesce requests before
`Portal.Close()`; failed construction must stop and await owned cache workers as
well. `Server.Close()` owns portal disposal and reverse construction cleanup;
standalone portal consumers still call Close themselves after draining requests.
Closed portal HTTP/BasicAuth entry points reject new work. See the
[embedding lifecycle](../coding-directives/references/embedding-integration.md)
for host ownership and replacement boundaries.

The serialized record limit can be reached below the configured family/rotation
counts. Prepare a candidate with `Record.PrepareEncode`; on capacity refusal,
leave the old current digest, revision, deadlines, and history intact. Restore
every replacement target on refused fresh issuance. Keep the shared store usable
and permit logout/replay revocation to remove whole families. A disk commit error
still disables the component. Test capacity against actual encoded size,
including restart and unrelated record writes.

`MemoryStore` removes a whole family immediately on explicit/replay/identity
revocation or rotation exhaustion. Creation reclaims idle- or absolutely expired
families; lookup also removes an expired presented family. All digests disappear
together because no usable descendant remains. Later old replay is an unknown
credential and cannot affect a new family. Live families retain the initial plus
at most `MaxRotations` descendant digests, bounding storage by `MaxSessions`
families and `MaxSessions * (MaxRotations + 1)` digest entries. No tombstone map,
live eviction, replay grace, or cleanup worker is needed. Trusted store callers
must generate fresh unpredictable IDs/credentials, never resurrect snapshots.

`Manager.IssueReplacing` stages identity checks/signing and uses the optional
`ReplacementStore.CreateReplacing` transaction to retire presented families and
admit a fresh login at full capacity. It matches the complete new binding,
deduplicates presented families, rejects retained ID/digest collisions, and
preserves every live family on failed commit. Current or spent old credentials
may identify replacement targets only after independent fresh authentication.
Malformed/unknown credentials cannot evict anything. With a syntactically valid
previous token, an adapter lacking this optional interface returns
`ErrUnavailable`; the original `Store` and `Manager.Issue` API remain supported.

Portal browser issuance supplies the effective refresh-cookie values, including
duplicate paths, to this transaction. Native/API-key login stays independent.
Subsequent cookie deletion and OIDC completion are outside the store transaction.
HTML and JSON completion discard a newly committed, undelivered refresh family on error,
including OIDC capacity or identity failure. Cleanup uses a bounded context
independent of request cancellation; cleanup failure remains an unavailable
error. Previously replaced families remain revoked. This releases admission for
a new login after the downstream failure recovers. An all-live full store rejects an
independent login that does not present a family it can replace. Unobserved
identity-version invalidation can retain a slot until a denial, logout, or
expiry; backend mutations do not eagerly enumerate the store's families.
Preserve deterministic capacity/replay/concurrency tests and actual parser-based
TLS form/JSON logout/relogin/replacement coverage at capacity one.

A distributed adapter must satisfy the `Store` atomicity contract across all
instances and coordinate identity changes with issuance. Implementing an
interface alone does not expose configurable distributed storage. Do not promise
distributed continuity, upstream refresh, or immediate revocation of stateless
access JWTs. Local restart continuity is supplied by the runtime-state integration,
not by the Store interface alone.

## Validation

Use `make test TEST_DIR='./pkg/authn/... ./pkg/identity ./pkg/ids/local ./pkg/kms'`
and `make test-ui` for an affected-flow run; `make test` covers all Go packages
with race detection and reports. The narrow suites are
`pkg/authn/token_refresh/manager_test.go`, `pkg/authn/token_refresh_config_test.go`, and
`pkg/authn/handle_api_refresh_token_test.go`. Preserve concurrent reuse,
logout-during-signing, failed-signing retry, replay isolation, expiry during
commit, capacity, realm capability, disabled-feature, and single-use-login cases.
Run parser unit tests and examples with
`make test TEST_DIR='./pkg/authn/token_refresh/parser'`; its consumer E2E tests
remain in `pkg/authn/token_refresh_config_parser_e2e_test.go` and use the public parser
through the shared TLS portal fixture.
`TestTokenRefreshCookieConfiguration` covers inherited names, directive override
precedence, disabled configuration, malformed names, and collisions with every
other portal cookie role. `TestE2ETokenRefreshCookieLifecycle` uses a real cookie
jar for default/custom names, legacy-path cleanup, rotation, and logout.
Fuzz token grammar with
`go test ./pkg/authn/token_refresh -run '^$' -fuzz FuzzRefreshToken -fuzztime 5s`.
