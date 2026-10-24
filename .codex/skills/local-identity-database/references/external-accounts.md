# External account attachments

## Configuration and ownership

`pkg/identity/attachment.Config.LocalIdentityStore` selects a named local store.
The JSON/XML/YAML envelope is `attachment: {local_identity_store: localdb}`.
`attachment/parser.NewIdentityAttachmentConfigFromDirectives([]string)` accepts
one complete encoded statement `attach to local identity store localdb`.
Empty input means a private memory store. Duplicate/malformed directives and
`:memory:` as an explicit target name fail; omission selects memory.
OAuth's full typed parser and shared `idp/parser` adapter delegate this clause.
SAML and LDAP accept the same typed attachment or `Params["attachment"]` through
their shared dispatchers. Their remaining legacy settings have no full body
parser; the new attachment grammar is owned solely by the reusable parser.
The SQLite ticket provider's parser delegates this clause too.

Every built-in OAuth, SAML, LDAP and SQLite ticket instance owns an
`attachment.Attachment` and exposes `attachment.Consumer.IdentityAttachment`.
`ids.BindIdentityAttachment(backend, stores)` resolves explicit targets to one
configured concrete `*local.IdentityStore`, rejecting missing, ambiguous or
wrong-kind stores. Call it after store configuration and before serving.
The lower-level `attachment.BindStore(attachment, concreteStorePointer)` accepts
only a pointer implementing `attachment.Store`; typed nil pointers are rejected.
Binding the same instance is idempotent, while a different pointer fails even
if it wraps the same storage. Preserve this instance boundary without reflection.
`NewServer` binds its owned providers and LDAP stores, including direct OAuth policies.
`NewPortal` also binds selected injected backends against its supplied stores.
Only the target's existence is required for provisioning; enable its local realm
in the portal for connection confirmation and local factor challenges.
Do not copy the local database or silently fall back to memory for a broken name.

For a borrowed provider passed through `ServerOptions.IdentityProviders`, the
default is to preserve its attachment: unnamed memory stays lazy, and an explicit
name must already be bound. To bind a fresh provider to a store that this root
will construct, set `ServerOptions.IdentityProviderAttachmentStores` to a map of
provider name to exact local-store name. Include the typed attachment in the
normalized backend used for its external provider descriptor. This map is
runtime-only; it does not replace that declarative persistence binding.

Opt-in preflight requires a matching external provider descriptor and ready
runtime handle, a nonnil Consumer attachment whose nonempty StoreName equals the
target, and exactly one enabled built-in local store declaration. Missing,
disabled, duplicate, external or wrong-kind targets fail before root resources
open. An already-bound opted provider also fails early; its pointer cannot be the
new root's store. The root captures the attachment once under sanitized plugin
metadata checks, configures the actual local store and its persistent epoch, and
binds that pointer before any portal is published. Several fresh providers may
share that store. Binding does not enable its local realm on a portal. A target
named `:memory:` is invalid; a named local store with path `:memory:` is valid
for a nonpersistent root.

The root still never configures or closes the borrowed provider, replaces its
dynamic instance, or installs state in a borrowed store. A later construction
failure can leave the provider bound to the candidate's store. Discard that
unpublished provider and create a fresh one for retry; failed root construction
does not undo the binding or every earlier file write. The root releases its own
components and state lock. Drain consumers before disposing the root and then
the host-owned provider. Without explicit opt-in, existing caller-owned bindings
and optional non-Consumer compatibility retain their prior behavior.

Omitted attachments lazily create `identity.NewDatabase(":memory:")` directly,
without a generated administrator, file, local login realm or background worker.
The memory sentinel never reads a same-named working-directory file. Existing
filesystem identities, roles and policy cannot seed an implicit provider store.
They belong to the provider instance and are shared by its consumers. Replacing
that provider loses its implicit identities; persisted evidence against them must
fail closed. Attach to a file-backed local store when identity continuity is
required. Hosts must preserve the store epoch using the existing runtime-state
contract when keeping refresh/session evidence over restart. Legacy injected HTTP
providers without the optional capability get a portal-lifetime private memory
attachment; implement the capability to share an attachment across portals.
Provider wrappers must forward optional attachment capabilities.

## Identity and provisioning

An external key is the exact tuple `(provider name, kind, issuer, subject)`.
No case folding, delimiter concatenation, email lookup, or transformed claim
lookup selects the local record. Each local record has its existing unique random
`id`; several external keys may point to that record. Signed `id` is local,
`sub` retains existing provider/transform semantics, and `jti` remains a session ID.
Access-only session issuance adds a fresh signed `nonce` so two logins in the same second
cannot share a JWT and borrow each other's cached proof. Upstream or transformed
nonce values do not control this value; it is separate from protocol verification.
Changing a provider name or issuer makes a different namespace; do not repoint an
existing provider/directory realm at another identity authority and expect safe
identity continuity. A provider that recycles upstream subjects needs an operator
migration policy. Implicit memory IDs are intentionally not durable.

OIDC uses the verified ID token issuer/subject before access-token or UserInfo
claim enrichment. Named profile drivers use their verified immutable account ID;
GitHub requires a positive lossless numeric ID, never a mutable login name.
SAML rejects missing/empty/transient NameIDs and keys the verified issuer plus a
JSON array of NameID format, name qualifier, SP qualifier and value. Configure a
persistent NameID at the IdP. LDAP DN renames change the key; recycling a DN
reuses it, so directory lifecycle must include deliberate account migration.
LDAP uses its configured realm and the DN whose
password was verified, re-reading attributes under the service binding while
requiring the same DN. Ticket providers use the pinned issuer URL and validated
subject. Protocol verification always precedes local provisioning.

`Database.ResolveExternalAccount(ctx, account, create)` is a trusted Go API.
Missing connections automatically create passwordless local records with random
internal usernames, `externally_provisioned: true`, no local email/recovery aliases,
no passwords, no administrator role and no invented MFA evidence. Provider email
and display name live only in the connection metadata. Disabled/locked identities
cannot be reprovisioned to bypass their state. A verified first login needs no
create decision or confirmation. Repeated/concurrent logins resolve to one ID.
The returned `Account` is the stored connection, including its display metadata
and `ConnectedAt`, and matches its entry in `Identity.ExternalAccounts`. Existing
lookups do not update these fields from the supplied account. Preserve this
contract across repeated logins, connection moves and database reopening.

The passwordless default applies only while an automatically provisioned record
has no local password history. Disabling or expiring a local password cannot
remove its default checkpoint; preserve the distinction between available
credentials and selected policy described in the
[challenge owner](../../authentication-portal-challenges/SKILL.md#selection-contract).

`external_accounts` is persisted on `identity.User` and exposed in admin info.
Duplicate external keys fail startup and snapshot indexing. All snapshot adoption
paths must retain its index, and detached results must not alias live state.
Provisioning/connection uses current file contents and one atomic commit under
the existing database/file locks. Cancellation before commit publishes no mutation.
The local authenticator lock protects database replacement around these calls.
Observing another file revision rotates the local authentication epoch, including
a file rollback; resolving an external account must not absorb that change and
revive older proof. Persist the observed epoch even for a lookup without mutation.

## Administration

Existing-account admin actions on the concrete local store accept the internal
username with omitted or empty email only for an automatically provisioned
record that has no local email aliases. This applies to info, deletion, status,
password reset, role changes and challenge policy. Never substitute an upstream
display email or treat a non-string/null email as omission. Ordinary local
records, including externally provisioned records with local aliases, still
require a matching local email. Account creation and other backend kinds retain
their nonempty-email requirement. Administrator authorization and origin/body
checks run before this selector handling; external authentication alone grants
no account-management role.

Re-enabling uses the exact stored username and, when required, exact email
spelling. It preserves the immutable ID and external connections, advances the
credential generation and never revives old proof. Disable to prevent subsequent
external logins. Deleting a record removes its connections and allows the next
verified login to automatically provision a new ID without its former local
roles or credentials. Neither operation changes existing stateless JWT expiry.

## Connection and local authority

`/connected-accounts` lists connections or offers an optional existing-account
connection after external sign-in. The normal portal link is shown when an
explicit attachment exists. The route owns `/connected-accounts/{ticket}` before
JSON negotiation. Preserve earlier provider/API namespaces and nested mounts.
The `connected_accounts` Go template and CSS are overrideable through the normal
UI factory, with all eight portal languages. Strict-origin referrer policy hides
ticket paths while retaining Origin on Chrome form POSTs; no-referrer would cause
Origin:null. CSP permits only same-origin assets/forms and denies framing.

A pending connection holds server-only external proof, a browser-cookie hash,
portal mount, expiry and random CSRF. It lasts five minutes, with at most 4096
pending operations per portal. Starting requires the same live external session;
a fresh local login is then required. Bind the operation to the local HTML
sandbox created through its fresh, bound return URL and then to that sandbox's
successfully issued access token. Whole-second authentication timestamps alone
cannot distinguish an earlier session from a later operation. A local login
started before the operation, a different or superseded sandbox, JSON/API-key
login, renewal, or a copied unrelated local session cannot authorize confirmation.
Starting another eligible sandbox replaces the pending destination binding.
Its return URL is a narrow same-origin,
exact pending-ticket exception, never an arbitrary redirect allowlist bypass.
Require exactly one browser session cookie and one access cookie. The validated
access token must come from that cookie and match the current cached login's
token exactly; `jti` alone cannot select login evidence after an account switch.
Bearer/query credentials and duplicate access cookies do not authorize this page.
Confirmation displays the provider and current local account. Same-origin form
POSTs require exactly action/csrf, bounded bodies and no duplicates. A bearer JWT,
URL subject, another browser, earlier local session or API-key login cannot choose
the destination. Logout cancels this browser's operations; Close clears all.

`ConnectExternalAccount` atomically rechecks both completed proofs' ID, epoch,
credential generation, freshness and enabled/unlocked state. The source must own
this exact key and remain an automatically created identity with exactly one
connection and no password/MFA/API/public-key credentials. Never merge established
accounts implicitly. The target keeps its immutable ID; the key moves once; both
credential versions advance; the source stays as a disabled record. No roles,
profile data, documents or credentials migrate. Connection metadata is retained.
A consumed confirmation cannot be retried, including after an uncertain failure.
Successful confirmation asks for a fresh login against the changed generations.

Portal issuance and provider refresh hold `WithRefreshIdentity` through current
local role/factor checks and signing. Default local password is replaced by external
verification; explicitly required passwords and registered local MFA still require
real local checkpoints. LDAP browser/JSON continuations retain their directory
input identity while local checkpoints use the attached canonical identity.
Public LDAP Basic authentication and encrypted system assertions hold the same
attached identity transaction through current policy and signing. They retain
the directory subject, add local roles and the immutable local ID, and report
federated AMR. They cannot complete local factors and reject explicit local
password requirements or MFA; directory password verification is not local proof.
Portal-backed gatekeepers repeat this directory authentication and local policy
check for every Basic credential request, even when the same credentials
previously authorized a resource. The portal opts out of credential-result
caching; see the
[credential authenticator contract](../../credential-authenticators/SKILL.md).
AMR includes federated plus actually completed factors, never upstream AMR/ACR.
Credential changes and new factor requirements invalidate outstanding proof.
Direct OAuth policies recheck the attached identity on every session request and
reject accounts requiring local factors, since they cannot display challenges.
Already issued stateless JWTs retain their ordinary lifetime.

External sessions retain separate `ExternalIdentity` proof. They do not gain local
profile/credential-management authority merely from a matching ID/email/name.
Attached local MFA also does not make them eligible for the local-only downstream
OIDC adapter; completion clears its previous browser session.
OAuth snapshot renewal retains the local proof and completed factors alongside
its separately captured upstream attributes; upstream revocation still needs a
new upstream login. Cross-device transfers revalidate local proof and cannot
extend the approving login's lifetime. Completing attached local factors does
not make the transfer eligible for a new refresh family; expiry is bounded
before signing within the identity transaction.

## Verification

Keep parser external-package units/examples and consumer parser usage. The
identity transaction E2E covers concurrent file handles, durable connection,
revoked proof, namespace isolation and corrupt duplicate rejection. Memory lookup
units and that E2E also compare returned connection metadata with persisted
records, including after reopening and with changed lookup display attributes.
Portal TLS and Chrome journeys cover automatic creation, same-email separation, repeat ID,
fresh local confirmation, CSRF/replay rejection, persistence, local MFA and disablement.
Keep memory/file disable-enable units for email-less external identities,
ordinary local records and external records with local email aliases. The TLS
administration journey must use real local administrator login, enforce member
denial, manage the automatically provisioned record through the public API,
validate request/response schemas, and verify signed identity/role continuity
after re-enable and a fresh ID without old roles after deletion/reprovisioning.
Exercise admin password reset and explicit local-factor enforcement in that
journey; never use provider email as the administrative selector.
Keep replay of the external JWT after fresh local login, duplicate access cookies,
bearer-only submissions, and another browser's connection return URL in that
TLS journey. Unit tests cover expired/consumed tickets, root/nested mounts,
foreign origins, encoded paths, URL userinfo and ambiguous browser cookies.
Keep constructor tests for absent, valid/invalid file, directory and symlink
sentinel collisions. The implicit-store TLS OAuth journey must prove a matching
filesystem external key and role do not enter the signed local identity, while
repeat login retains its private ID and leaves the file unchanged.
For root opt-in, reject bad targets and reused bound providers before opening
files or state; a later invalid provider must not mutate an earlier valid one.
Test failures loading identity epochs before binding and portal snapshots after
binding, with owned resources released and borrowed providers left to their host.
The public-root ticket TLS journey must use the actual configured local store,
preserve file identity and evidence epoch across fresh provider/root instances,
and recheck local roles and disablement on new verified external login.
Keep a deterministic TLS test with a frozen clock: an earlier valid local JWT
must fail without mutation even in the same second, and the operation's own new
local login must still connect in that second. Close all fixture workers,
including the OAuth journey's gatekeeper, before leaving the clock bubble.
LDAPS tests use an actual TLS bind/search fixture and portal login, including
wrong passwords, canonical aliases and implicit/explicit stores. Exercise the
public Basic and encrypted system APIs with local roles, explicit password policy,
TOTP and disablement so they cannot bypass browser enforcement. Signed SAML
journeys require persistent subjects and reject transient subjects. Keep refresh,
cross-device, direct-policy, SQLite ticket and storage restart tests in scope.
The external-MFA cross-device regression must leave refresh capacity available
and assert that the receiving browser gets access only, retains verified factors
and local ID, and never exceeds the approving expiry. Full capacity can hide
incorrect family admission behind an unrelated denial.

Run focused cases with `make test TEST='Connected|ExternalAccount|IdentityAttachment'`
and the owning protocol packages, then the complete repository gate. Preserve
failed runs; neither a unit pass nor a passing synthetic issuer proves a named
provider's production deployment works. Consumer-specific Caddy syntax and host
integration belong in the requested ignored `tmp/` handoff, never sibling edits.
