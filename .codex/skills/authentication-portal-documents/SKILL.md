---
name: authentication-portal-documents
description: Maintain the opt-in encrypted Documents API, immutable account ownership, SQLite ciphertext storage, chunk transactions, recipient key envelopes, configuration parser, and TLS/browser cryptographic tests. The separately maintained React application has its own integration skill.
---

# Portal Documents

Use [documents-app-integration](../documents-app-integration/SKILL.md) to implement
or review the separately maintained Documents React client, recovery UX, encrypted
transfer workflow, and sharing/download behavior.

Read the shared [Mermaid sequences and design rationale](references/sequences.md)
when implementing or reviewing the lifecycle. They trace request admission,
enrollment/unlock, upload/commit, download, sharing, revocation and destructive
reset, including transaction boundaries and the reasons for each security rule.
Keep them aligned with the protocol, OpenAPI and behavioral tests when changing
any of those flows.

## Ownership and trust

`pkg/authn/documents` owns ciphertext persistence and the wire models;
`pkg/authn/documents_http.go` owns the 16 resource operation paths beneath `/api/documents/` under the portal mount.
`pkg/authn/documents.go` provisions and closes the store with the portal.
Routes, filenames and protocol identifiers are unversioned; keep that invariant
in the API contract and all consumers.
The feature is independent of profile/admin API enablement. No Documents SPA,
static asset inventory or `/documents` page route is supplied by this API change.

The confidentiality target is passive inspection of decrypted TLS traffic. The
browser encrypts file bytes and filenames before transmission. The server never
receives recovery secrets, private scalars or unwrapped document keys. The
protocol uses standard Web Crypto P-256 ECDH, HKDF-SHA256 and AES-256-GCM with
portal/document/user context binding. Algorithm secrecy is not a security claim.
Read the [crypto and wire protocol](references/protocol.md) before changing
encodings, key lifecycle, encrypted fields, or the client module.

The trusted computing base includes the served JavaScript, browser, device and
recipient key discovery. Active script modification, compromised endpoints, and
malicious recipients are outside this confidentiality guarantee. The server and
network observer can see identities, sharing relationships, ciphertext sizes,
chunk counts, timings and traffic patterns. Durable recipient keys do not provide
forward secrecy. Revocation cannot erase plaintext or keys already copied.

## Identity and authorization

An access JWT alone is insufficient. Require a valid portal JWT, current stored
browser login session, configured realm, portal user/admin role and immutable
login evidence. Require the exact validated token in the cached session, both
at admission and again inside the identity callback. `jti` alone can identify
a newer account's login after the same browser switches accounts; reject an
earlier token with 401. The store must implement `WithRefreshIdentity`; operations run
inside that callback so credential revocation and identity changes cannot race
the database operation. Body reads happen before the identity lock. Responses
are published only after both identity callback and document transaction return.

Current support is local authenticated identity stores with transactional
verification (the local JSON backend is exercised end to end). LDAP and upstream
OAuth/SAML are not silently mapped from display claims. Ordinary access-only JSON,
API-key and native body-refresh credentials do not establish the stored browser
session needed here. Do not weaken this boundary to admit a new client.

Ownership is the exact immutable `identity.User.ID` from verified login evidence,
a canonical lowercase non-nil UUID. `keys.user_id`, `files.owner`, and
`shares.recipient` store that ID directly; the wire uses `user_id` for account
identity and `owner` for a file's owner. Do not hash it, replace it with an OAuth
subject, or select it from transformed `sub`/`email`. Credential generations and
runtime epochs govern admission but do not alter persistent ownership. A new
login after a password change or restart retains files; deleting/recreating an
account produces a new ID and cannot inherit them. Admins have no access override.

After identity revalidation, `Store.BindIdentity` atomically reserves the user ID
for the authoritative backend name/realm. A different source claiming the same
UUID gets 403, even after reset or restart. This immutable reservation prevents
cross-store collisions and check/use races. `MaxKeys` separately bounds active
key registrations and permanent identity reservations (including admitted users
who have not enrolled keys). Reset does not free reservations. Store consumers
must authenticate/revalidate and bind the identity before any operation.
External-account attachment now resolves an authoritative local record, but
external login alone still does not grant Documents authority. A completed
local login supplies the canonical ID and source; never create a separate
Documents namespace from provider claims.

All Documents descendants stay with this handler before legacy suffix dispatch,
including unknown children ending in `/api/logout` or `/api/profile`. Exact
configured mount, allowlisted canonical resource path, per-operation method and
HTTPS origin checks precede operations. Only file listing accepts an exclusive
`after` cursor in the query; reject unknown, duplicate, empty and noncanonical
queries, including a bare `?`. Resource IDs and canonical decimal chunk numbers
are path parameters; invalid values return 400. Origin, when present, must match the configured public origin;
Sec-Fetch-Site must be `same-origin` or `none`. No CORS is enabled. Native requests
may omit browser headers but still require stored login evidence. Embedding hosts
own trusted forwarded-header normalization and route declarations; Documents
configuration also applies the shared canonical mount validation described below.

## Configuration and lifecycle

Documents is disabled by default, exactly like the Admin API switch.
`APIConfig.DocumentsEnabled` is the sole portal enablement flag. Merely supplying
`PortalConfig.Documents` storage settings, enabling Admin/Profile, or parsing an
empty directive list does not activate Documents or provision its database.

The dedicated public constructor
`pkg/authn/documents/parser.NewDocumentsAPIConfigFromDirectives([]string)` returns
`*authn.DocumentsAPIConfig` with `Enabled` and `Storage` fields. Apply it with
`PortalConfig.ConfigureDocumentsAPI`; that method snapshots storage and realm
slices, sets `API.DocumentsEnabled`, and preserves all other API flags. Nil input
and invalid enabled settings leave the portal unchanged. A zero-value input
disables Documents. Direct serialized configuration uses
`api.documents_enabled: true` plus the separate `documents` storage object.

The parser accepts complete portal statements encoded with `cfgutil.EncodeArgs`,
without braces. Collect all Documents statements before calling; reject empty
tokens before encoding. Enablement is explicit, and all storage statements carry
the `documents api` prefix. Unknown/duplicate settings, opposite enable/disable
statements, raw newlines and invalid values return nil plus a redacted error.
Keep every keyword as its own token: a quoted `"max file bytes"` keyword is
invalid, while a quoted database path containing spaces is a valid value.
Storage validation/defaults run when enabled; disabled settings do not require
an available directory, origin or realm. Parsing and configuration perform no IO.

```text
enable documents api
documents api database /private/authcrunch/documents.db
documents api public origin https://auth.example.test
documents api base path /auth
documents api realms local
```

| Complete directive | Default and meaning |
| --- | --- |
| `enable documents api` / `disable documents api` | Disabled; mutually exclusive, never implicit |
| `documents api database PATH` | Required when enabled; absolute path, one dedicated database per portal |
| `documents api public origin URL` | Required when enabled; canonical HTTPS origin, no path/trailing slash |
| `documents api base path PATH` | `/`; canonical absolute portal mount accepted by `portalpath.Validate`, no trailing slash except root |
| `documents api realms NAME...` | Required when enabled; distinct allowed identity-store realms |
| `documents api max file bytes N` | 268435456 ciphertext bytes; allowed 16..4294967296 |
| `documents api max user bytes N` | 1073741824 reserved ciphertext bytes, at least file limit |
| `documents api max total bytes N` | 10737418240 reserved ciphertext bytes, at least user limit |
| `documents api max user files N` | 1000 owned pending/committed files; maximum 100000 |
| `documents api max total files N` | 10000 files; at least user count, maximum 1000000 |
| `documents api max keys N` | 10000 active registrations and permanent identity reservations; maximum 1000000 |
| `documents api max recipients N` | 100 recipients per file, excluding owner; maximum 1000 |
| `documents api upload ttl seconds N` | 86400, allowed 60..604800 |

Zero numeric values request defaults. Enabled typed configuration and the public
parser validate `BasePath` through the shared
[portal mount contract](../coding-directives/references/portal-routing.md#explicit-and-inferred-mount-delegation).
Use `/` for root; other mounts are literal canonical visible-ASCII paths with no
trailing slash, URL escapes or semicolons. Reserved portal prefixes and namespace
segments are rejected at every depth. Keep the Documents limit of 2048 bytes.
Do not normalize an invalid declaration into a different storage binding.
Disabled Documents retain the storage-validation opt-out described above.

Declare that same mount when an embedding host calls `Portal.ServeHTTPAt`.
For an enabled Documents API, delegation compares the declaration with the
private configuration used to open the store, not a later edit of the caller's
`PortalConfig.Documents`. Disagreement returns 500 with no-store and no cookies
before protocol dispatch. Outside or encoded mount aliases return 404 at the
explicit route boundary. Hosts should also reject configuration disagreement
before opening storage or starting listeners; request-time enforcement does not
provide that construction-time guarantee. Legacy `Portal.ServeHTTP` remains
available with inferred route semantics and does not acquire the explicit
declaration check.

Config snapshots isolate running storage from later caller mutation. The public origin must already match the browser's
serialized HTTPS origin: use lowercase ASCII/punycode DNS names or canonical IP
literals, omit default port 443, and write other ports in decimal without leading
zeroes (0..65535). Reject query/fragment delimiters, even empty ones, Unicode host
spellings, abbreviated/numeric IPv4 aliases, noncanonical IPv6 and empty ports.
Do not silently normalize this permanent cryptographic binding. Invalid enabled
settings fail before creating a database. Configured realms must identify exactly one supported
store and must not collide with provider realms. The database parent must already
exist as an owner-only directory, with an existing database at mode 0600. Current
private SQLite support is Unix; Windows fails construction. Never provision files
in the served static tree. The database is permanently bound to portal name,
public origin and mount, with a random persistent portal ID. Changing those
settings requires an explicit migration design; do not silently open old data
under a new cryptographic context. Keep identity-store names and realm identifiers
stable as well: the immutable source reservation rejects renames until an explicit migration.
The owner ID itself stays the local database UUID; do not remap by username.

Drain requests before `Portal.Close`; ciphertext survives closure. SQLite uses
private rollback-journal transactions, strict schema/application validation and
cross-process serialization through `internal/sqlitedb`. Backup the complete
SQLite database consistently along with the identity database. Do not copy only
selected rows or restore identity accounts by username. Quotas are logical
ciphertext reservations, not exact on-disk usage; metadata/index overhead and
SQLite free pages require additional disk capacity. No background janitor runs:
allocation collects expired unfinished uploads. Operators should account for
inactive users, orphaned deleted-account data and idle expired uploads in retention
procedures; no management deletion/retention API is implemented.

## State and failure contracts

Register a public key and encrypted vault once. Identical retries succeed;
replacement returns 409. `key.reset` is an explicit destructive reset: it
atomically deletes owned files and all associated grants, received grants, and
registration, allowing fresh enrollment. Supply the confirmed `{user_id,key_id}`;
an account switch or a changed registration returns 409 without deletion.
Fingerprint comparison and deletion share one transaction. An already absent
registration is a successful no-op. It cannot recover old plaintext.

Allocate a random ID while reserving the complete ciphertext size; upload an
immutable encrypted manifest and immutable numbered chunks; commit only when
manifest/envelope, count and exact sizes agree. Recipients cannot observe pending
files. Expiry is absolute and is not extended by writes. Chunk and manifest retries
must match exactly, including after commit. Lost allocation responses require
listing/reconciliation because allocation itself is not idempotent.

Only owners mutate, share, revoke and delete. Share against the recipient's
current registered fingerprint; stale or replaced keys fail. A received grant is
read-only. The descriptor returns only the requesting user's envelope. Public
key lookup omits vaults; no user enumeration/search endpoint exists. Lists contain
up to 100 identifier-ordered descriptors with an exclusive `after` cursor and omit
encrypted metadata/envelopes. Client decrypts metadata using `file.fetch` messages.

Use the [protocol's method/path catalogue](references/protocol.md#http-messages).
GET reads keys, descriptors, chunks and recipient lists; PUT installs keys,
manifests, chunks and grants; DELETE removes documents/grants; POST allocates,
commits or resets. List files with `GET /api/documents/files` and reserve uploads
with `POST /api/documents/files/allocate`. Own-key operations use
`/keys/fetch`, `/keys/register` and `/keys/reset` beneath the API
base; recipient lookup remains `/api/documents/key/{user_id}/lookup`.
Files use `/api/documents/file/{id}/...`, with chunks and shares
nested beneath that file. Deletion is `DELETE /api/documents/file/{id}/delete`.
Use `fetch` for key/file/chunk reads, not `get`. The root `/api/documents` is not a
dispatcher. Superseded singular collection paths, old all-POST paths, encoded
paths, trailing slashes and extra descendants
are not aliases. Wrong methods return 405 with the specific method in `Allow`.

GET, DELETE and commit have no body; reject even `{}`. Other writes accept direct
JSON fields with no `operation` or `payload` wrapper and no repeated path values.
Decode body fields only after validating their exact operation-specific allowlist;
they cannot override a path-selected file, recipient or chunk. Every success is
HTTP 200 with the concrete resource fields directly in the body; mutations
without resource data return the typed confirmation `{"success":true}`. Never add
`operation` or `result` response wrappers.
`chunk.put`/`chunk.fetch` carry canonical base64url ciphertext in JSON. URLs expose
resource identifiers, operation and optional list cursor. Decrypted TLS additionally
reveals sharing metadata and traffic patterns, while content stays encrypted.

JSON writes have a 1463659-byte hard limit before parsing/identity locks; all JSON
writes except `chunk.put` have a further 65536-byte limit. Decoded chunks are at most
1048592 bytes. Require application/json for JSON writes; reject content encoding
on every operation. Reject unknown fields, null required values, duplicate members
(including escaped aliases), case aliases and non-ASCII member names,
trailing JSON and nesting deeper than 16. Each operation has an exact payload
shape; fields for another operation are invalid. Errors are generic:
400 invalid, 401 missing/stale evidence, 403 origin/role/realm/source, 404 unavailable
or inaccessible, 405 method with the endpoint-specific `Allow`, 409 state/content conflict, 413
body/chunk size, 415 media, 507 quota, 503 storage. Invalid lengths within key,
vault, envelope and metadata fields return 400. Reconcile uncertain writes using read
messages; do not blind-retry reset or allocation. Plaintext validation and GCM
verification belong to the client; the server cannot prove submitted bytes were
correctly encrypted.

## Acceptance and validation

When changing mount handling, qualify typed and parser rejection of reserved,
escaped and non-ASCII mounts before database creation, plus root, nested and
permitted lookalike mounts. Exercise an actual opened Documents store through
`ServeHTTPAt`: a matching declaration must reach the API, a different declaration
must fail before early dispatch, and mutating the caller's Documents settings
must not retarget the private store binding. Preserve disabled-feature and
legacy-delegation behavior as separate cases.

`documents_api_config_test.go` covers default-disabled behavior, independent API
flags, immutable configuration snapshots and JSON/XML/YAML round trips. The TLS
fixture also verifies omitted settings, storage alone, Admin/Profile enablement,
explicit disablement and unused invalid storage all leave the API unavailable
without creating a database.
`documents/store_test.go` covers persistence, independent-connection quota exclusion,
expiry, immutable writes, sharing isolation, key reset and malformed inputs.
Its concurrent share/reset test uses separate connections and verifies that
neither a new grant nor an identical grant retry can survive recipient reset.
`documents/protocol_test.go` independently decrypts the Web Crypto test vector
with Go standard crypto. `documents_e2e_test.go` consumes the public parser,
real TLS browser login and storage, including transformed identities, restart,
revocation, account recreation, colliding IDs across authoritative stores,
method/resource/body boundaries, quotas and reset. A Chrome network observer verifies each method and resource path, no
body on reads/deletes/commit, and no repeated identifiers in write bodies.
Rejection tests include obsolete request wrappers, destructive fields on read
paths, obsolete read paths and all five superseded singular collection paths.
Binary contract tests cover all first-byte public-point prefixes, noncanonical
base64url lengths/unused bits, and payload size boundaries. TLS tests reject
invalid point prefixes and off-curve points even with matching fingerprints,
and verify valid enrollment, manifests and sharing still work afterward.
`documents_concurrency_e2e_test.go` pauses real TLS request bodies after HTTP
100 Continue, then revokes credentials or replaces a recipient key. Revocation
must finish while the body is withheld. The resumed request must fail without
storing a chunk or grant; fresh authorized work must still succeed. Keep these
journeys in the native OpenAPI contract suite as well as the Documents suite.
`server_documents_e2e_test.go` exercises root configuration serialization, custom
cookies, browser refresh/logout, administrative isolation and root server restart.
Register new exported models in `internal/tag/tag_test.go`, with matching
JSON/XML/YAML tags and explicit exceptions for required wire fields. Required
values and empty lists must retain their JSON representation.
`documents_browser_e2e_test.go` runs Chrome with actual Web Crypto and API transfers,
owner/recipient decryption, tampering and plaintext-exposure assertions. Node
client tests cover context separation, wrong keys and nonce reuse prevention.
The crypto helper snapshots caller buffers and context before its first await;
Node and Chrome regressions clear or reuse buffers while encryption is pending
and verify the original file still decrypts. Configuration units and the real
TLS consumer reject browser-origin aliases and combined keyword tokens while
preserving the running store. Keep these regressions when changing async crypto
or configuration parsing.
Keep browser tests in the default Go suite. Update authored OpenAPI and source
fingerprints together, including `documents/client/crypto.mjs`.
The Documents tag at `/#tag/documents` owns the HTTP operation/message catalogue:
all 16 operations have distinct real paths, operation IDs, paired examples,
field/state/retry guidance, documented resource parameters and dedicated JSON
write-body/response schemas. Keep the tag
index and endpoint examples consistent; the reference browser test exercises
every operation's native Test Request console and checks its transmitted path,
message and displayed response against synthetic fixtures. Native TLS tests
separately validate real API responses against those schemas.

```sh
make test TEST_DIR='./pkg/authn/documents/... ./pkg/authn' TEST='Documents|^TestStore|^TestConfig|ProtocolWebCrypto' COVERAGE_DIR=.coverage/documents
make test TEST_DIR='./internal/tag .' TEST='TagCompliance|Documents' COVERAGE_DIR=.coverage/documents-composition
make test-ui
make openapi-test
make ci-check
```
