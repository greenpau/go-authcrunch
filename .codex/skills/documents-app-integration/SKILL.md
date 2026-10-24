---
name: documents-app-integration
description: Implement the separately maintained Documents React client for AuthCrunch encrypted storage, recovery keys, chunk upload/download, recipient sharing, and safe session handling. Does not implement manager/profile APIs or provision the backend.
---

# Documents React Integration

This skill is intended for the external React application's agent to read from
its AuthCrunch library checkout. Keep implementation in the task's authorized
repository; reading this skill does not authorize edits to sibling checkouts.
For an app-local AGENTS.md, add a route pointing to this skill at the actual
library checkout location. Do not copy a machine-specific path into the app's
source or pretend the compiled app already ships in AuthCrunch.

Read the [crypto/wire contract](../authentication-portal-documents/references/protocol.md)
and use the portable
[crypto.mjs module](../../../pkg/authn/documents/client/crypto.mjs).
Vendor a reviewed version into the frontend's source or bundle it via an explicit
build dependency. It is plain ESM using native Web Crypto with no third-party
runtime dependencies. It is not currently served by a production asset route.
Preserve the protocol and test against the
[interoperability vector](../../../pkg/authn/documents/testdata/protocol.json).
Use the shared [Mermaid sequences and design rationale](../authentication-portal-documents/references/sequences.md)
to follow enrollment/unlock, encrypted upload/download, sharing, revocation and
reset. They distinguish local crypto and required React UX from implemented
server behavior, and explain retries, key context and account-switch protection.
Keep these sequences and the protocol aligned when changing a client workflow.

The [OpenAPI source](../../../assets/openapi/content/openapi.yaml) describes the API.
Its rendered `/#tag/documents` catalogue documents every operation's fields,
request/response messages, state transitions and retry behavior. Every operation
has its own method/resource path, expected response schema, parameter/body examples and native
Test Request console.
No plaintext-upload endpoint, username-directory endpoint or public share link
exists. The manager application and profile application are separate products.

## Session and capability discovery

The host must explicitly enable `APIConfig.DocumentsEnabled`; the feature is
disabled by default and independent of Admin/Profile. A configured storage path
alone does not enable it.

Configure the exact portal origin/base path via the embedding app's trusted
bootstrap. The host's Documents storage mount and declared portal route must
agree; use the canonical mount accepted by the shared
[portal path contract](../coding-directives/references/portal-routing.md#explicit-and-inferred-mount-delegation).
Root is `/`; remove that one trailing slash when joining the API suffix so root
uses `/api/documents` and `/tenant/auth` uses `/tenant/auth/api/documents`.
Do not infer a different mount from the current React page, normalize an invalid
mount, or probe alternate paths after a configuration failure. A mount mismatch
at explicit portal delegation returns 500 and needs a host configuration fix;
it is not an expired session or a reason to reset a vault. The database's portal,
origin and mount binding persists across reopening, so moving an app's static
route alone does not migrate Documents data. Every operation has its own
method/resource path; use the complete
[operation table](../authentication-portal-documents/references/protocol.md#http-messages).
GET reads; PUT registers keys and writes immutable manifests, chunks or grants;
DELETE removes documents or grants; POST allocates, commits and resets. Paths use
`fetch`, never `get`. For example, fetch a chunk with
`GET /api/documents/file/{id}/chunk/{idx}/fetch` and delete an owned file with
`DELETE /api/documents/file/{id}/delete`. Select from the fixed catalogue; never
accept a complete operation URL from untrusted file data. Validate and encode
individual path parameters. Use canonical decimal chunk indices without leading
zeros. List files with `GET /api/documents/files` and allocate uploads with
`POST /api/documents/files/allocate`. Own-key operations use `/keys/fetch`,
`/keys/register` and `/keys/reset` beneath the API base; recipient lookup remains
`/key/{user_id}/lookup`. The only query is file listing's optional `after` cursor.

Use relative same-origin fetch URLs and `credentials: "same-origin"`. GET, DELETE
and commit have no body. Other writes require `Content-Type: application/json`
and only their documented direct fields. Do not send `operation`/`payload`
wrappers or repeat resource path parameters in a body. Every success is HTTP 200
with resource fields directly in the response. Validate
them against the selected method/path schema. There is no `operation` or `result`
wrapper. Mutations without resource data return `{"success":true}`; require the
literal boolean true. Failures have an HTTP error
status and `{status,message}`. See the linked protocol's operation table for exact
payloads. Bound response reads to 2 MiB; reject oversized or malformed JSON.

For example, capability discovery sends:

```js
const response = await fetch(`${apiBase}/bootstrap`, {
  method: "GET",
  credentials: "same-origin",
  signal,
});
// Read a bounded response, check HTTP status, then validate its direct fields.
```

Do not store JWTs in JavaScript
storage or introduce a token in URLs. The API needs both a valid portal cookie
and server-cached local browser login evidence. Do not use access-only JSON login
as a substitute. A document recovery key is an additional client-only secret,
independent of the portal password and MFA.

GET `/bootstrap`, verify `protocol === "authcrunch-documents"`, obtain the
portal ID, exact local user ID and limits, then `key.fetch`. Distinguish its 404 (not enrolled)
from the bootstrap's 404 (feature unavailable). Handle 401 through a fresh portal
browser login. When the host already provides refresh/session coordination,
reuse it for expiry; do not invent a competing refresh loop or repeatedly refresh
revoked identity evidence. Follow the host's validated return-navigation contract.
403 is a permission/origin/realm failure; 503 is temporary storage unavailability.

Never persist decrypted documents or keys in localStorage, service-worker caches,
analytics, error monitoring payloads, logs, query strings or React debug tools.
Keep secrets out of React component state where a dedicated worker can own them.
On account/portal change, logout or lock, abort requests, clear decrypted state,
terminate the crypto worker, and revoke object URLs. Bootstrap user ID/portal
must match the unlocked vault before every operation; transformed display names
are not ownership identifiers.

## Enrollment, unlock, and key loss

`enroll(bootstrap)` returns `{registration,recoveryKey}`. The recovery key is a
random 256-bit secret encoded as 43-character base64url. Require the user to save
it and confirm the backup before `key.register` with **`{key:registration}` only**. Show the
key locally; do not send it in telemetry or application API state. Explain that
anyone with this key and the encrypted vault can decrypt the user's files and
received shares. Login-password reset cannot recover document keys.

On later devices, fetch the registration and call
`unlock(bootstrap, registration, recoveryKey)`. Retain the non-exportable private
CryptoKey in memory. Wrong keys and tampered vaults must stop before showing files.
Never derive a recovery key from the portal password or accept a weak human
passphrase in its place; the client has no passphrase KDF.

On lost recovery key, present a deliberate destructive-reset flow. Explain that
`key.reset` with `{user_id:confirmedUserID,key_id:confirmedKeyID}` removes all
owned documents, their shares, and received grants,
then allows fresh enrollment; it does not recover plaintext or affect other
owners' stored files. Require an explicit user confirmation in the UI before
sending that deletion. Capture the user ID and fingerprint from the registration
shown in the confirmation UI; do not replace them with a later bootstrap/key
value before sending. A cookie account switch or changed registration causes 409
and must invalidate the confirmation. Never automatically retarget or reconfirm
a reset after a conflict. This server check closes the gap between a UI check
and another tab switching cookies. A different `key.register` registration returns 409. If an enrollment
response is lost, `key.fetch` and reconcile the fingerprint and vault before retry.
Never auto-reset after an unlock or network error.

## Upload workflow

1. Read `File.size` locally; call `describeSize(size)` and compare its ciphertext
   `size` against the server limit. Send `file.allocate` with only `{size,chunks}`.
   Keep the returned ID/owner/size/chunks immutable. Allocation is not idempotent;
   after a lost response, inspect the owner's pending list. Concurrent tabs can
   allocate indistinguishable descriptors: never guess ownership of an operation
   from size/time or automatically delete a matching candidate. Present uncertain
   pending entries for deliberate abandonment; fresh attempts use a fresh ID/key.
2. Call `prepareUpload(bootstrap, descriptor, ownRegistration,
   {name:file.name,type:file.type,size:file.size})`. It returns `manifest`,
   `encryptChunk(idx,bytes)` and `dispose()`.
3. PUT `{manifest}` to `/file/{id}/manifest`. Read each Blob slice of at most
   1048576 plaintext bytes, encrypt once, then PUT
   `{ciphertext:encode(encryptedBytes)}` to `/file/{id}/chunk/{idx}/put`. No FormData, plaintext metadata or data URLs go
   to the API. Limit concurrent encryption/network work to bound memory.
4. Retry uncertain writes using the exact buffered ciphertext. The module rejects
   encrypting the same `idx` twice. Do not mix chunks from different prepareUpload
   calls. If exact upload state is lost on reload, delete/abandon that allocation
   and allocate a fresh document/key. `chunk.fetch` does not support pending files.
5. POST `/file/{id}/commit` **without a body** after every chunk succeeds. Identical
   commits/chunk and manifest writes are idempotent; conflicting ciphertext returns 409. Check the
   descriptor after an uncertain commit. Finally dispose the upload key buffer.

Crypto calls snapshot input buffers and the context fields they use before their
first await. You may clear or reuse your own Uint8Array after starting a call;
the helper clears only its owned copies. This includes Node Buffers. Keep
concurrency bounded because each pending call owns a copy. This snapshot is not
cancellation: dispose prevents new chunk encryption but already started work may
finish. After logout or an account switch, discard late results and stop network
writes even if the cryptographic promise succeeds.

Cancel aborts requests and may DELETE `/file/{id}/delete` without a body for the pending owner file. Pending uploads have
an absolute TTL; activity does not extend it. Expired uploads return 404. Handle
507 as quota exhaustion, retaining the user's original local file. Empty files
still upload one 16-byte ciphertext/tag chunk. Files and metadata are immutable;
editing means allocating a new file/key. Revocation-sensitive new versions must
use a new key and only wrap it for current recipients.

## List and download workflow

GET `/files` without a body or query for the first page. Follow `next` using
`/files?after=<next>`. Lists omit metadata/envelopes, so GET `/file/{id}/fetch`
with bounded concurrency for display.
After unlock, call `unwrapKey(bootstrap, detail, ownRegistration, privateKey)` and
`decryptMetadata(...)`. Render filenames as text; never use decrypted metadata
as HTML or a navigation URL. This API supports flat documents, not server-side
folders or plaintext search; any name search happens locally after decryption.

GET every expected `/file/{id}/chunk/{idx}/fetch` without a body, decode its
`ciphertext` using the module's canonical base64url decoder, and call
`decryptChunk(bootstrap, detail, documentKey, idx, ciphertext)`. Verify all tags,
indices, lengths and the metadata plaintext size before marking the download
complete. Fail closed on corruption/truncation; never offer partial data as a
successful file. A bounded Blob fallback can use `URL.createObjectURL`, an anchor
with a sanitized basename in `download`, and timely `URL.revokeObjectURL` after
the browser accepts the save. Use application/octet-stream for the download;
avoid inline execution or preview of uploaded HTML/SVG. For large files, use a
supported local streaming save flow with explicit partial-file cleanup on failure.

The client cannot guarantee secure erasure of strings or browser-managed memory.
Clear owned Uint8Arrays with fill(0), release CryptoKeys, and stop workers when
finished. Avoid buffering an entire large file solely to make an object URL.

## Sharing

Use a JSON share code with exactly these string fields:

```json
{"protocol":"authcrunch-documents","portal_id":"<bootstrap.portal_id>","user_id":"<bootstrap.user_id>","key_id":"<registration.key_id>"}
```

The portal ID and key fingerprint are canonical 43-character base64url values.
`user_id` is the exact canonical lowercase non-nil UUID (36 characters) from the
local user database. Never substitute email, username, a hash or an external
provider subject. Future federation-to-local mapping is not implemented here. Bound pasted
codes to 1 KiB and reject unknown fields, invalid identifiers and unsupported
protocols. This is public identity data, not a
secret link or a bearer grant. Display the portal and recipient fingerprint for
confirmation. Never include recovery/document keys or session credentials.

Compare the code's portal ID against the current bootstrap, then GET
`/key/{user_id}/lookup` and verify its user_id and full fingerprint match the code.
The public-key response has no portal ID field. Refuse changed keys and require an explicitly confirmed new
code. Owner unwraps the existing document key, calls
`wrapKey(bootstrap, detail, recipientPublicRegistration, documentKey)` and sends
PUT `/file/{id}/share/{user_id}/put` with only `{envelope}`. Only owners can share. Recipients
receive read access and use their own vault/key; no private key is exchanged.
GET `/file/{id}/share/list` returns recipient UUIDs only.
DELETE `/file/{id}/share/{user_id}/delete` without a body stops future downloads.
Clearly explain that recipients can keep or redistribute plaintext already read.

## Product and integration limits

Present encryption as protection against passive traffic/content inspection,
with a server that stores ciphertext. Operation paths, resource IDs and list cursors are visible in URL logs.
Decrypted TLS messages also reveal sharing metadata and ciphertext sizes;
do not promise otherwise. Do not promise protection against modified
JavaScript, compromised browsers/devices, a malicious recipient, traffic analysis,
or file recovery without the key. The protocol is public; its
security relies on keys rather than obscurity. Recovery-key compromise exposes
historical documents; there is no forward-secrecy claim.

The Go repository currently embeds only the existing Profile SPA. This work adds
the Documents API and reusable crypto module, not an embedded Documents build or
new page route. App build packaging, hosting, route reservation, CSP and frontend
links must be integrated explicitly when the external React app is ready; do not
place a source tree into the compiled `pkg/authn/ui/profile` directory or run the
profile-only asset refresh script for Documents.

## Acceptance tests

Use actual browser Web Crypto and real TLS portal login with two distinct users.
Assert actual network requests use each documented method and resource path,
with only the optional list cursor in queries. GET, DELETE and commit send no
body; other writes send direct JSON without repeated path parameters. Cover rejection of obsolete `get` paths, operation/payload wrappers and fields
that do not belong to the selected operation. Cover enrollment backup/unlock on another device, zero-byte and multichunk files,
owner and recipient decryption, outsider rejection, pagination, retry of identical
ciphertext, interrupted uploads, stale key fingerprints, reset, revocation, logout,
401 recovery and account switches. Check URLs and decoded TLS-visible request bodies for
plaintext filenames, file content, recovery keys and unwrapped keys. Tamper with
ciphertext, metadata, portal/owner/document IDs, sizes and chunk ordering and
require decryption failure. Verify safe filename rendering and completed download
contents. Start encryption/wrapping, immediately clear the input buffers, and
verify the original bytes still decrypt; mutate caller-owned context during a
pending operation and verify that it uses the call-entry snapshot. Run the
independent protocol vector along with the frontend tests.
Delay an upload while its login evidence is revoked, and delay a share while
the recipient resets and reenrolls. The first request must return 401 without
writing a chunk; the second must return 409 without creating a grant for the old
fingerprint. Retain the user's source file and require fresh login or explicitly
confirmed recipient identity before starting new work.
The backend's reference Chrome journey is
[`documents_browser_e2e.cjs`](../../../pkg/authn/ui/testdata/documents_browser_e2e.cjs).
It checks an HttpOnly cookie bootstrap using a session established by real HTML
login, then uses bearer transport for isolated multi-user crypto/API assertions.
The external app must additionally exercise its own login navigation, cookie-only
journey, account switching and session-expiry UI; the reference is not a React UI.
