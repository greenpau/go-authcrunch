# Documents cryptographic and wire contract

The shared [Mermaid sequence diagrams](sequences.md) explain the order of these
operations, client/server boundaries and the design reasons. This reference owns
the exact cryptographic derivations, encodings and HTTP message catalogue.

`authcrunch-documents` identifies the Documents cryptographic domain. The
portable implementation is
[`pkg/authn/documents/client/crypto.mjs`](../../../../pkg/authn/documents/client/crypto.mjs).
Its fixed interoperability vector is
[`documents/testdata/protocol.json`](../../../../pkg/authn/documents/testdata/protocol.json).
All vector secrets are synthetic. The server validates envelopes structurally;
clients authenticate ciphertext. Never substitute XOR, obfuscation, a static
application secret, the login password, or server-generated plaintext keys.

Standard primitives and trust assumptions follow the
[Web Cryptography specification](https://www.w3.org/TR/WebCryptoAPI/).
The composition below is the explicit contract; it is not an HPKE
implementation and must not be advertised as independently audited encryption.

## Encoding and context

Binary JSON values use strict unpadded base64url. Portal/document IDs and fingerprints are 32 bytes
(43 characters). User IDs are the exact canonical lowercase non-nil UUIDs from
the local identity database (36 characters); they are not base64 or hashes. Public keys are P-256 SEC1 uncompressed points, 65 bytes (87
characters), with curve membership validation. Fingerprint = SHA-256(raw point).
Integer values are whole safe integers. Metadata is UTF-8 JSON
`{"name":string,"type":string,"size":integer}`; name is nonempty and at most
1024 UTF-8 bytes, type at most 255 bytes, size is original plaintext byte length.
The module rejects additional metadata properties. Render these fields as
untrusted user text after decryption, and sanitize names for local downloads.

Let `C(parts...)` be UTF-8 encoding of compact JSON.stringify on the string array
`["authcrunch-documents", ...parts]`. All parts below are strings, including
canonical decimal size/count/idx. No whitespace, Unicode normalization or
alternate object serialization is allowed. Context is used BOTH as HKDF info and
AES-GCM additional authenticated data (AAD).

`D(purpose, extras...) = C(purpose, portalID, ownerUserID, documentID,
String(ciphertextSize), String(chunkCount), extras...)`.
Do not derive context from filenames, transformed claims, JWT IDs, current host
strings, or recipient UI labels. Use the authenticated bootstrap and allocated
immutable descriptor. Owner stays the original owner when a recipient decrypts.

HKDF is RFC 5869 HKDF-SHA256 producing 32 bytes, fed to AES-256-GCM with a 128-bit
tag appended to ciphertext. Default salt is SHA-256(UTF8(protocol)). Exceptions
and nonce rules appear below. Do not send any derived AES key.

## Enrollment and recovery vault

The browser generates a P-256 ECDH keypair and an independent random 32-byte
recovery key using Web Crypto. Display/save the recovery key before registration;
only it can unlock this vault. The recovery key is 43-character base64url, not a
human password. No password KDF or server password-recovery mechanism is defined.

Encrypt the 32-byte big-endian P-256 private scalar under
`HKDF(recoveryKey, random32ByteSalt, C("vault", portalID, user_id, keyID))`, using
a fresh random 12-byte GCM nonce and the same context as AAD. Upload only
`{user_id,key_id,public_key,vault:{salt,nonce,ciphertext}}`; vault ciphertext is
48 bytes. Never send the recovery key, scalar or private JWK.

On unlock, authenticate the vault, reconstruct the private key with the registered
public coordinates, verify private/public consistency using a fresh ECDH pair,
and retain the resulting private CryptoKey as non-exportable. Public/private
mismatch or GCM failure is a hard error. The reference module overwrites owned
byte buffers where practical; JavaScript strings and engine memory cannot be
reliably erased. Key reset deletes data; it never recovers an old key.

The reference helper copies caller-owned key/data buffers and snapshots the
context fields it needs before the first await. Clearing or reusing the caller's
buffers while a promise is pending must not change the resulting plaintext or
key binding. Internal copies are cleared after use; caller buffers remain the
caller's responsibility. Snapshotting does not cancel an operation on logout:
the app must still discard late results after account changes and stop writes.

## Document content and metadata

Allocate the ID first. Generate a fresh random 32-byte document key per allocated
file. Do not reuse it for another file or restart encryption of the same file
with a different key after some chunks were accepted.

Plaintext chunk size = 1048576 bytes. Chunk count = max(1,ceil(plaintextSize /
1048576)). Total ciphertext size = plaintextSize + 16*chunkCount. Only the final
chunk can be short; empty files have one zero-plaintext, 16-byte ciphertext chunk.
Each chunk `idx` gets its own AES key with info/AAD `D("chunk", String(idx))`.
Metadata gets its own AES key with info/AAD `D("metadata")`. Both use the default
HKDF salt and a fixed all-zero 12-byte nonce. This nonce is safe ONLY because each
purpose/idx has a distinct derived key and is encrypted once for that document.
The immutable server protocol and client reuse guard are part of this contract.

`prepareUpload` reserves each `idx` before its first async encryption. Save the
resulting ciphertext for retry; calling encryption again for the same `idx` is
an error. Never edit an existing encrypted file in place. Allocate a new ID and
key for changed contents or metadata. A reload without the exact upload state
must abandon/delete the pending upload and allocate a fresh one.

Decrypt/authenticate every expected chunk with its exact `idx`/context before
publishing a complete download. Reject swapped chunks, altered count/size/owner,
wrong portal, truncated/missing bytes, invalid tags or malformed metadata.
The API does not store a plaintext hash; AES-GCM and context binding authenticate
each immutable chunk and its position/expected length.

## Recipient envelopes

For every envelope, generate a fresh ephemeral P-256 ECDH pair. Compute the
32-byte ECDH shared secret with the recipient's validated public point.
Derive AES key using default salt and
`D("envelope", recipientUserID, recipientKeyID, ephemeralPublicKeyBase64url)`.
Encrypt the 32-byte document key with zero nonce and the same context as AAD.
Upload `{key_id,ephemeral_key,ciphertext}`; ciphertext is 48 bytes. Destroy the
ephemeral secret and intermediate byte buffers after use.

The owner also needs an envelope for their own registered key. A recipient uses
their unlocked private CryptoKey with the ephemeral public point and identical
context to recover the document key. A server-authenticated grant associates
that envelope with a file/recipient. This is not a sender-signature protocol.
Use a recipient share code containing portalID, user_id and full keyID, and
verify that independently supplied fingerprint before sharing. No passphrase,
recovery key, session token, or document key belongs in a share code or URL.

Changing a recipient's key requires explicit reset and fresh sharing. Revocation
blocks future API reads but cannot invalidate a cached envelope or ciphertext.
Persisted key compromise can decrypt historical files; there is no forward
secrecy for saved documents. Active server/key-directory/script compromise
requires a separately trusted client and independently authenticated keys.

## HTTP messages

Operations use the resource paths below, relative to `<portalBasePath>`. GET
reads resources; PUT installs immutable data; DELETE removes documents or grants.
POST allocates uploads, commits them or resets a vault. Each path accepts exactly
its documented method; other methods return 405 with that method in `Allow`.
Use `fetch`, never `get`, in read path names. There is no root dispatcher or
compatibility alias for the old all-POST paths.

Document IDs, recipient user IDs and chunk indices select resources in paths.
The chunk path parameter is named `idx`, a canonical unsigned decimal value
from 0 through 4095 with no leading zeros.
Only file listing accepts `?after=<documentID>`, copied from the previous `next`.
Omit the query for the first page. Reject unknown, duplicate, empty or noncanonical
query parameters, even a bare `?`. Unknown/encoded paths, extra descendants and
trailing slashes return 404; invalid resource parameters return 400.

GET, DELETE and commit send **no body**, not even `{}`. Other writes send only
the direct JSON fields below with `Content-Type: application/json`. Path values
must not be repeated in bodies. `operation` and `payload` wrappers are rejected.
Body member names have exact lowercase ASCII spellings; duplicates and unknown
fields fail. Use the portal's HTTPS origin and normal session cookies.

Success: HTTP 200 with resource fields directly, for example a chunk response
`{"ciphertext":"<canonical base64url>"}`. Mutations without resource data return
`{"success":true}` with a required boolean constrained to true.
Error: `{"status":HTTPCode,"message":reasonPhrase}` with the corresponding HTTP
status. Validate the concrete response fields for the selected method/path.
There is no `operation` or `result` response wrapper. URLs expose operation and resource
identifiers (including the list cursor); filenames, file content and private keys
remain encrypted in transit. Never put credentials or plaintext in a URL.

| Operation | Method and path | Request body | Response |
| --- | --- | --- | --- |
| `bootstrap` | `GET /api/documents/bootstrap` | None | Protocol, portal ID, local `user_id`, fixed chunk size and limits |
| `key.fetch` | `GET /api/documents/keys/fetch` | None | Own registration and vault; 404 before enrollment |
| `key.register` | `PUT /api/documents/keys/register` | `{key:registration}` | `{"success":true}`; different registration conflicts |
| `file.allocate` | `POST /api/documents/files/allocate` | `{size:ciphertextBytes,chunks:count}` | Allocated descriptor; not idempotent |
| `file.manifest` | `PUT /api/documents/file/{id}/manifest` | `{manifest:{metadata,envelope}}` | `{"success":true}` |
| `chunk.put` | `PUT /api/documents/file/{id}/chunk/{idx}/put` | `{ciphertext:base64url}` | `{"success":true}` |
| `file.commit` | `POST /api/documents/file/{id}/commit` | None | `{"success":true}` when complete; 409 otherwise |
| `file.list` | `GET /api/documents/files` | None | Up to 100 descriptors and optional `next` cursor |
| `file.fetch` | `GET /api/documents/file/{id}/fetch` | None | Descriptor, encrypted metadata, caller envelope |
| `chunk.fetch` | `GET /api/documents/file/{id}/chunk/{idx}/fetch` | None | `{ciphertext:base64url}`; committed and authorized only |
| `key.lookup` | `GET /api/documents/key/{user_id}/lookup` | None | Public registration only, no vault even for self |
| `share.put` | `PUT /api/documents/file/{id}/share/{user_id}/put` | `{envelope:recipientEnvelope}` | `{"success":true}` |
| `share.list` | `GET /api/documents/file/{id}/share/list` | None | Owner-only `{recipients:[localUserUUIDs]}` |
| `share.delete` | `DELETE /api/documents/file/{id}/share/{user_id}/delete` | None | `{"success":true}`; future reads revoked |
| `file.delete` | `DELETE /api/documents/file/{id}/delete` | None | Owner-only `{"success":true}`; missing file 404 |
| `key.reset` | `POST /api/documents/keys/reset` | `{user_id:confirmedUUID,key_id:confirmedFingerprint}` | `{"success":true}`; destructive deletion of owned files and all grants |

All successes, including allocation and deletion, use HTTP 200. Reset compares
the confirmed local user ID against the currently authenticated account and checks
the expected fingerprint inside the deletion transaction. Account switches and
replacement registrations return 409. An already absent registration succeeds
without further mutation; never retarget an uncertain reset to a new fingerprint. Key reset leaves
the permanent authoritative identity-source reservation intact. Source collisions
return 403, and maximum admitted identity reservations use the configured MaxKeys
limit. No CORS, plaintext filenames, plaintext-upload endpoint, or public share
links are supplied. Multipart and Content-Encoding are rejected. Bound JSON
request bodies to 65536 bytes except `chunk.put`, which can use up to 1463659
bytes for the entire JSON object. Its decoded ciphertext is at most 1048592 bytes.
Bound client response reads as well (2 MiB covers current responses); reject
oversized/malformed JSON and validate the direct response fields before use.

Use the [authored OpenAPI](../../../../assets/openapi/content/openapi.yaml) for
exact schemas and constraints. Encryption happens client-side before sending
messages. Operation and resource IDs are visible in URL logs. Ciphertext
length, timing and sharing relationships remain visible to a decrypted-TLS observer. File contents and metadata stay
encrypted under client-only secrets.
