# Gatekeeper Credential Handling

`pkg/authz/authenticate.go` owns identity-header provenance and downstream token
removal. Strip enabled default claim headers and every configured custom
injection header before any branch can return, including bypass and rejection.
A public route does not authorize caller-supplied authenticated identity headers.
Canonicalize configured names consistently and preserve unrelated headers.

`StripTokenEnabled` covers the accepted cookie, bearer, named Authorization,
query, Basic and API-key source. Bearer, named Authorization, cookie and query
removal preserves unrelated values and Authorization field lines. For Basic,
remove all Basic entries; for API keys, remove every value of the configured
API-key header. Do not claim those two transports retain alternate credentials.
Use parsed cookie values to handle quoted cookies and quote-aware Authorization
splitting to retain commas inside auth parameters. Keep the downstream URL and
RequestURI consistent when removing a query token. Disabled stripping retains
its configured behavior. Cache hits must preserve the original source metadata
needed for equivalent removal.

`pkg/authz/validator/auth.go` hashes Basic/API credential material in internal
cache keys; include local/remote authenticator mode, source address and realm without retaining
raw reusable secrets. The token cache has a fixed 65,536-entry bound, reclaims
expired entries, and declines caching when full without turning a valid request
into an authorization failure. Only successful admission marks a user cached.
The cache still holds ordinary bearer access tokens; hashing password cache keys
does not establish a secret-free process heap.

`strip_token_test.go` and `strip_token_e2e_test.go` cover every source, unrelated
values, quoted cookies/auth parameters, separate header lines and cache hits.
`path_e2e_test.go` proves spoofed identity headers do not survive a bypass.
Use real downstream request observations, not only helper return values.
