# Authorization path interpretations

Use this reference when changing `pkg/authz` bypass or path validation, or
`pkg/acl.MatchPathBasedACL`. These checks protect the path actually handed to
the embedding application's downstream handler.

## Runtime contract

`pkg/authz/internal/uri.RequestPaths` accepts the request and starts from decoded
`r.URL.Path`.
`bypass.Match` and `validator.TokenValidator.authorizeRequest` must require
**every returned interpretation** to pass their policy. Keep the supplied path
as well as its `path.Clean` result at every decoding stage. Keep trailing slash
semantics. Never rewrite `Path`, `RawPath`, or `RequestURI` during authorization.

Cleaning and decoding do not commute. Expand both the original and cleaned
candidate into the next decoding stage, deduplicating paths. There are at most
four additional `url.PathUnescape` passes after HTTP parsing, producing at most
124 candidates across the decoded-path and escaped-path-cleaning branches.
Reject the entire result if a branch still has an encoded byte at the limit or
contains mixed valid and malformed escapes. Literal percent text with no `%HH`
sequence remains valid; use path decoding, never query decoding, so `+` stays
literal. Also include the path obtained by cleaning `URL.EscapedPath()` before
the initial unescape. Reject single-encoded slashes (`%2f`/`%2F`) because segment-aware
routers retain them as segment data while `URL.Path` turns them into separators.
Use `EscapedPath()`, which validates `RawPath`, instead of trusting a stale raw
field. Ordinary empty paths retain the root-path convention. Nil requests/URLs,
opaque targets, authority-form CONNECT (which names a host and port, not `/`),
and the server-wide `*` target fail path checks. CONNECT with a real URL path
remains supported. Do not grant a tunnel solely because its absent path became `/`.

Reject invalid UTF-8 before cleaning at every decoding stage, even if cleaning
would erase the offending segment. Go's regexp matcher treats malformed bytes
as U+FFFD; `ServeMux` compares decoded segment bytes. A regex grant for a valid
U+FFFD directory could otherwise admit `/public/%FF/file` to a different
handler. Do not repair malformed bytes by replacing them. Valid Unicode,
including U+FFFD, remains supported without normalization or case folding.

Do not replace the result with only the final canonical path, or canonicalize
before preserving the supplied path. For example:

- `/admin/%2e%2e/public/file` arrives with `Path=/admin/../public/file` and cleans
  to `/public/file`, but Go's `ServeMux` can dispatch the original escaped target
  to `/admin/`. Cleaning alone must not grant a bypass or path ACL access.
- `/public/a%252fb/../%252e%252e/admin` arrives as
  `/public/a%2fb/../%2e%2e/admin`. Decoding then cleaning reaches `/public/admin`;
  cleaning before decoding reaches `/admin`. Both orders must be checked.
- `/public%2Fadmin` decodes to `/public/admin`, but `ServeMux` can send it to a
  protected fallback handler instead of `/public/`. Reject this separator
  ambiguity even if all decoded interpretations appear public.
- `/public/admin/%2e/../file` becomes `/public/file` when decoded first, but
  cleaning the escaped path first produces `/public/admin/file`. Include both.
- Multiple decoding stages can leave a public path, cross a protected path,
  and later return to a public path. An intermediate denial remains a denial.

The validator runs these checks whenever `ValidateMethodPath` or
`ValidateAccessListPathClaim` is enabled, including every source-address
combination and cached identities. Invalid interpretations return the existing
path authorization errors. Identity-only policies retain their existing behavior;
a rejected bypass still proceeds through normal authentication and authorization.

Bypass matching retains the configured exact, partial, prefix, suffix, or regex
semantics. A prefix `/public` still includes `/publicity`; use `/public/` for a
subtree boundary. Different candidates may match different explicitly allowed
rules. Do not silently turn administrator regex rules into literal patterns.

The supported normalization model is URL percent decoding plus POSIX path
cleaning, starting from `URL.Path`. It does not prove equivalence for backend
case folding, backslash separators, matrix parameters, Unicode normalization,
symlinks, selective decoding, or rewrites after authorization. Embedding servers
must align those routing semantics and any escaped-path-only resource identities
with their policy. Raw query and authority fields are not path ACL inputs.

## JWT path-claim patterns

`pkg/acl.MatchPathBasedACL` interprets `*` and `**` as wildcards and every other
character literally. `*` matches one or more ASCII letters, digits, underscore,
dot, tilde, or hyphen; `**` additionally spans `/`. Empty wildcard matches remain
disallowed. Quote regex metacharacters before expanding wildcards; a grant such
as `/tenant.v1/**` must never authorize `/tenantXv1/file`. This is separate from
explicit regex conditions in policy ACLs and bypass configuration.

Validate UTF-8 in both the pattern and request path before exact matching or
cached regex lookup. The standalone matcher must enforce this itself because
callers outside the gatekeeper may not use `RequestPaths`. An invalid byte must
never alias a valid U+FFFD literal in a wildcard grant.

Compiled patterns are shared across requests. Guard every cache access with its
mutex and cap retained entries; uncached patterns must produce identical
allow/deny decisions when capacity is reached. Do not store request or user
state in this cache.

## Verification

Unit coverage belongs in `pkg/authz/internal/uri/path_test.go`,
`pkg/authz/bypass/bypass_test.go`, `pkg/authz/validator/path_test.go`, and
`pkg/acl/path_test.go`. Cover original and intermediate paths, cleaning/decoding
order, decode limits, malformed/literal percents, invalid UTF-8 at intermediate
stages, valid Unicode, trailing slashes, literal glob punctuation, concurrent
matching, and cache capacity. The URI fuzzer checks closure under both supported
transformations, valid UTF-8, and bounded results. The ACL fuzzer compares
decisions with an independent literal/wildcard matcher without regexp or cache
reuse; keep its input bounds so its reference model remains inexpensive.

Consumer TLS E2E coverage lives in `pkg/authz/path_e2e_test.go` and uses the
public `NewGatekeeper`/`Authenticate` workflow, signed JWTs, real downstream
handlers, and socket-level request targets. Verify forbidden content is never
served; cover `ServeMux`, backends that clean between decoding passes,
encoded-separator routing, escaped-path cleaning, absolute-form and
authority-form targets, leading double slashes, all path/source-address policy
combinations, fresh and cached identities, and concurrent distinct path grants.
The UTF-8 routing matrix covers bypass regexes, method/path regexes, and JWT
wildcards over HTTP/1.1 and HTTP/2; assert the negotiated protocol and successful
valid-Unicode requests as well as rejection. These are gatekeeper consumer tests;
they do not require portal internals.

```sh
make test TEST_DIR='./pkg/authz/... ./pkg/acl' COVERAGE_DIR='.coverage/authz-path-review'
go test ./pkg/authz/internal/uri -run '^$' -fuzz '^FuzzRequestPaths$' -fuzztime=30s -parallel=4
go test ./pkg/acl -run '^$' -fuzz '^FuzzMatchPathBasedACL$' -fuzztime=30s -parallel=4
```

Encoded slash and invalid UTF-8 requests are rejected by path-based checks. A
path normalization change can also intentionally reject requests whose original
form is forbidden even when their cleaned form is allowed. Record this
compatibility effect and any correction to previously interpreted regex syntax
in JWT path grants. Do not claim universal protection against arbitrary backend
normalization.
