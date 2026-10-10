# Reserved portal route words

Before adding, renaming, or matching a portal route, read the canonical
[reserved-word catalogue](../../../../pkg/authn/testdata/reserved_route_words.json).
Each word has an owner, a route role, and a mount rule. This contributor and CI
contract also checks the standalone host's configuration validation; it is not
a request-time denylist or a new router.

## Reservation rules

| Role | Meaning and rule |
| --- | --- |
| `namespace` | Owns a route family. Add operations beneath the existing owner; do not reuse the name for an unrelated feature. |
| `endpoint` | An existing standalone endpoint retained for compatibility. Do not turn it into a family or copy its unqualified naming for new actions. |
| `early_namespace` | Owned by discovery or the configured OpenID Provider, before ordinary portal extraction. Its dedicated dispatcher owns validation. |
| `asset_prefix` | An existing asset-prefix reservation with legacy matching behavior; not a general API namespace. |
| `mount` | An existing mount convention, not a feature or action namespace. |

New features use descriptive namespaces. New actions belong below their owning
namespace. Every new top-level name must be registered with its intended role
and owner and an explicit mount rule in the catalogue, after reviewing
extraction and competing dispatchers.
Do not auto-populate the catalogue from code or OpenAPI: independence is what
makes unreviewed additions fail. Do not broaden a reserved role or add a generic
action to the standalone compatibility entries just to clear a test.

Reservation is positional. A word used as a realm, identifier, or resource within
another namespace is data owned by that namespace; it must not activate the
same-named portal endpoint. Preserve supported existing names. This catalogue
does not authorize banning reserved words from user/provider data or renaming
existing public routes. An unknown child remains with its selected owner and
fails there, rather than being reinterpreted by another feature.

## Reserved base paths

The portal base path is the mount preceding an endpoint: `/auth` in
`/auth/saml/example`. Root `/`, `/auth`, `/xauth`, `/tenant/auth`, and
`/tenant/xauth` are valid choices. A route word is not a mount name: `/saml`,
`/oauth2`, `/tenant/saml`, and `/oauth2/team` are forbidden mount choices.

The catalogue's `mount` field applies to **every segment** of a configured base
path, independently of whether the associated feature is enabled:

| Mount rule | Constraint |
| --- | --- |
| `allow` | The legacy `auth` mount convention remains available. Unreserved names such as `xauth` are also allowed. |
| `deny_segment` | The whole segment is reserved. A lookalike such as `saml-service` or `team-saml` is allowed. |
| `deny_prefix` | A segment starting with the word is reserved, including `login-service` and `profile-ui`; a name such as `team-login` remains available. |

Prefix reservations cover the legacy substring markers `profile`, `portal`,
`recover`, `forgot`, `register`, `whoami`, `logout`, `favicon`, `beacon`, and
`login`. Other feature/discovery words use whole-segment reservations. Some
reservations are conservative ownership rules even when a subset of endpoints
currently works at that mount; successful login alone does not prove that all
features can share it. Matching is case-sensitive, as in portal dispatch.

`httpserver.Config.Validate`, its public directive parser and `httpserver.Serve`
enforce this policy before provisioning. Host paths must also be canonical
absolute paths, with `/` for root and no trailing slash otherwise; URL escapes,
control characters, query/fragment delimiters and dot segments are rejected by
the existing host validator. New reservations must update host validation and
its catalogue-driven tests together. Other embedding hosts own their configured
mount validation and must adopt this contract; the portal cannot reliably
recover an intended mount from an already ambiguous request path.

These rules constrain configured mount paths, not realm names or resources
inside an established route family. Do not turn them into a global rejection of
requests containing reserved words.

## Why mount extraction matters

`pkg/authn/serve_http.go` selects protocol/API/JSON/browser dispatch;
`respond_http.go`, `respond_json.go`, and `respond_api.go` select operations.
`extract_base_path.go` independently derives the portal mount. They must agree
on the boundary between mount, namespace, and operation/resource.

`extractBaseURLPath` delegates to `util.GetBaseURL`, which uses the first
substring matching one of its comma-separated markers. It is not a router,
longest-prefix matcher, or segment-aware mount resolver. A short action marker
can mistake its feature prefix for the mount. A marker can also match text
inside the mount itself. Replacing `Index` with `LastIndex` does not establish
correctness when realms or nested resource names repeat the marker.

Match complete namespace boundaries before interpreting child actions. A local
child-action switch is valid after the owner is established and its prefix is
removed. Do not promote those local words into global suffix/substring matches.
Retain namespace ownership through errors, content negotiation, and feature
availability. Review the exclusion lists in `crossDeviceRouteIndex` and
`providerLoginRouteIndex` alongside the ordinary dispatch/extraction switches
when introducing a new namespace.

Apply the reserved-base-path rules when designing new mount paths. Legacy inferred
mounts cannot distinguish every possible reserved-word mount from a route.
Lookalike prefixes also need testing where existing code uses substring matches.
Do not silently change the meaning of established mounts. OIDC uses its exact
configured issuer mount; discovery and host-delegated authorization-policy
callbacks have separate dispatch contracts.

## Enforced checks and acceptance evidence

- `TestPortalReservedRouteWords` inspects path literals and local constant
  declarations in the full-path extraction/dispatch owners, folding literal
  concatenations and paths appended to the trailing-slash `Upstream.BasePath`.
  Configuration fields named `BasePath` do not imply that trailing-slash
  convention. It checks
  the assembled path's first word; a child fragment does not acquire top-level
  ownership. New unregistered words fail even without an OpenAPI entry. Moving
  an owner requires updating the scan boundary. Feature-local child switches
  are intentionally excluded. Dynamically assembled paths, identifier aliases
  and constants supplied from other files still require source review; the
  scan is not a complete Go data-flow analysis.
- `TestPortalReservedRouteSourceGuard` feeds proposed source edits through that
  same checker. Keep rejection cases for unregistered roots and endpoint-to-
  namespace changes alongside acceptance cases for child actions, resource
  data, concatenated markers, and local child switches. When extending the
  checker, prove both rejection and continued acceptance of valid ownership.
- `TestPortalRouteContract` reads authored OpenAPI paths, enforces reserved roles,
  and checks mount extraction at root, `/auth`, `/xauth`, nested and escaped mounts.
  It also generates permitted lookalike mounts from every catalogue entry:
  suffixes where allowed, words occurring later in a segment, and case variants.
  This binds the naming policy to real extraction: shortening a segment marker
  must not silently break a previously valid mount.
  Every added documented endpoint joins the matrix automatically. Bare mount
  roots have no endpoint delimiter; early discovery/OP routes have separate
  dispatch tests rather than being forced through ordinary extraction.
- `TestE2EPortalReservedRouteOwnership` uses real TLS, password login and cookies
  to check HTML login, static resources, discovery, JSON/API method handling,
  exact issuer/cookie scope, and preservation of the exact authenticated
  identity and session when an API operation shares a word with a browser
  endpoint. Method rejection must not issue or delete cookies.
- `TestPortalReservedMountContract` checks the catalogue against the standalone
  host's typed validator and public parser, including nested segments, prefix
  lookalikes and safe names. `TestE2EHTTPServerReservedMounts` checks rejection
  through real listener startup and cleanup; the executable's TLS journeys
  retain successful `/auth` and `/xauth` login coverage.

For each new family, add its own collision cases: reserved words used as data,
namespace lookalikes, unknown children, overlapping terminal names, relevant
methods and content negotiation, and feature-disabled behavior. Assert the
selected behavior, mount, redirect and cookie scope; status alone can hide a
wrong handler. Never weaken these assertions simply to admit a new route.

Update the authored OpenAPI contract or explain why a route is outside its
scope, and follow its source-review gate. Fingerprint refresh is not proof of
correct dispatch. No finite vocabulary or test matrix proves all possible
combinations; naming review and feature-specific E2E remain required.

```sh
make test TEST_DIR='./pkg/authn ./pkg/httpserver/...' TEST='PortalReservedRoute|PortalRouteContract|ReservedMount|ExtractBasePath|OIDCIssuerMount|E2EHTTPServerSessions' COVERAGE_DIR=.coverage/portal-routing
make test TEST_DIR=./cmd/authdb TEST=E2EAuthdb COVERAGE_DIR=.coverage/portal-mount-executable
```
