---
name: saml-identity-provider
description: Maintain upstream SAML identity-provider authentication, request/response browser binding, ACS and assertion validation, pinned signing certificates, and signed TLS/browser tests.
---

# SAML Identity Provider

`pkg/idp/saml` owns provider configuration, metadata, service providers and
request state. `pkg/authn` supplies the browser transport. Use shared provider
construction and public portal consumers in tests; do not conflate downstream
OIDC sessions with upstream SAML authentication.

## Configuration boundary

`pkg/idp/saml.Config` owns name, realm, driver, metadata location, signing pin,
IdP login URL, ACS URLs, TLS settings, and login-icon configuration. Its
`Validate` checks required values and applies the `azure` or `generic` driver
behavior; `saml.NewIdentityProvider` constructs the runtime. Shared
`idp.IdentityProviderConfig` dispatches SAML parameters through `idp.NewIdentityProvider`.

There is no dedicated SAML directive-parser package or SAML constructor in
`pkg/idp/parser`; that package currently adapts only OAuth. This is an existing
configuration-parser conformance gap. Do not invent a supported SAML directive
API, or infer one from an embedding server's configuration syntax. A change to
this configuration surface must include its parser and consumer coverage under
the [shared parser contract](../coding-directives/references/configuration-parsers.md).

## Browser transaction and trust

GET initiates an SP AuthnRequest. RelayState is a random transaction identifier,
never a redirect destination or browser credential. Bind it server-side to the
initiating browser secret, exact configured ACS callback, AuthnRequest ID and a
five-minute deadline. Admit matching callbacks atomically once, before XML
validation; failed verification requires a new initiation. Capacity is bounded;
expiry reclamation must not allow replay or evict active state to admit another
request. No unconditional IdP-initiated acceptance is supported.

SAML binds no post-login destination to the transaction. A trusted `redirect_url`
on the initiating GET only refreshes the portal's shared redirect cookie, and the
portal never reads one from the ACS callback URL; see the
[redirect trust boundaries](../threat-hunting/references/redirects.md#portal-login-and-external-providers).
`TestE2ESAMLCallbackIgnoresDestinationOnItsURL` keeps that boundary.

The portal browser binding must survive a real cross-site HTTP-POST callback.
A default/Lax session cookie is insufficient even if Go's cookiejar sends it in
TLS tests. Use the dedicated factory-managed SAML binding cookie with host-only,
Secure, HttpOnly, SameSite=None attributes, independent of the ordinary session
cookie and RelayState. Domain-scoped session IDs must not supply SAML proof.
Cookie names/configuration/parsing/collision checks belong to
[portal cookies](../authentication-portal-cookies/SKILL.md).

Pass only the stored AuthnRequest ID to the SAML verifier with
AllowIDPInitiated=false. Keep exact destination/recipient, issuer, audience,
signature, time and subject-confirmation checks. Callback selection comes from
the actual mounted request, never a caller-supplied RelayState URL.

`IdpSignCertLocation` is the authoritative signing pin. Remove all metadata
signing-capable descriptors (use signing or omitted) across every IdP SSO
partition; preserve explicit encryption descriptors. Metadata must not widen
trust by adding another certificate. This is exact signing-certificate trust,
not permission for arbitrary descendants of a configured CA certificate.

## Acceptance and validation

Unit tests cover state lifetime/capacity/concurrency and certificate precedence.
`pkg/authn/saml_state_e2e_test.go` uses real signed responses and a TLS portal:
valid login, missing/wrong-browser/wrong-callback/replayed state and rogue metadata
cert rejection. Preserve a real Chrome cross-site POST journey for cookie
semantics; a net/http cookiejar alone cannot validate SameSite. Document migration
from earlier unsolicited IdP responses and test only synthetic local IdPs.

```sh
make test TEST_DIR='./pkg/idp/saml ./pkg/authn/cookie/... ./pkg/authn' TEST='SAML|Saml|StateManager' COVERAGE_DIR=.coverage/saml
```

A valid signed response from the initiating browser at the bound ACS succeeds
once. Wrong-browser, wrong-callback, expired, replayed, or metadata-only rogue
signing credentials cannot issue a portal token. Retain a successful control
alongside each rejection so transport failure cannot masquerade as validation.
