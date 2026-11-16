---
name: web-app-authentication
description: Design and generate authentication integrations for new browser web apps using AuthCrunch. Select portal-cookie or OIDC topology, configure renewable sessions, define verified application session and authorization boundaries, and implement login, return navigation, recovery, and logout. Routes React lifecycle and API-client work to react-authentication; excludes Go engine internals and native CLI clients.
---

# Web App Authentication

## Start from the consuming application

Use this skill when adding authentication to a web app or investigating repeated
sign-in prompts. AuthCrunch supplies server protocols and a native portal client;
it does not ship a general React authentication SDK. The application must wire
session discovery, renewal, authorization and recovery into its own lifecycle.

Inspect the app's actual dependencies, routes, API client, backend/gateway and
AuthCrunch version before generating code. Identify the public HTTPS origins,
canonical portal mount, application/API mounts, identity source, verified account
identifier, cookie settings, refresh capability, session policy and logout scope.
Resolve these from source/configuration first. Ask only for decisions that cannot
be inferred, such as a required session lifetime or incompatible origin topology.
Do not invent role names, tenant formats, API paths, SDK exports or host directives.

Keep changes within the repository authorized for the task. An application agent
may read these skills from its AuthCrunch checkout and implement in its authorized
app repository; an AuthCrunch task does not authorize sibling edits. Pin guidance
to the version the consuming application actually runs. A newer checkout's feature
is not evidence that the deployed dependency supports it.

Use [react-authentication](../react-authentication/SKILL.md) to generate the React
provider, cookie-renewal coordinator, account-safe API client and browser tests.
Use [authentication-portal-oidc](../authentication-portal-oidc/SKILL.md) to configure
AuthCrunch as a downstream OpenID Provider and implement its relying-party flow.
Use [authorization-policy-oauth](../authorization-policy-oauth/SKILL.md) to integrate
an existing gatekeeper-owned OAuth login and opaque session instead of a portal.

## Choose one session protocol

Read [topology and server integration](references/topology-and-server.md) before
selecting routes, cookie scopes or a server session adapter. Keep these distinct:

- **Same-origin portal cookies:** serve the app, its APIs and a portal mount under
  one public origin. JavaScript receives verified identity and expiry metadata;
  Secure, HttpOnly cookies carry credentials. Use the portal refresh endpoints
  and compatible cross-tab coordination described in the React workflow.
- **OIDC relying party:** use the provider's discovery, authorization-code/PKCE,
  token and revocation protocols. A backend-for-frontend (BFF) can keep provider
  tokens server-side and expose its own secure app session. A public browser
  client has a different token exposure and lifecycle contract. Portal refresh
  endpoints cannot renew OIDC tokens.
- **Gatekeeper OAuth session:** its policy owns the opaque cookie and recovery.
  Do not assume a portal refresh family exists because login used OAuth.

Cross-origin browser calls are not enabled by using `credentials: include`.
Portal refresh requires exact same-origin requests. Never enable native JSON
body transport, embed client secrets or persist bearer tokens to bypass this
boundary. Choose a supported server arrangement or an explicitly configured
OIDC relying party when origins cannot be unified.

## Define the integration before generating components

Write a compact contract identifying:

1. The selected topology, issuer, portal base, identity source and supported
   renewal capability, with source/configuration evidence.
2. The app's verified session response, API error semantics, server authorization,
   CSRF and account-binding strategy. Distinguish implemented library endpoints
   from endpoints the app must implement.
3. Public bootstrap/login/callback routes, authenticated routes, validated return
   destinations, logout ownership and behavior after explicit sign-out.
4. Access, idle and absolute lifetimes, renewal scheduling, outage behavior,
   cross-tab ownership and restart/storage limits.
5. Files to generate or adapt and acceptance tests for the chosen protocol.

The [application session contract](references/application-session.md) defines the
server/browser boundary and navigation behavior. Keep this contract app-owned;
`whoami` verifies portal identity but does not establish application permissions.
An ID token is likewise not an application API access token.

Read [configuration and operational limits](references/configuration-and-limits.md)
when enabling refresh or diagnosing fixed-time logout. Confirm refresh issuance
for the actual login method; extending a JWT lifetime does not implement renewal.

## Required user experience

A valid renewable session continues without a route change or Sign In click.
Recover expired access before deciding that the user is signed out. Keep the
current route, permitted form state and account lifetime intact during same-account
renewal. A read outage is a recoverable state, not proof of logout. Block operations
that require current authorization until it can be confirmed.

Idle/absolute expiry, revocation, changed authentication requirements, explicit
logout and an uncertain rotation can require fresh login. Never promise an
indefinite session or silently extend policy limits. Explain the recovery action
without exposing credentials or server error details. A public bootstrap must
remain reachable to perform recovery, and protected APIs must return machine-
readable failures rather than login HTML.

## Completion

Match the deliverable to the request. For architecture/design work, provide the
concrete protocol, contracts, configuration choices and validation plan, and label
consumer implementation as remaining work. Do not fabricate app files or runtime
evidence when the consuming repository is unavailable or outside scope.

Generate the server adapter/configuration, browser controller/provider and shared
API integration required by the selected design; a login button or interval alone
is incomplete for an implementation request. Reuse existing app architecture and
current dependency APIs. Do not claim application wiring has been delivered merely
by enabling portal refresh.

Validate normal login, access expiry, simultaneous tabs, restart limits, account
changes, failed requests and logout with the real selected protocol. The React
skill supplies the cookie-flow acceptance matrix. For OIDC or gatekeeper OAuth,
use the corresponding owner's acceptance requirements; do not apply the portal
cookie journal to another protocol. Report the implemented files, checks actually
run and remaining consumer/runtime work without overstating test evidence.
