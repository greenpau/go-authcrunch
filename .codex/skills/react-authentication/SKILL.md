---
name: react-authentication
description: Implement AuthCrunch authentication in React apps with verified bootstrap, automatic portal-cookie refresh, cross-tab and native-portal coordination, stable account providers, CSRF-safe API requests, recovery, and logout. Use for new React integrations or unwanted sign-in redirects; OIDC/BFF sessions retain their own protocol and renewal owner.
---

# React Authentication

## Select the protocol and existing app boundaries

Inspect the consuming app's manifest, router, providers, API transport and server
session contract. Identify the deployed AuthCrunch version, public origin, portal
mount, supported login/refresh methods and expected session policy. The
[topology contract](../web-app-authentication/references/topology-and-server.md)
and [app session boundary](../web-app-authentication/references/application-session.md)
are prerequisites when these decisions have not yet been made.

This workflow's coordinator is for same-origin **portal-cookie** sessions. OIDC
and BFF integrations can reuse the React lifetime and feedback principles, but
must use their own session adapter and sole renewal owner. Do not attach the
portal cookie algorithm to an OIDC access token or a gatekeeper OAuth cookie.
There is no general AuthCrunch React SDK to import.

Use [refresh-token-transports](../refresh-token-transports/SKILL.md) to implement
or review the exact portal browser HTTP contract and compatibility with the native
portal coordinator.

## Generate one complete integration

Read the focused references for the component being built:

- [Controller and provider blueprint](references/controller-and-provider.md):
  app-owned interfaces, lifecycle, state, timers and identity boundaries.
- [Cookie renewal coordinator](references/cookie-renewal.md): bootstrap, shared
  locks/journal, uncertainty, native-portal interoperability and logout.
- [API requests and acceptance tests](references/requests-and-validation.md):
  account-bound writes, CSRF, retry/cancellation, browser scenarios and diagnostics.

Adapt the consuming app's naming and module conventions. Implement a framework-
independent controller, a thin React provider/hook, one shared API transport and
route/recovery integration. Reuse existing request/cache infrastructure rather
than adding an independent interceptor to each page. App-owned interfaces in these
references are generation contracts, not exports from `go-authcrunch`.

Before writing code, specify who owns refresh in this document and across tabs.
The native `window.AuthCrunchSession` script is a DOM-oriented portal client with
`refresh(force?)` and `logout()`, not an installable React service with a public
subscription/disposal API. Do not load it alongside a second local refresh timer.
A custom React coordinator must interoperate with native portal tabs through the
same origin-and-mount Web Lock and metadata journal.

## Preserve these invariants

- Access expiry is not final session expiry. Bootstrap and API recovery attempt
  safe renewal before a route guard selects fresh login.
- Credentials remain in secure HttpOnly cookies. Browser storage contains only
  the native coordinator's family/expiry/uncertainty metadata; it is never an
  identity or authorization source.
- At most one coordinated rotation occurs at a time across all apps and portal
  tabs sharing a family. A same-tab promise alone is insufficient. Do not replace
  Web Locks with a localStorage spin lock or a BroadcastChannel election.
- Record pending state before dispatch. Never automatically retry an ambiguous
  rotation, clear its marker on unmount, or probe the refresh credential to
  determine whether it was consumed. Fresh login establishes recovery evidence.
- Keep the same account's providers, route and permitted drafts mounted during
  renewal. Do not key them by access `jti`, expiry, or the session response object.
- Fence old account requests and rebind writes to current CSRF/session evidence.
  UI checks do not replace server authorization or expected-account validation.
- Confirm logout before claiming success, preserve uncertainty on failure and
  reconcile other tabs even when hidden. Do not automatically sign back in after
  an explicit successful logout.

## Implement and prove the user experience

Exercise normal renewal without navigation, initial load after access expiry,
background/resume, native portal interactions, blocked storage/locks, concurrency,
interrupted exchanges, permission/account changes and logout. Use the acceptance
matrix to select tests; a fake JWT or mocked provider cannot prove browser cookies,
Origin enforcement, server replay protection or real account binding.

Build and test with the app's actual tooling and this checkout's supported
protocol. Report which consumer and real-auth tests ran. Do not describe the
reference blueprint itself as a shipped SDK or a verified app implementation.
