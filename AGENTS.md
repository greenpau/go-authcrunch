# Repository Guidelines

## Project Summary

go-authcrunch is a Go library for AuthCrunch Authentication, Authorization, and
Accounting (AAA) security functions. It provides the core runtime used for
authentication portals, authorization gatekeepers, identity stores, identity
providers, single sign-on providers, user registration, messaging, credentials,
and cryptographic key handling.

The top-level `authcrunch.Config` and `Server` wire together the repository's
major packages. Authentication portal behavior lives mostly under `pkg/authn`,
authorization policy and gatekeeper behavior under `pkg/authz`, identity store
dispatch under `pkg/ids`, identity provider dispatch under `pkg/idp`, local and
LDAP stores under `pkg/ids/local` and `pkg/ids/ldap`, OAuth and SAML providers
under `pkg/idp/oauth` and `pkg/idp/saml`, and crypto key management under
`pkg/kms`.

The repository also includes the `authdbctl` management CLI in `cmd/authdbctl`,
embedded portal/profile UI assets under `pkg/authn/ui`, shared identity and user
data models under `pkg/identity`, user registration under `pkg/registry`,
messaging providers under `pkg/messaging`, i18n helpers under `pkg/translate`,
and test fixtures under `testdata`.

## Source Code Management

Use the repo-local `source-code-management` skill for commit message rules and
for the workflow used when asked to create a commit message for a change.
