# go-authcrunch

AuthCrunch provides Authentication, Authorization, and Accounting (AAA)
Security Functions (SF) in Golang.

<a href="https://github.com/greenpau/go-authcrunch/actions/workflows/test.yml" target="_blank"><img src="https://github.com/greenpau/go-authcrunch/actions/workflows/test.yml/badge.svg?branch=main"></a>
<a href="https://pkg.go.dev/github.com/greenpau/go-authcrunch" target="_blank"><img src="https://img.shields.io/badge/godoc-reference-blue.svg"></a>

This code base contains the functions implementing AAA. It is a standalone library, i.e. it can be used with Gin, Beego, Echo,Mux (Gorilla). 
Originally developed for the Caddy web server in the form of `caddy-security` app, AuthCrunch forms the foundation for the
server's security functionality, including authentication portal, authorization gateway, and other features.

## Documentation

Please browse to [docs.authcrunch.com](https://docs.authcrunch.com/).

See [portal refresh sessions](.codex/skills/refresh-token-implementation/references/configuration-and-clients.md) for opt-in rotating refresh
credentials, configuration, client integration, and lifecycle behavior.

See [the portal OpenID Provider](.codex/skills/authentication-portal-oidc/references/configuration-and-clients.md)
for local-user OIDC login and relying-party registration, the
[reusable Go provider](.codex/skills/authentication-portal-oidc/references/reusable-provider.md), and
[conformance testing](.codex/skills/authentication-portal-oidc/references/conformance.md).

## Standalone server

Run AuthCrunch directly with Go's HTTP server using `authdb`:

```sh
make build
./bin/authdb run --config /path/to/authdb.json
```

Start with [the example configuration](cmd/authdb/config.json), set your TLS
certificate/key and identity database paths, and follow the
[authdb usage guide](cmd/authdb/README.md).
The example serves the portal at `https://localhost:8443/auth`. `authdbctl`
remains the management client; Caddy is not required.

## Development

Use Go 1.26 or newer (CI uses 1.26.8), Node 24, Python 3.9+, and Make.

```sh
make dep
make change-test
make ci-check
```

`make change-test` tests staged, unstaged, and untracked changes. Use
`make change-test CHANGE_DRY_RUN=1` to inspect its selection. Documentation-only
changes skip tests; Go changes select owning packages and affected consumers.
Selected Go reports are in `.coverage/changes/go/index.html`. See
[change-based testing](.codex/skills/scripts-and-automation/references/change-tests.md)
for commit ranges, fallbacks, and GitHub's selected-then-full validation flow.

`make test` runs race-enabled Go tests through pinned `tested` and writes the
coverage/report bundle to `.coverage/index.html`. Use `make test-ui` for browser
session tests and `make build` for `bin/authdb` and `bin/authdbctl`.
Tests run one package at a time with a memory/process watchdog on macOS and
Linux. An exceeded budget stops the run and records the reason in
`.coverage/resource-usage.json`. See the
[test resource controls](.codex/skills/scripts-and-automation/references/test-resources.md)
for limits and troubleshooting.

Run `make generate-acl` to regenerate ACL conditions, rules, and their tests
from `assets/scripts/generate_acl.py`. It requires Python 3.9+ and `gofmt` on
PATH; no separate generator repository or Python packages are needed.

Repository guidance lives in [repo-local skills](.codex/skills).
[Release and versioning](.codex/skills/release-and-versioning/SKILL.md) describes
`make release` (patch) and `make minor-release`, which publish a release.
Use `make fast-release` or `make fast-minor-release` to skip the local quality
gate, including tests; GitHub release validation still runs.

## Issues

Please open issues in [caddy-security](https://github.com/greenpau/caddy-security/issues/new/choose).

## Plugins

Production plugins are separate Go modules. Synthetic references under `plugins/`
are packages in this root module. Secrets plugins retrieve values for an
embedding application to apply to AuthCrunch configuration. Host registration
and configuration syntax belong to that application's adapter; this library
does not automatically discover or load plugins.

### Secrets

| Plugin | Backend |
| --- | --- |
| [`go-authcrunch-secrets-static-secrets-manager`](https://github.com/greenpau/go-authcrunch-secrets-static-secrets-manager) | Statically configured secret maps |
| [`go-authcrunch-secrets-aws-secrets-manager`](https://github.com/greenpau/go-authcrunch-secrets-aws-secrets-manager) | JSON secrets retrieved from AWS Secrets Manager |

See the [secrets plugin contracts](.codex/skills/secrets-plugins/SKILL.md) for
their APIs, integration examples, and lifecycle differences. To build a plugin,
start with the [plugin architecture](.codex/skills/plugin-development/SKILL.md)
and [development blueprint](.codex/skills/plugin-development/references/development-blueprint.md).

### Plugin categories

Beyond secrets, the architecture covers the following extension categories.
Existing Go interfaces support some forms of direct composition; other entries
describe proposed integration work. This is a development map, not a list of
installed or automatically loadable backends.

| Category | Purpose | Integration status |
| --- | --- | --- |
| [Identity stores](.codex/skills/plugin-development/references/plugin-categories.md#identity-stores) | Account databases such as PostgreSQL, DynamoDB, or Consul | Direct portal injection; new root-config kinds need dispatch integration |
| [Identity providers](.codex/skills/plugin-development/references/plugin-categories.md#identity-providers) | Federation services and authentication protocols | Direct portal injection; new protocols also need routing and flow support |
| [Credential authenticators](.codex/skills/plugin-development/references/plugin-categories.md#credential-authenticators) | External Basic-credential or API-key verification | Gatekeeper authenticator injection with configured realm binding |
| [Messaging](.codex/skills/plugin-development/references/plugin-categories.md#messaging) | Email APIs and notification delivery | Provider interface exists; new backends need config and consumer wiring |
| [Registration workflows](.codex/skills/plugin-development/references/plugin-categories.md#registration-workflows) | Invitations, approvals, and account creation | Direct registry attachment; root configuration is local-only |
| [Session and refresh storage](.codex/skills/plugin-development/references/plugin-categories.md#session-and-refresh-storage) | Shared token-family storage and revocation | Refresh-engine interface exists; portal backend selection needs wiring |
| [Cryptographic signing](.codex/skills/plugin-development/references/plugin-categories.md#cryptographic-signing) | Sign approved token claims with a selected key | [Local PS256 plugin](plugins/cryptographic-signing/rsapss), refresh-engine injection, and core verification; general portal/OIDC signer selection remains separate |
| [External authorization](.codex/skills/plugin-development/references/plugin-categories.md#external-authorization) | Decisions from an external policy service | Required gatekeeper/validator decisions and [HTTP JSON plugin](plugins/external-authorization/httpjson) |
| [Claims enrichment](.codex/skills/plugin-development/references/plugin-categories.md#claims-enrichment) | Trusted organization, group, or entitlement attributes | Request-time gatekeeper/validator hook and [static claims plugin](plugins/claims-enrichment/static) |

The [category contracts](.codex/skills/plugin-development/references/plugin-categories.md)
describe current APIs, implementation gaps, lifecycle requirements, and acceptance
scenarios for each category. Backend examples do not imply published support.

### Other plugin projects

At the inspected revisions linked below, these repositories contain project
scaffolding only, with no Go backend implementation or module manifest. They are
project references, not usable plugins. Check implementation and consumer
compatibility when revisiting a newer revision.

| Category | Project | Inspected status |
| --- | --- | --- |
| Identity stores | [`go-authcrunch-ids-consul`](https://github.com/greenpau/go-authcrunch-ids-consul) — Consul KV | [Scaffold](https://github.com/greenpau/go-authcrunch-ids-consul/tree/0e5fc8d9669559ef0770280491c042dffde02908) |
| Identity stores | [`go-authcrunch-ids-dynamodb`](https://github.com/greenpau/go-authcrunch-ids-dynamodb) — Amazon DynamoDB | [Scaffold](https://github.com/greenpau/go-authcrunch-ids-dynamodb/tree/c274052b44f9588df267670333876843520b28df) |
| Credentials | [`go-authcrunch-creds-aws-ssm-parameter-store`](https://github.com/greenpau/go-authcrunch-creds-aws-ssm-parameter-store) — AWS SSM Parameter Store | [Scaffold](https://github.com/greenpau/go-authcrunch-creds-aws-ssm-parameter-store/tree/5e6d455275419921c2fe9695bae4ff9110de7d8f) |
