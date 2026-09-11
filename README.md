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

## Development

Use Go 1.25 or newer (CI uses 1.26.0), Node 24, Python 3.9+, and Make.

```sh
make dep
make ci-check
```

`make test` runs race-enabled Go tests through pinned `tested` and writes the
coverage/report bundle to `.coverage/index.html`. Use `make test-ui` for browser
session tests and `make build` for `bin/authdbctl`.

Repository guidance lives in [repo-local skills](.codex/skills).
[Release and versioning](.codex/skills/release-and-versioning/SKILL.md) describes
`make release` (patch) and `make minor-release`, which publish a release.

## Issues

Please open issues in [caddy-security](https://github.com/greenpau/caddy-security/issues/new/choose).

## Plugins

* Identity Stores:
  - [`go-authcrunch-ids-consul`](https://github.com/greenpau/go-authcrunch-ids-consul): Identity Store Plugin for Consul Key/Value (KV) Store Integration
  - [`go-authcrunch-ids-dynamodb`](https://github.com/greenpau/go-authcrunch-ids-dynamodb): Identity Store Plugin for Amazon DynamoDB Integration

* Credentials:
  - [`go-authcrunch-creds-aws-secrets-manager`](https://github.com/greenpau/go-authcrunch-creds-aws-secrets-manager): Credentials Plugin for AWS Secrets Manager Integration
  - [`go-authcrunch-creds-aws-ssm-parameter-store`](https://github.com/greenpau/go-authcrunch-creds-aws-ssm-parameter-store): Credentials Plugin for AWS SSM Parameter Store Integration
