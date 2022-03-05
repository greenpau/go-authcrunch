# AuthDB Management Client

<!-- begin-markdown-toc -->
## Table of Contents

* [Getting Started](#getting-started)
* [Configuration Files](#configuration-files)
* [Under Development](#under-development)

<!-- end-markdown-toc -->

## Getting Started

Initially, create configuration file ` ~/.config/authdbctl/config.yaml`:

```yaml
---
base_url: "https://auth.myfiosgateway.com:8443"
username: "webadmin"
# password: "foobar"
realm: "local"
```

First, connect to an Auth Portal instance:

```bash
authdbctl connect
authdbctl --debug connect
```

The expected output follows:

```
2022/02/15 18:33:01 auth token found: /home/greenpau/.config/authdbctl/token.jwt
```

Next, get metadata:

```
authdbctl metadata
```

The expected output follows:

```
{"branch":"main","commit":"v1.0.17-2-g8295d6a","name":"authp","timestamp":"2022-03-05T15:27:07.289679072Z","version":"1.0.17"}
```

## Configuration Files

The `authdbctl`'s configuration file is `~/.config/authdbctl/config.json`.

The configuration file contains the following:

* Auth Portal URL
* Default username, password, realm
* TOTP Shared Secret

The `authdbctl` stores the JWT token acquired after a successful authentication
in `~/.config/authdbctl/token.jwt`.

## Under Development

* [ ] `authdbctl list realms`
* [ ] `authdbctl --format table list users --realm local`
* [ ] `authdbctl add user --realm local <user_data.json>`
* [ ] `authdbctl --format table list ...`
* [ ] `authdbctl reload realm --name local`
* [ ] auth with app authenticator
* [ ] auth with U2F token
