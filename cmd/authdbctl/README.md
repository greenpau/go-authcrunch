# AuthDB Management Client

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

Next, list the portal's users:

```bash
authdbctl list users
authdbctl --debug --format table list users
```

## Configuration Files

The `authdbctl`'s configuration file is `~/.config/authdbctl/config.json`.

The configuration file contains the following:

* Auth Portal URL
* Default username, password, realm
* TOTP Shared Secret

The `authdbctl` stores the JWT token acquired after a successful authentication
in `~/.config/authdbctl/token.jwt`.


