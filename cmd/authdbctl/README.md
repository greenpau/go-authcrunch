# AuthDB Management Client

<!-- begin-markdown-toc -->
## Table of Contents

* [Getting Started](#getting-started)
* [Configuration Files](#configuration-files)
* [Commands](#commands)
  * [Server Metadata](#server-metadata)
  * [List Realms](#list-realms)
  * [List Realm Users](#list-realm-users)
  * [Reload Database](#reload-database)
  * [Database Info](#database-info)
  * [Generating Hashed Password](#generating-hashed-password)
  * [Adding New Users](#adding-new-users)
* [Backlog](#backlog)

<!-- end-markdown-toc -->

## Getting Started

The use of the tool requires the `enable admin api` directive in `Caddyfile`:

```text
{
	security {
		authentication portal myportal {
			enable admin api
		}
  }
}
```

Initially, create configuration file `~/.config/authdbctl/config.yaml`:

```bash
mkdir -p ~/.config/authdbctl
touch ~/.config/authdbctl/config.yaml
```

If portal is at `/` (root):

```yaml
---
base_url: "https://auth.myfiosgateway.com:8443"
username: "webadmin"
# password: "foobar"
realm: "local"
```

If portal is at `/auth`:

```yaml
---
base_url: "https://auth.myfiosgateway.com:8443/auth"
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
2026/03/03 12:04:32 auth token acquired: /Users/greenpau/.config/authdbctl/token.jwt
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

The `authdbctl`'s configuration file is `~/.config/authdbctl/config.yaml`.

The configuration file contains the following:

* Auth Portal URL
* Default username, password, realm
* TOTP Shared Secret

The `authdbctl` stores the JWT token acquired after a successful authentication
in `~/.config/authdbctl/token.jwt`.


## Commands

### Server Metadata

The following command retrieves server metadata:

```bash
authdbctl metadata
authdbctl --debug metadata
```

Expected response follows:

```json
{
  "branch": "main",
  "commit": "v1.1.12-1-g9996bf4",
  "name": "authdb",
  "timestamp": "2026-03-03T20:45:05.257195Z",
  "version": "1.1.12"
}
```

### List Realms

The following commands list realms on the server:

```bash
authdbctl list realms
authdbctl --debug list realms
authdbctl --format table list realms
authdbctl --debug --format table list realms
```

Expected response follows:

```json
{
  "count": 1,
  "realms": [
    {
      "realm": "local",
      "kind": "local",
      "name": "localdb"
    }
  ],
  "timestamp": "2026-03-03T21:09:47.86778Z"
}
```


### List Realm Users

The following commands list realm's users on the server:

```bash
authdbctl list users --realm local
authdbctl --format table list users --realm local
```

Expected response follows:

```json
{
  "count": 3,
  "users": [
    {
      "created": "2026-02-28T16:20:05.129675Z",
      "email": "webadmin@localhost.localdomain",
      "id": "e2d8d6ec-c3a5-409a-aeca-24d9f7966c14",
      "last_modified": "2026-03-01T22:25:59.667969Z",
      "name": "Webmaster",
      "revision": 8,
      "roles": [
        "authp/admin",
        "authp/user"
      ],
      "username": "webadmin"
    },
    {
      "created": "2026-02-28T16:20:05.188852Z",
      "email": "jsmith@localhost.localdomain",
      "id": "40244493-f15b-4c59-8baa-1cdeb54e9cf0",
      "last_modified": "2026-02-28T16:20:05.248115Z",
      "name": "Smith, John",
      "roles": [
        "authp/user",
        "dash"
      ],
      "username": "jsmith"
    },
    {
      "created": "2026-02-28T16:20:05.248263Z",
      "email": "mstone@localhost.localdomain",
      "id": "e66c792d-edf2-49c2-80aa-8eb4cddc4f50",
      "last_modified": "2026-02-28T16:20:05.306761Z",
      "name": "Stone, Mia",
      "roles": [
        "authp/user",
        "dash"
      ],
      "username": "mstone"
    }
  ],
  "timestamp": "2026-03-03T23:54:32.222624Z"
}
```

Alternatively:

```text
$ authdbctl --format table list users --realm local
┌──────────┬─────────────┬────────────────────────────────┬────────────────────────┐
│ USERNAME │    NAME     │             EMAIL              │         ROLES          │
├──────────┼─────────────┼────────────────────────────────┼────────────────────────┤
│ webadmin │ Webmaster   │ webadmin@localhost.localdomain │ authp/admin;authp/user │
│ jsmith   │ Smith, John │ jsmith@localhost.localdomain   │ authp/user;dash        │
│ mstone   │ Stone, Mia  │ mstone@localhost.localdomain   │ authp/user;dash        │
└──────────┴─────────────┴────────────────────────────────┴────────────────────────┘
```

### Reload Database

The following commands reload local database on the server:

```bash
authdbctl reload --realm local
authdbctl --debug reload --realm local
```

Expected response follows:

```json
{
  "status": "success",
  "timestamp": "2026-03-04T00:38:27.526579Z"
}
```

The the reload fails, the expected response follows:

```json
{
  "status": "failure",
  "timestamp": "2026-03-04T00:48:37.023904Z"
}
```

Additionally, you will see the following log. Here, I broke `users.json` by malforming JSON structure.

```text
2026/03/04 00:48:37.023 WARN    security        failed to reaload database      {"session_id": "CK4Zqwxp9KsH4pP9hgylwcee6E6hJAp21TmdN", "request_id": "c3b08c7b-5c92-43e5-8b88-58ea31b66a9a", "api_endpoint": "server/reload", "error": "failed initializing database at \"assets/config/users.json\": invalid character ':' after top-level value"}
```

### Database Info

The following commands reads local database info on the server:

```bash
authdbctl info --realm local
authdbctl --debug info --realm local
```

Expected response follows:

```json
{
  "in_memory": false,
  "last_modified": "2026-03-04T00:25:06.170999Z",
  "loaded_at": "2026-03-04T00:25:06.111275Z",
  "path": "assets/config/users.json",
  "policy": {
    "password": {
      "keep_versions": 10,
      "min_length": 8,
      "max_length": 128,
      "require_uppercase": false,
      "require_lowercase": false,
      "require_number": false,
      "require_non_alpha_numeric": false,
      "block_reuse": false,
      "block_password_change": false
    },
    "user": {
      "min_length": 3,
      "max_length": 50,
      "allow_non_alpha_numeric": false,
      "allow_uppercase": false
    }
  },
  "revision": 62,
  "timestamp": "2026-03-04T00:25:18.089139Z",
  "user_count": 3,
  "version": "1.1.12"
}
```

### Generating Hashed Password

The following command generates hashed password. The tool prompt the user for the password.

```bash
authdbctl generate password hash
```

The output follows. Entered `12345678` when prompted "Enter Password".

```text
$ authdbctl generate password hash
Enter Password: 
Database: :memory:
Cost: 10
Status: Generating hash for password 12...78 (length 8)
password "bcrypt:10:$2a$10$K9KksvjRCdjT1sYbecGCCu.Y33xpii94itQPgGVS6vShuEUB0On1q"
```

You can provide path to existing database file. This way the tool will check password compliance policies.

```bash
authdbctl generate password hash --db-path assets/conf/local/users.json
```

You can also provide custom cost.

```bash
authdbctl generate password hash --cost 10 --password SomeFunkyPassword
```

### Adding New Users

The following commands adds a user to local database on the server:

```bash
bin/authdbctl --debug add user --username jsmith --name "John Smith" --roles "authp/user" --email jsmith@localhost.localdomain --realm local
```

To pass multiple roles use the following pattern:

```bash
bin/authdbctl ... --roles "authp/user","dash" ... --realm local
```

If you want to provide password, then do it like this:

```bash
bin/authdbctl --debug add user --username jsmith --name "John Smith" --roles "authp/user" --email jsmith@localhost.localdomain --realm local < "My@Password123"
```

Expected response follows:

```json
TBD
```

## Backlog

* [ ] auth with app authenticator
* [ ] auth with U2F token
