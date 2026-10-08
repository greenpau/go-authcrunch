# AuthDB Management Client

<!-- begin-markdown-toc -->
## Table of Contents

* [Getting Started](#getting-started)
* [Configuration Files](#configuration-files)
  * [TOTP Configuration](#totp-configuration)
* [Commands](#commands)
  * [Server Metadata](#server-metadata)
  * [List Realms](#list-realms)
  * [List Realm Users](#list-realm-users)
  * [Reload Database](#reload-database)
  * [Database Info](#database-info)
  * [Generating Hashed Password](#generating-hashed-password)
  * [Generating API Key](#generating-api-key)
  * [User Info](#user-info)
  * [Adding New Users](#adding-new-users)
  * [Deleting Users](#deleting-users)
  * [Managing Users](#managing-users)
    * [Disable User](#disable-user)
    * [Password Reset](#password-reset)
    * [Update Roles](#update-roles)
    * [Update Authentication Challenges](#update-authentication-challenges)

<!-- end-markdown-toc -->

## Getting Started

Database management commands require the portal's admin API. With standalone
[`authdb`](../authdb/README.md), set `api.admin_enabled` to `true` in the portal's
JSON configuration. With Caddy, use the `enable admin api` directive shown
below. The `connect` command uses the portal's JSON `/login` endpoint and does
not require the admin API:

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
* API key and realm as an alternative to username/password login

The `authdbctl` stores the JWT token acquired after a successful authentication
in `~/.config/authdbctl/token.jwt`. Despite the filename, this is a JSON object
containing the access token, its header name, and issuance metadata.

Applications can reuse portal authentication through `pkg/authclient`. See the
[authentication client integration guide](../../.codex/skills/authentication-client/references/integration.md)
for the Go API and application-specific credential paths.

For API key login, use `base_url`, `realm`, and `api_key` in the configuration
file, omitting `username`, `password`, and `totp_secret`. Run `authdbctl connect`
as usual. This requires a portal with API key JSON login support and returns an
access token without a refresh session.

### TOTP Configuration

The following configuration contains password and TOTP shared secret for `jsmith`. 

```
base_url: "https://auth.myfiosgateway.com:8443/auth"
username: jsmith
password: My@Password123
totp_secret: mrYEe39OnjZquTrFfg44IFlbGTDMrURlW8wORistVDivuOyzhtIkDYIemscayW6QcwumJe9f33C6a6ruUaZn5qxTKkJq
totp_code_length: 6
realm: "local"
```

If the portal requests TOTP and no `totp_secret` is configured, the CLI prompts
for the current code from your authenticator app. Password-only login does not
prompt for TOTP. U2F/WebAuthn authentication is not supported by the CLI.

## Commands

Successful management commands print the server's JSON response unless an
output format is selected. A server-reported `status: failure` makes the command
exit nonzero with `management operation failed`; the CLI does not print the
failure response body or retry that operation.

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
┌──────────┬─────────────┬───────────────────────────────┬───────────────────────┬──────────┐
│ USERNAME │    NAME     │             EMAIL             │         ROLES         │ DISABLED │
├──────────┼─────────────┼───────────────────────────────┼───────────────────────┼──────────┤
│ webadmin │ Webmaster   │ webadmin@localhost.localdomain │ authp/admin;authp/user │ false    │
│ jsmith   │ Smith, John │ jsmith@localhost.localdomain   │ authp/user;dash        │ false    │
│ mstone   │ Stone, Mia  │ mstone@localhost.localdomain   │ authp/user;dash        │ false    │
└──────────┴─────────────┴───────────────────────────────┴───────────────────────┴──────────┘
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

If the server reports a reload failure, the command exits nonzero with:

```text
failed fetching database info: management operation failed
```

### Database Info

The following commands reads local database info on the server:

```bash
authdbctl info realm --realm local
authdbctl --debug info realm --realm local
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
Algorithm: bcrypt
Status: Generating password hash (length 8)
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

Generate Argon2id instead with the following command:

```bash
authdbctl generate password hash --algorithm argon2
```

It prints `password "argon2:$argon2id$v=19$m=65536,t=3,p=4$...$..."` with a
fresh salt and the complete hash. The defaults use 64 MiB of memory, three
passes and four lanes. Optional `--memory` (KiB), `--iterations` and
`--parallelism` tune Argon2; `--cost` applies only to bcrypt. Keep the generated
value quoted when placing it in configuration.

### Generating API Key

The following command generates a random API key and its bcrypt hash without
prompting for a password:

```bash
authdbctl generate api key
```

Example output follows. Each run generates a new secret and hash.

```text
$ authdbctl generate api key
Database: :memory:
Cost: 10
Status: Generating hash for API key
secret: XnxJ5W0AAcDb2FO1nefd35fTx6jrOAXB29xQ9IuYZRiQeexIH0Vk9IzWih8invXUngQGJGEw
api key XnxJ5W0AAcDb2FO1nefd35fT "bcrypt:10:$2a$10$2QKmYR9Q5wvl8UUNkICUoOf5KMVixTEhbUor5Y3oUfQsrz5iiG.K6"
```

The output can be used in `Caddyfile` to add the API key to a user:

```
		local identity store localdb {
			user webadmin {
				api key XnxJ5W0AAcDb2FO1nefd35fT "bcrypt:10:$2a$10$2QKmYR9Q5wvl8UUNkICUoOf5KMVixTEhbUor5Y3oUfQsrz5iiG.K6"
			}
    }
```


### User Info

The following commands reads user info from local database on the server:

```bash
authdbctl info user --username jsmith --email jsmith@localhost.localdomain --realm local
authdbctl --debug info user --username jsmith --email jsmith@localhost.localdomain --realm local
```

Expected response follows:

```json
{
  "created": "2026-02-28T16:20:05.188852Z",
  "email_address": {
    "address": "jsmith@localhost.localdomain",
    "domain": "localhost.localdomain"
  },
  "email_addresses": [
    {
      "address": "jsmith@localhost.localdomain",
      "domain": "localhost.localdomain"
    }
  ],
  "id": "40244493-f15b-4c59-8baa-1cdeb54e9cf0",
  "last_modified": "2026-02-28T16:20:05.248115Z",
  "name": {
    "first": "John",
    "last": "Smith"
  },
  "names": [
    {
      "first": "John",
      "last": "Smith"
    }
  ],
  "passwords": [
    {
      "algorithm": "bcrypt",
      "cost": 10,
      "created_at": "2026-02-28T16:20:05.188852Z",
      "disabled_at": "0001-01-01T00:00:00Z",
      "expired_at": "0001-01-01T00:00:00Z",
      "hash": "$2a$10$AVaIYtQ.18aWFtW2I3bug./ievuxXJU1zsVqga4VxqeXxWgD39gBe",
      "purpose": "generic"
    }
  ],
  "roles": [
    {
      "name": "user",
      "organization": "authp"
    },
    {
      "name": "dash"
    }
  ],
  "username": "jsmith"
}
```

### Adding New Users

> NOTE: You cannot provide password during the creation of new users.

The following command adds a user to local database on the server:

```bash
authdbctl --debug add user --username jsmith --name "John Smith" --roles "authp/user" --email jsmith@localhost.localdomain --realm local
```

To pass multiple roles use the following pattern:

```bash
authdbctl ... --roles "authp/user","dash" ... --realm local
```

If it fails, you will the following message:

```text
2026/03/06 09:21:04 failed adding "jsmith" user to "local" realm: server responded with 400 after 3 attempts
```

A successfuly response will contain database-generated password:

```json
{"password":"CzRhT3Pg","status":"success","timestamp":"2026-03-06T17:21:02.435454Z"}
```

### Deleting Users

You must provide both username and email to delete a user.

The following command deletes a user from local database on the server:

```bash
authdbctl --debug delete user --username jsmith --email jsmith@localhost.localdomain --realm local
```

If the server reports a deletion failure, the command exits nonzero with:

```text
failed deleting "jsmith" user to "local" realm: management operation failed
```

Successful response follows:

```json
{"status":"success","timestamp":"2026-03-06T16:57:24.029785Z"}
```

### Managing Users

#### Disable User

The following command disables a user in local database on the server. The user will not be able to login.

```bash
authdbctl --debug update user --username jsmith --email jsmith@localhost.localdomain --realm local --disable
```

If the server reports an update failure, the command exits nonzero with:

```text
failed updating "jsmith" user to "local" realm: management operation failed
```

Successful response follows:

```json
{"status":"success","timestamp":"2026-03-06T18:10:15.379784Z"}
```

The user is now disabled:

```text
$ authdbctl --format table list users --realm local
┌──────────┬─────────────┬────────────────────────────────┬────────────────────────┬──────────┐
│ USERNAME │    NAME     │             EMAIL              │         ROLES          │ DISABLED │
├──────────┼─────────────┼────────────────────────────────┼────────────────────────┼──────────┤
│ webadmin │ Webmaster   │ webadmin@localhost.localdomain │ authp/admin;authp/user │ false    │
│ mstone   │ Stone, Mia  │ mstone@localhost.localdomain   │ authp/user;dash        │ false    │
│ jsmith   │ Smith, John │ jsmith@localhost.localdomain   │ authp/user             │ true     │
└──────────┴─────────────┴────────────────────────────────┴────────────────────────┴──────────┘
```


The following command re-enabled a user in local database on the server.

```bash
authdbctl --debug update user --username jsmith --email jsmith@localhost.localdomain --realm local --enable
```


#### Password Reset

The following command resets a user's password in local database on the server.

```bash
authdbctl --debug update user --username jsmith --email jsmith@localhost.localdomain --realm local --reset-password
```

If the server reports a password-reset failure, the command exits nonzero with:

```text
failed updating "jsmith" user to "local" realm: management operation failed
```

A successfuly response will contain database-regenerated password:

```json
{"password":"htJ9v0nw","status":"success","timestamp":"2026-03-06T19:04:56.450332Z"}
```

#### Update Roles

The following command updates user's roles in local database on the server.

```bash
authdbctl --debug update user --username jsmith --email jsmith@localhost.localdomain --realm local --overwrite-roles "authp/user","dash","foo"
```

If the server reports a role-update failure, the command exits nonzero with:

```text
failed updating "jsmith" user to "local" realm: management operation failed
```

A successfuly response follows:

```json
{"roles":["authp/user","dash","foo"],"status":"success","timestamp":"2026-03-06T19:44:25.213519Z"}
```

Alternatively, you can just add roles.

```bash
authdbctl --debug update user --username jsmith --email jsmith@localhost.localdomain --realm local --add-roles "baz"
```

#### Update Authentication Challenges

The following command updates user's authentication challenges in local database on the server.

```bash
authdbctl --debug update user --username jsmith --email jsmith@localhost.localdomain --realm local --overwrite-auth-challenges "u2f","password"
authdbctl --debug update user --username jsmith --email jsmith@localhost.localdomain --realm local --overwrite-auth-challenges "email","password"
```

A successfuly response follows:

```json
{"auth_challenge_rules":["u2f","password"],"status":"success","timestamp":"2026-03-06T19:44:25.213519Z"}
```
