# AuthDB Standalone Server

`authdb` serves AuthCrunch authentication portals using Go's HTTP server. It
supports HTTPS and HTTP/2 without requiring Caddy. Login, identity providers,
profile and admin APIs, refresh sessions, and OpenID Connect use the existing
AuthCrunch implementation.

`authdb` is the server. [`authdbctl`](../authdbctl/README.md) is the separate
authentication and database management client.

## Build

From the repository root, with Go 1.26 or newer:

```sh
make build
./bin/authdb --help
./bin/authdb --version
```

`make build` produces both `bin/authdb` and `bin/authdbctl`. To build only the
server, or install it from this checkout into your Go binary directory:

```sh
go build -mod=readonly -o ./bin/authdb ./cmd/authdb
go install ./cmd/authdb
```

For development, `go run ./cmd/authdb run --config /path/to/authdb.json` also works
from the repository root. Relative paths still use the working directory.

## Run a Local HTTPS Portal

These steps use Bash or Zsh on a Unix-like system. Start in the repository
root after building the binary.

### 1. Prepare the Configuration and Database Directory

Keep configuration, keys, and identities in a private working directory:

```sh
authdb_binary="$(pwd)/bin/authdb"
authdb_workdir="$HOME/.local/share/authdb"
umask 077
mkdir -p "$authdb_workdir/data"
cp cmd/authdb/config.json "$authdb_workdir/authdb.json"
cd "$authdb_workdir"
```

Use a new directory for this walkthrough. On later starts, reuse your existing
configuration and database instead of copying the example over them.

The [example configuration](config.json) listens on `127.0.0.1:8443`, mounts
the `local` portal at `/auth`, and stores local identities in `data/users.json`.
It also enables the admin and profile APIs. **All relative paths use the
process working directory**, including paths inside the JSON configuration;
they are not relative to the configuration file's directory.

### 2. Supply a TLS Certificate and Key

Place your certificate chain in `server.crt` and its matching PEM private key
in `server.key`, or change their paths in `authdb.json`. The certificate must
cover the hostname clients use.

For local development, OpenSSL 3 or newer can generate a certificate:

```sh
openssl req -x509 -newkey rsa:3072 -sha256 -noenc -days 7 \
  -keyout server.key -out server.crt \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

This self-signed certificate requires explicit client trust. The `curl` check
below trusts it with `--cacert`. Browser use requires trusting the certificate
in the browser's certificate store or using a certificate it already trusts.
For deployment, use a certificate trusted by your clients. `authdb` loads
supplied certificates; it does not issue or automatically renew them.

### 3. Bootstrap the Administrator and Start the Server

Set the first administrator's credentials through the environment. This prompt
keeps the password out of shell history:

```sh
export AUTHP_ADMIN_USER=admin
export AUTHP_ADMIN_EMAIL=admin@example.test
printf 'Administrator password: '
read -r -s AUTHP_ADMIN_SECRET
printf '\n'
export AUTHP_ADMIN_SECRET
"$authdb_binary" run --config authdb.json
```

Enter a nonempty password. The local store creates an administrator if its
database has none. Without `AUTHP_ADMIN_SECRET`, it generates a random password
that is not printed. Username and email default to `webadmin` and
`webadmin@localdomain.local` if omitted. These variables do **not** reset an
existing account's password on restart.

The server runs in the foreground and logs `authdb listening` with its actual
listener address. Open `https://localhost:8443/auth/login` and log in as
`admin` using the password you supplied. The identity realm is `local`.
Visiting `/auth` redirects to `/auth/login`.

From another terminal, verify the login page:

```sh
curl --cacert "$HOME/.local/share/authdb/server.crt" \
  --fail --silent --show-error --output /dev/null \
  --write-out '%{http_code}\n' https://localhost:8443/auth/login
```

A successful check prints `200`. Press Ctrl-C in the server terminal to shut
down, then remove the bootstrap secret from that shell:

```sh
unset AUTHP_ADMIN_SECRET
```

For later starts, run `"$authdb_binary" run --config authdb.json` from the same
working directory. The identity database and administrator remain available.
For a service manager, provide secrets through its secret-handling mechanism
and use absolute paths or an explicit working directory.

## Commands and Options

`authdb` follows the same command and help layout as `authdbctl`. Start the
server with the `run` command. Running `authdb` without a command prints help.

```sh
authdb run --config /path/to/authdb.json
authdb run --config /path/to/authdb.json --debug
authdb --config /path/to/authdb.json --debug run
authdb help
authdb help run
authdb version
```

| Command | Behavior |
| --- | --- |
| `run` | Load configuration and serve until shutdown |
| `help`, `help run` | Show available commands or server options |
| `version` | Print version and build information |

| Option | Behavior |
| --- | --- |
| `--config PATH`, `-c PATH` | Select the JSON server configuration |
| `--debug` | Enable debug logging; default is info-level logging |
| `--help`, `-h` | Print help and exit; also supported after `run` |
| `--version`, `-v` | Print version/build information and exit |

`--config` and `--debug` work before or after `run`. An explicit option after
`run` overrides the same option before it, including `--debug=false`.
Configuration selection is: command option, global option,
`AUTHDB_CONFIG_PATH`, then `authdb.json` in the working directory. Help and
version commands do not load configuration or start a listener. Logs are JSON
on standard error; help and version output goes to standard output.

The executable does not load Caddyfiles, expand environment variables inside
JSON, or search other configuration directories. Startup can initialize a
local database; there is no check-only or runtime reload command.

## Configuration

The file contains one JSON object with two required sections: `http` configures
the listener and named portal mounts; `security` is the root AuthCrunch
configuration for portals, identity stores, providers, and other features.

```json
{
  "http": {
    "listen_address": "127.0.0.1:8443",
    "tls_certificate_file": "server.crt",
    "tls_key_file": "server.key",
    "portals": [{"name": "local", "path": "/auth"}]
  },
  "security": {
    "identity_stores": [{
      "name": "local",
      "kind": "local",
      "params": {"realm": "local", "path": "data/users.json"}
    }],
    "authentication_portals": [{
      "name": "local",
      "identity_stores": ["local"],
      "api": {"admin_enabled": true, "profile_enabled": true}
    }]
  }
}
```

Configuration must be a regular file no larger than 16 MiB. Unknown typed
fields, wrong JSON types, additional JSON documents, and null objects inside
typed collections are rejected. Provider-specific `params` maps use their
existing validators. Protect configuration files containing credentials.

### HTTP Settings

| Field | Default | Meaning |
| --- | --- | --- |
| `listen_address` | `127.0.0.1:8443` | TCP `host:port`; port `0` selects an available port reported in the log |
| `tls_certificate_file` | Required for HTTPS | PEM certificate chain |
| `tls_key_file` | Required for HTTPS | Matching PEM private key |
| `insecure_http` | `false` | Plaintext HTTP opt-in; incompatible with TLS file settings |
| `read_header_timeout` | `10s` | Request-header read deadline |
| `read_timeout` | `30s` | Entire request read deadline |
| `write_timeout` | `60s` | Response write deadline |
| `idle_timeout` | `120s` | Keep-alive idle deadline |
| `shutdown_timeout` | `30s` | Graceful HTTP drain window |
| `max_header_bytes` | `1048576` | Header limit; nonzero values must be 1024–16777216 |
| `portals` | Required | Nonempty array of portal names and mount paths |

Timeouts use Go duration syntax, such as `500ms`, `30s`, or `2m`, and must be
positive and at most `24h`. Empty timeout strings and zero or omitted
`max_header_bytes` receive their defaults. HTTPS requires TLS 1.2 or newer;
HTTP/2 is negotiated automatically.

The default listener accepts only local connections. For remote clients,
explicitly select an interface, such as `0.0.0.0:8443` for all IPv4 interfaces.

### Portal Mounts

Every `http.portals[].name` must match a name in
`security.authentication_portals`. Route names are unique. Use mounts such as
`/`, `/auth`, or `/tenant/auth`; omit the trailing slash except for `/` itself.
Multiple portals need separate, nonoverlapping paths. A root mount owns the
entire path space.

Mount roots redirect temporarily to their own `/login`, preserving query
parameters. Paths outside configured mounts return `404`. Mounts cannot
contain URL escapes, control characters, or reserved endpoint namespaces such
as `api`, `assets`, or `login`. Prefixes such as `login-service` and `profile-ui`
are also reserved; choose a neutral name such as `/auth`.

### Explicit HTTP for Local Development

To use plaintext HTTP, replace the `http` section with:

```json
{
  "listen_address": "127.0.0.1:8080",
  "insecure_http": true,
  "portals": [{"name": "local", "path": "/auth"}]
}
```

Keep the `security` section and omit both TLS file settings. This does not
change the portal's secure-cookie defaults; HTTP is not equivalent to the
HTTPS browser-session setup. Refresh and OIDC portals require HTTPS.

### Reverse Proxies

The listener discards `Forwarded`, all `X-Forwarded-*`, and `X-Real-IP` headers.
There is no trusted-proxy configuration. When proxying to `authdb`, use TLS to
its listener and preserve the public `Host` header; client addresses remain
the proxy's peer address. Plain HTTP behind a TLS-terminating proxy does not
restore HTTPS semantics. TCP passthrough can retain local TLS termination.

## Connect with authdbctl

Once the server certificate is trusted by the client, create a separate
private YAML configuration for `authdbctl`:

```yaml
base_url: "https://localhost:8443/auth"
username: "admin"
realm: "local"
```

From the repository root:

```sh
./bin/authdbctl --config /path/to/client.yaml connect
./bin/authdbctl --config /path/to/client.yaml list realms
```

`connect` prompts for the password and uses the ordinary portal login endpoint;
it does not require the admin API. Database management requires an
administrator and `api.admin_enabled: true` in the portal's JSON configuration,
as in the example. Private signing-key export remains separately disabled by
default. See the [management client guide](../authdbctl/README.md) for other
commands and credential-file handling.

## Existing AuthCrunch Features

Configure stores, upstream identity providers, messaging, registration,
transforms, cookies, UI, and signing keys through their existing fields in
`security`. Provider callback URLs include the portal mount.

Access-token signing keys are separate from the listener's TLS key. When
tokens must remain verifiable across restarts, configure persistent keys in
the portal's `raw_crypto_key_store_config`, for example
`crypto key portal sign-verify from file /etc/authdb/access-signing.pem`.
The example uses default key provisioning and does not provide existing-token
continuity across restarts.

For refresh, set `public_origin` to the external HTTPS origin and `base_path`
to the mount. Native refresh requires explicit `body_transport_enabled`. For
OIDC, set the issuer to that origin plus the mount and use dedicated ID-token
keys distinct from access-token keys. Persist provisioned client registrations
and key files before starting. See
[refresh configuration](../../.codex/skills/refresh-token-implementation/references/configuration-and-clients.md)
and [OIDC configuration](../../.codex/skills/authentication-portal-oidc/references/configuration-and-clients.md).

This executable hosts authentication portals. It does not provide an
application reverse proxy, general static-site hosting, or a forward-auth
endpoint. Declaring `authorization_policies` does not expose an HTTP
authorization-check endpoint.

## Shutdown, Restart, and Troubleshooting

SIGINT or SIGTERM stops new requests and drains accepted work before closing
the runtime. At the drain deadline, requests are canceled and connections are
closed. The deadline bounds HTTP draining; blocking provider code can take
longer. A second termination signal exits if startup or shutdown is stuck.
Normal graceful shutdown succeeds; startup or shutdown errors return a
nonzero exit status.

Restart after changing configuration or replacing TLS certificates. There is
no certificate hot reload, seamless runtime replacement, or distributed
session store. Identity databases and configured key files survive restart;
process-local refresh and OIDC sessions require a new login.

| Symptom | Check |
| --- | --- |
| Certificate verification fails | Certificate hostname, expiry, chain, and client trust; use the documented `--cacert` check for the development certificate |
| Remote clients cannot connect | The listener defaults to loopback; also check the selected port and host firewall |
| Address already in use | Another process is listening on the configured address |
| Configuration or TLS file cannot be found | Relative paths use the working directory; prefer absolute paths for services |
| Initialization fails with redacted details | Check `security`, portal/store names, key files, and database-directory permissions; library errors may contain credentials, so the command withholds their details |
| Login fails after changing bootstrap variables | Bootstrap does not reset existing accounts; use the existing account or its password-management workflow |
| Management requests are denied | Enable the admin API and authenticate an administrator; use the portal root as the client's `base_url` |
