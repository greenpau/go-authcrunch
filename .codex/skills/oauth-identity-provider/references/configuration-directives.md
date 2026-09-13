# Upstream OAuth Configuration Directives

Sections: [public APIs](#public-apis), [grammar](#grammar),
[trust settings](#issuer-and-audience), [validation](#validation-and-defaults),
and [maintenance](#maintaining-the-parsers).

These parsers configure an upstream identity provider against which portal users
authenticate. Portal OIDC providers and registered OAuth applications have their
own parsers under `pkg/oidc/parser`.

## Public APIs

Both packages export
`NewOAuthIdentityProviderConfigFromDirectives(name string, statements []string)`:

| Import | Result | Application |
| --- | --- | --- |
| `pkg/idp/oauth/parser` | `*oauth.Config, error` | `oauth.NewIdentityProvider(config, logger)` |
| `pkg/idp/parser` | `*idp.IdentityProviderConfig, error` | `idp.NewIdentityProvider(config, logger)` or root `Config.AddIdentityProvider(config.Name, config.Kind, config.Params)` |

The typed parser owns grammar and invokes `oauth.Config.Validate`. The shared
adapter reuses it, retains defaults, preserves integral settings during JSON
conversion, and invokes `idp.NewIdentityProviderConfig`. It removes only `name`
and derived `server_name` from Params. The existing shared allowlist remains
authoritative: typed-only `logout_url` is rejected by the shared adapter. Do not
silently drop unsupported settings or duplicate grammar in the adapter.

Consumer example after tokenization and placeholder expansion:

```go
import (
    idpparser "github.com/greenpau/go-authcrunch/pkg/idp/parser"
    cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

provider, err := idpparser.NewOAuthIdentityProviderConfigFromDirectives("corporate", []string{
    cfgutil.EncodeArgs([]string{"realm", "employees"}),
    cfgutil.EncodeArgs([]string{"driver", "generic"}),
    cfgutil.EncodeArgs([]string{"client_id", clientID}),
    cfgutil.EncodeArgs([]string{"client_secret", clientSecret}),
    cfgutil.EncodeArgs([]string{"metadata_url", metadataURL}),
    cfgutil.EncodeArgs([]string{"issuer", expectedIssuer}),
    cfgutil.EncodeArgs([]string{"access_token_audience", resourceAudience}),
})
if err != nil {
    return err
}
return config.AddIdentityProvider(provider.Name, provider.Kind, provider.Params)
```

Pass only the complete block body, with name separate; omit enclosing braces
and headers. The consumer collects all statements before calling the parser so
duplicates are rejected across the whole provider. It also associates the
registered provider name with its portal configuration. The parser does not
implement a host's block traversal, placeholder expansion, or registration.
All consumer integration work outside this repository is separate work.

## Grammar

The parser uses `cfgutil.DecodeArgs`. Encode one statement at a time, with each
keyword a separate token and each quoted value retained as one token. Reject
empty tokens before encoding because `EncodeArgs` can trim a trailing empty
field. Raw CR/LF and invalid UTF-8 records are rejected. No boolean literals,
grouped keyword tokens, implicit last-value-wins, or arbitrary Params passthrough.

Scalar and list keys below accept the displayed existing snake_case spelling
or the equivalent separate words, for example `client id` and `access token
audience`. Each setting may occur once, including across aliases. Values retain
their exact spelling; quoted whitespace in a nonblank value is preserved.

| Kind | Keys | Arguments |
| --- | --- | --- |
| Scalar | `realm`, `driver`, `domain_name`, `client_id`, `client_secret`, `server_id`, `tenant_id`, `user_pool_id`, `region` | One nonblank value |
| Scalar | `issuer`, `access_token_audience`, `base_auth_url`, `metadata_url`, `authorization_url`, `token_url`, `logout_url` | One nonblank value |
| Scalar | `identity_token_cookie_name`, `identity_token_field_name`, `user_info_roles_field_name` | One nonblank value |
| List | `scopes`, `required_token_fields`, `response_type`, `user_group_filters`, `user_org_filters`, `user_info_fields` | One or more nonblank tokens in one statement |
| Integer | `delay_start`, `retry_attempts`, `retry_interval` | One integer, using the typed config's seconds/count semantics |

Switches take exactly `enabled` or `disabled`, with separate words:

```text
metadata discovery enabled
key verification enabled
pass grant type enabled
response type parameter enabled
scope enabled
nonce enabled
pkce enabled
accept header disabled
js callback disabled
logout disabled
identity token cookie disabled
email claim check enabled
tls verification enabled
```

These show syntax and the ordinary generic-provider state, not a required
block. Omission retains typed, driver-specific defaults. Disable fields invert
the positive setting names; e.g. `tls verification disabled` sets
`TLSInsecureSkipVerify`. Preserve nonce, PKCE, signature, and TLS protections in
production examples. Repeated or opposing states are rejected. Serialized
boolean keys such as `nonce_disabled true` are not directive grammar.

`jwks key <kid> <path>` takes exactly one nonblank key ID and public PEM path.
It may repeat with distinct IDs; duplicate IDs fail. Paths with spaces must be
one encoded token. Existing Ed25519 PKIX/SPKI, RSA PKIX, and RSA PKCS#1 public
key formats require no algorithm-specific directive. Private-key input remains
unsupported. This directive populates `Config.JwksKeys`.

`login icon <attribute> <value>` supports `class name`, `color`, `background
color`, `text`, `text color`, `text background color`, and integer `priority`.
Attribute snake_case aliases are accepted. Each attribute occurs once and takes
one value; quote labels with spaces. This nested appearance configuration is
part of the OAuth grammar. `ServerName` is derived; unused `AppSecret` and
`UserRoleMapList` fields are not operator settings.

## Issuer and Audience

Both of these are single-value directives:

```text
issuer https://idp.example
access_token_audience resource-api
```

`access token audience resource-api` is also accepted. An explicit issuer
overrides discovered metadata, and matching uses the exact string, including
case and trailing slash. Omitted issuer falls back to discovery; with neither
configured nor discovered issuer, existing optional checking is preserved.
Never infer issuer from `base_auth_url` or normalize configured issuer strings.

`access_token_audience` sets the audience for the optional JWT access token.
ID tokens and access tokens selected as the identity token still use the client
ID. When access audience is omitted, the existing access-token `azp` fallback
remains available; an explicit audience mismatch does not use that fallback.
An invalid identity token rejects login. Invalid optional JWT access tokens
contribute no claims while a valid identity token can still authenticate.
Opaque bearer/UserInfo handling is unchanged.

## Validation and Defaults

An empty body cannot construct a usable provider. Required fields, driver
normalization, endpoint dependencies, retry defaults, default scopes and token
fields, filter regex validation, icon defaults, and public-key validation remain
owned by `oauth.Config.Validate`. The parser adds strict grammar and duplicate
checks, not a second implementation of domain constraints. When identity token
cookies are enabled without an explicit name, validation uses
`cookie.NewConfig().IdentityTokenCookieName` (`AUTHP_ID_TOKEN`). The public
`DefaultIdentityTokenCookieName` constant is only the suffix. An explicit
provider cookie name remains authoritative for issuance, Whoami, and logout;
see the [shared cookie owner](../../authentication-portal-cookies/SKILL.md).
`pkg/authn/oauth_cookie_e2e_test.go` verifies both defaults and overrides through
the real TLS login, Whoami, and external logout workflow.

Validation can read configured static key files; parsing does not fetch
discovery/JWKS, generate credentials, start workers, or bind sockets. Repeated
parsing returns independent normalized config objects. Caller inputs are not
mutated. Errors return no partial config and identify known settings/statement
positions without echoing raw values, secrets, or key paths. Domain validation
errors are deliberately redacted because they may include supplied values.

Grammar and examples are tested externally in both parser packages. Root
registration/reload is covered by `config_oauth_identity_provider_test.go`.
The real TLS portal fixture imports the shared parser directly, reloads its
serialized result, and verifies trust enforcement and static key handling
through code exchange, portal credentials, and protected-resource access.
Use the commands in the owning skill's [Validation section](../SKILL.md#validation).

## Maintaining the Parsers

`pkg/idp/oauth/parser/fields.go` owns scalar/list/integer/state bindings and
nested login-icon attributes. `parser.go` owns statement decoding, names, JWKS
entries, duplicate tracking, and final typed validation. `pkg/idp/parser/oauth.go`
only adapts the normalized result to shared configuration. Extend these owners
when exposing settings; do not add OAuth grammar to the root config, dispatcher,
or each embedding handler.

For a new operator setting, add its binding, cardinality, supported spelling,
and corresponding tests. Check `pkg/idp/config.go` when the setting must also
work through shared dispatch. Keep derived and unused fields out of the grammar,
and retain documented typed-only differences unless the task changes that
contract. Existing scalar/list/integer aliases are compatibility behavior;
new spelling choices still follow the repository's readable-keyword convention.

Match the longest exact keyword prefix before consuming values. For example,
`response type parameter disabled` must select the state setting instead of the
`response type` list, and `identity token cookie name` must select the name
instead of the cookie switch. Preserve decoded token boundaries and use one
canonical identity for duplicate detection across aliases. Test overlapping
keywords and quoted values when extending these tables.

The shared adapter uses `json.Decoder.UseNumber` to preserve integral retry and
delay values. Keep `TestOAuthIdentityProviderAdapterPreservesIntegers` exercising
that boundary, alongside shared validation, JSON reload, and independent-result
tests. Keep real portal E2E setup importing the shared parser and passing its
reloaded result into `idp.NewIdentityProvider`; manually rebuilding an OAuth
config there would bypass the integration under test.
