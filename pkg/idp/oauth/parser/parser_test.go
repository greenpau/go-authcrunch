// Copyright 2026 Paul Greenberg greenpau@outlook.com
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package parser_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/authn/icons"
	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	oauthparser "github.com/greenpau/go-authcrunch/pkg/idp/oauth/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func oauthDirectives(extra ...string) []string {
	return append([]string{
		"realm upstream", "driver generic", "client_id client", "client_secret synthetic-secret",
		"base_auth_url https://endpoint.example/oauth", "metadata_url https://metadata.example/discovery",
	}, extra...)
}

func TestNewOAuthIdentityProviderConfigFromDirectives(t *testing.T) {
	config, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", oauthDirectives())
	if err != nil {
		t.Fatal(err)
	}
	if config.Name != "upstream" || config.Realm != "upstream" || config.Driver != "generic" || config.ServerName != "endpoint.example" {
		t.Fatal("provider identity or derived server name changed")
	}
	if config.Issuer != "" || config.AccessTokenAudience != "" {
		t.Fatal("omitted trust settings must not be derived from endpoint URLs")
	}
	if config.NonceDisabled || config.PKCEDisabled || config.TLSInsecureSkipVerify || config.MetadataDiscoveryDisabled || config.KeyVerificationDisabled {
		t.Fatal("parser disabled a default verification control")
	}
	if !slices.Equal(config.Scopes, []string{"openid", "email", "profile"}) || !slices.Equal(config.ResponseType, []string{"code"}) || config.IdentityTokenFieldName != "id_token" {
		t.Fatal("typed configuration defaults were not applied")
	}
	for _, key := range []string{"issuer", "access_token_audience", "access token audience"} {
		t.Run(key, func(t *testing.T) {
			value := "https://Issuer.example/Exact/"
			if key != "issuer" {
				value = "resource with spaces"
			}
			args := append(strings.Split(key, " "), value)
			got, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", oauthDirectives(cfgutil.EncodeArgs(args)))
			if err != nil {
				t.Fatal(err)
			}
			actual := got.AccessTokenAudience
			if key == "issuer" {
				actual = got.Issuer
			}
			if actual != value {
				t.Fatal("parser changed an explicit trust value")
			}
		})
	}
}

func TestOAuthIdentityProviderDirectiveFields(t *testing.T) {
	statements := []string{
		"realm upstream", "driver generic", "client id client", "client secret synthetic-secret",
		"domain name example.test", "server id server", "tenant id tenant", "user pool id pool", "region region-1",
		"issuer https://issuer.example/", "access token audience resource-api",
		"base auth url https://endpoint.example/oauth", "metadata url https://metadata.example/discovery",
		"authorization url https://endpoint.example/authorize", "token url https://endpoint.example/token",
		"logout url https://endpoint.example/logout", "identity token cookie name CUSTOM_IDENTITY_TOKEN",
		"identity token field name access_token", "user info roles field name memberships",
		"scopes openid email custom", "required token fields access_token", "response type code id_token",
		cfgutil.EncodeArgs([]string{"user", "group", "filters", "^engineering .*", "^admins$"}),
		"user org filters ^example$", "user info fields email roles",
		"delay start 2", "retry attempts 3", "retry interval 7",
		cfgutil.EncodeArgs([]string{"login", "icon", "class", "name", "lab la-test"}),
		"login icon color white", "login icon background color black",
		cfgutil.EncodeArgs([]string{"login", "icon", "text", "Sign in with upstream"}),
		"login icon text color blue", "login icon text background color gray", "login icon priority 9",
	}
	got, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("example", statements)
	if err != nil {
		t.Fatal(err)
	}
	want := &oauth.Config{
		Name: "example", Realm: "upstream", Driver: "generic", ClientID: "client", ClientSecret: "synthetic-secret",
		DomainName: "example.test", ServerID: "server", TenantID: "tenant", UserPoolID: "pool", Region: "region-1",
		Issuer: "https://issuer.example/", AccessTokenAudience: "resource-api", BaseAuthURL: "https://endpoint.example/oauth",
		MetadataURL: "https://metadata.example/discovery", AuthorizationURL: "https://endpoint.example/authorize",
		TokenURL: "https://endpoint.example/token", LogoutURL: "https://endpoint.example/logout",
		IdentityTokenCookieName: "CUSTOM_IDENTITY_TOKEN", IdentityTokenFieldName: "access_token", UserInfoRolesFieldName: "memberships",
		Scopes: []string{"openid", "email", "custom"}, RequiredTokenFields: []string{"access_token"}, ResponseType: []string{"code", "id_token"},
		UserGroupFilters: []string{"^engineering .*", "^admins$"}, UserOrgFilters: []string{"^example$"}, UserInfoFields: []string{"email", "roles"},
		DelayStart: 2, RetryAttempts: 3, RetryInterval: 7,
		LoginIcon: &icons.LoginIcon{ClassName: "lab la-test", Color: "white", BackgroundColor: "black", Text: "Sign in with upstream", TextColor: "blue", TextBackgroundColor: "gray", Priority: 9},
	}
	// Compare public directive configuration with independently constructed typed
	// configuration after the same domain normalization boundary.
	if err := want.Validate(); err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("directive and typed configurations differ (-want +got):\n%s", diff)
	}
}

func TestOAuthIdentityProviderDirectiveStates(t *testing.T) {
	for _, tc := range []struct {
		key, field string
		disabled   bool
	}{
		{"metadata discovery", "MetadataDiscoveryDisabled", true},
		{"key verification", "KeyVerificationDisabled", true},
		{"pass grant type", "PassGrantTypeDisabled", true},
		{"response type parameter", "ResponseTypeDisabled", true},
		{"scope", "ScopeDisabled", true},
		{"nonce", "NonceDisabled", true},
		{"pkce", "PKCEDisabled", true},
		{"accept header", "AcceptHeaderEnabled", false},
		{"js callback", "JsCallbackEnabled", false},
		{"logout", "LogoutEnabled", false},
		{"identity token cookie", "IdentityTokenCookieEnabled", false},
		{"email claim check", "EmailClaimCheckDisabled", true},
		{"tls verification", "TLSInsecureSkipVerify", true},
	} {
		for _, state := range []string{"enabled", "disabled"} {
			t.Run(tc.key+"/"+state, func(t *testing.T) {
				config, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", oauthDirectives(tc.key+" "+state))
				if err != nil {
					t.Fatal(err)
				}
				want := state == "enabled"
				if tc.disabled {
					want = state == "disabled"
				}
				if reflect.ValueOf(config).Elem().FieldByName(tc.field).Bool() != want {
					t.Fatal("directive state does not match the typed setting")
				}
				if config.IdentityTokenCookieEnabled && config.IdentityTokenCookieName != cookie.NewConfig().IdentityTokenCookieName {
					t.Fatal("identity token cookie did not use the repository default")
				}
				for _, second := range []string{"enabled", "disabled"} {
					got, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", oauthDirectives(tc.key+" "+state, tc.key+" "+second))
					if err == nil || got != nil || !strings.Contains(err.Error(), "duplicate") {
						t.Fatal("repeated or conflicting states must fail")
					}
				}
			})
		}
	}
}

func TestOAuthIdentityProviderDirectiveRejections(t *testing.T) {
	for _, tc := range []struct {
		name       string
		statements []string
	}{
		{"empty statement", []string{""}},
		{"unknown", []string{"unknown sensitive-value"}},
		{"block header", []string{"oauth identity provider upstream {"}},
		{"closing brace", []string{"}"}},
		{"missing issuer", []string{"issuer"}},
		{"issuer arity", []string{"issuer one two"}},
		{"audience arity", []string{"access_token_audience one two"}},
		{"empty issuer", []string{`issuer ""`}},
		{"blank audience", []string{`access_token_audience " "`}},
		{"unknown underscore flag", []string{"nonce_disabled true"}},
		{"boolean literal", []string{"nonce true"}},
		{"numeric literal", []string{"pkce 0"}},
		{"missing state", []string{"tls verification"}},
		{"grouped keywords", []string{`"access token audience" resource`}},
		{"partially grouped keywords", []string{`access "token audience" resource`}},
		{"mixed keyword spellings", []string{"access_token audience resource"}},
		{"unterminated quote", []string{`issuer "value`}},
		{"multiple records", []string{"issuer https://issuer.example\nissuer https://other.example"}},
		{"carriage return", []string{"issuer https://issuer.example\r"}},
		{"invalid UTF-8", []string{"issuer \xff"}},
		{"fractional integer", []string{"delay start 1.5"}},
		{"overflowing integer", []string{"retry attempts 99999999999999999999999999999"}},
		{"empty list", []string{"scopes"}},
		{"empty list item", []string{`user info fields email ""`}},
		{"duplicate scalar", []string{"issuer one", "issuer two"}},
		{"duplicate alias", []string{"access_token_audience one", "access token audience two"}},
		{"duplicate list alias", []string{"user_info_fields email", "user info fields roles"}},
		{"duplicate integer alias", []string{"retry_attempts 2", "retry attempts 3"}},
		{"missing key path", []string{"jwks key kid"}},
		{"unknown jwks kind", []string{"jwks private kid file"}},
		{"blank key ID", []string{`jwks key " " file`}},
		{"blank key path", []string{`jwks key kid " "`}},
		{"duplicate key ID", []string{"jwks key kid one", "jwks key kid two"}},
		{"missing icon setting", []string{"login icon"}},
		{"unknown icon setting", []string{"login icon secret value"}},
		{"extra icon values", []string{"login icon color one two"}},
		{"duplicate icon alias", []string{"login icon class_name first", "login icon class name second"}},
		{"derived server name", []string{"server_name untrusted"}},
		{"unused app secret", []string{"app_secret sensitive-value"}},
		{"unused roles", []string{"user_roles admin"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := oauthDirectives(tc.statements...)
			original := slices.Clone(input)
			got, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", input)
			if err == nil || got != nil {
				t.Fatal("invalid directives returned a usable configuration")
			}
			if strings.Contains(err.Error(), "sensitive-value") || !slices.Equal(input, original) {
				t.Fatal("failed parsing disclosed or mutated input")
			}
		})
	}
}

func TestOAuthIdentityProviderDirectiveValidation(t *testing.T) {
	for _, name := range []string{"", " ", " leading", "trailing ", "name\n", "name\x00", "name\xff"} {
		got, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives(name, oauthDirectives())
		if got != nil || err == nil || err.Error() != "invalid OAuth identity provider name" {
			t.Fatal("invalid provider name must fail without its value")
		}
	}
	for _, statements := range [][]string{
		nil,
		{"realm upstream", "driver generic"},
		oauthDirectives("identity token field name sensitive-invalid-field"),
		oauthDirectives("user group filters [sensitive-invalid-pattern"),
		oauthDirectives("user org filters [sensitive-invalid-pattern"),
	} {
		got, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", statements)
		if got != nil || err == nil || err.Error() != "invalid OAuth identity provider configuration" {
			t.Fatal("domain validation must fail without raw configuration values")
		}
	}
	config, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("google", []string{"realm google", "driver google", "client_id client", "client_secret synthetic"})
	if err != nil || config == nil || config.ClientID != "client.apps.googleusercontent.com" || config.MetadataURL != "https://accounts.google.com/.well-known/openid-configuration" {
		t.Fatal("driver-specific typed normalization was lost")
	}
	config, err = oauthparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", oauthDirectives("delay start 3"))
	if err != nil || config == nil || config.RetryAttempts != 2 || config.RetryInterval != 3 {
		t.Fatal("retry defaults were lost")
	}
}

func TestOAuthIdentityProviderDirectiveStaticKeys(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, kind string
		data       []byte
		valid      bool
	}{
		{"public key.pem", "PUBLIC KEY", publicDER, true},
		{"private key.pem", "PRIVATE KEY", privateDER, false},
		{"malformed.pem", "PUBLIC KEY", []byte("invalid"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), tc.name)
			if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: tc.kind, Bytes: tc.data}), 0600); err != nil {
				t.Fatal(err)
			}
			input := oauthDirectives("authorization url https://endpoint.example/authorize", "token url https://endpoint.example/token",
				cfgutil.EncodeArgs([]string{"jwks", "key", "first", path}), cfgutil.EncodeArgs([]string{"jwks", "key", "second", path}))
			config, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", input)
			if tc.valid {
				if err != nil || config == nil || config.JwksKeys["first"] != path || config.JwksKeys["second"] != path {
					t.Fatal("public key paths with spaces were not preserved")
				}
			} else if config != nil || err == nil || strings.Contains(err.Error(), path) {
				t.Fatal("invalid key configuration must fail without a path or key material")
			}
		})
	}
}

func TestOAuthIdentityProviderDirectiveIsolation(t *testing.T) {
	var requests atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	defer server.Close()
	input := []string{"realm upstream", "driver generic", "client_id client", "client_secret synthetic-secret", "metadata_url " + server.URL, "scopes openid custom"}
	original := slices.Clone(input)
	for range 2 {
		config, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", input)
		if err != nil || config == nil || !slices.Equal(config.Scopes, []string{"openid", "custom"}) || config.LoginIcon.Color != "white" {
			t.Fatal("configuration inherited mutation from an earlier result")
		}
		config.Scopes[0], config.LoginIcon.Color = "changed", "changed"
	}
	if !slices.Equal(input, original) || requests.Load() != 0 {
		t.Fatal("configuration parsing mutated inputs or fetched metadata")
	}
	for i := range 8 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			if config, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", input); err != nil || config == nil {
				t.Fatal("concurrent parsing failed")
			}
		})
	}
}

func TestOAuthIdentityProviderTrustSerialization(t *testing.T) {
	config, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("upstream", oauthDirectives("issuer https://Issuer.example/", `access_token_audience "resource with spaces"`))
	if err != nil {
		t.Fatal(err)
	}
	for _, codec := range []struct {
		name      string
		marshal   func(any) ([]byte, error)
		unmarshal func([]byte, any) error
	}{
		{"JSON", json.Marshal, json.Unmarshal}, {"XML", xml.Marshal, xml.Unmarshal}, {"YAML", yaml.Marshal, yaml.Unmarshal},
	} {
		t.Run(codec.name, func(t *testing.T) {
			data, err := codec.marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			var restored oauth.Config
			if err := codec.unmarshal(data, &restored); err != nil || restored.Issuer != config.Issuer || restored.AccessTokenAudience != config.AccessTokenAudience {
				t.Fatal("explicit trust settings did not survive serialization")
			}
		})
	}
}

func ExampleNewOAuthIdentityProviderConfigFromDirectives() {
	config, err := oauthparser.NewOAuthIdentityProviderConfigFromDirectives("corporate", []string{
		"realm employees", "driver generic", "client_id portal", "client_secret synthetic-example-secret",
		cfgutil.EncodeArgs([]string{"metadata_url", "https://idp.example/.well-known/openid-configuration"}),
		cfgutil.EncodeArgs([]string{"issuer", "https://idp.example"}),
		cfgutil.EncodeArgs([]string{"access_token_audience", "resource-api"}),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(config.Realm, config.Issuer, config.AccessTokenAudience)
	// Output: employees https://idp.example resource-api
}
