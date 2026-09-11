// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package authclient_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

const e2eTOTPSecret = "0123456789abcdef0123456789abcdef"
const e2eAPIKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"

// These tests use only the public client API and a real portal over TLS. Login
// responses, identity checks, sandbox transitions, signing, and token validation
// all run through production handlers; neither admin nor profile API is enabled.
func TestE2EAuthenticate(t *testing.T) {
	for _, tc := range []struct {
		name           string
		basePath       string
		factor         string
		promptPassword bool
		secret         string
		tokenName      string
		username       string
		prompts        []authclient.PromptKind
	}{
		{name: "password at root"},
		{name: "email and password", basePath: "/auth", username: tests.TestEmail1},
		{name: "mixed case username and password", basePath: "/auth", username: strings.ToUpper(tests.TestUser1)},
		{name: "email and password and TOTP", basePath: "/auth", username: tests.TestEmail1, factor: "totp", secret: e2eTOTPSecret},
		{name: "prompted password at subpath", basePath: "/auth", promptPassword: true, prompts: []authclient.PromptKind{authclient.PromptPassword}},
		{name: "configured TOTP and custom token name", basePath: "/auth", factor: "totp", secret: e2eTOTPSecret, tokenName: "CUSTOM_ACCESS_TOKEN"},
		{name: "prompted TOTP", basePath: "/auth", factor: "totp", prompts: []authclient.PromptKind{authclient.PromptTOTP}},
		{name: "MFA selection and prompted TOTP", basePath: "/auth", factor: "mfa", prompts: []authclient.PromptKind{authclient.PromptMFA, authclient.PromptTOTP}},
		{name: "noninteractive MFA", basePath: "/auth", factor: "mfa", secret: e2eTOTPSecret},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newE2EPortal(t, e2ePortalOptions{basePath: tc.basePath, factor: tc.factor, tokenName: tc.tokenName})
			cfg := f.config()
			if tc.username != "" {
				cfg.Username = tc.username
			}
			cfg.TOTPSecret = tc.secret
			if tc.promptPassword {
				cfg.Password = ""
			}
			opts := authclient.Options{HTTPClient: f.server.Client()}
			var prompts []authclient.PromptKind
			if len(tc.prompts) > 0 {
				opts.Prompt = func(ctx context.Context, kind authclient.PromptKind) (string, error) {
					if err := ctx.Err(); err != nil {
						return "", err
					}
					prompts = append(prompts, kind)
					switch kind {
					case authclient.PromptPassword:
						return tests.TestPwd1, nil
					case authclient.PromptMFA:
						return "totp", nil
					case authclient.PromptTOTP:
						return e2eTOTP(), nil
					default:
						return "", fmt.Errorf("unexpected prompt kind %q", kind)
					}
				}
			}
			client, err := authclient.NewClient(&cfg, opts)
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := client.Authenticate(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(prompts, tc.prompts) {
				t.Fatalf("prompt order: got %v, want %v", prompts, tc.prompts)
			}
			loginRequests := 2 // Identify the user, then answer the password challenge.
			if tc.factor != "" {
				loginRequests++
			}
			f.assertLoginRequests(t, loginRequests)
			wantTokenName := authclient.DefaultAccessTokenName
			if tc.tokenName != "" {
				wantTokenName = strings.ToLower(tc.tokenName)
			}
			if credentials.AccessTokenName != wantTokenName {
				t.Fatalf("returned token name: got %q, want %q", credentials.AccessTokenName, wantTokenName)
			}

			f.assertPersistedCredentialAccess(t, credentials)
		})
	}
}

func TestE2EAuthenticateRejectsInvalidCredentials(t *testing.T) {
	for _, tc := range []struct {
		name     string
		factor   string
		password string
		prompt   authclient.PromptFunc
		wantErr  error
		requests int
	}{
		{name: "wrong password", password: "incorrect-test-password", requests: 2},
		{name: "wrong TOTP", factor: "totp", password: tests.TestPwd1, requests: 3,
			prompt: func(context.Context, authclient.PromptKind) (string, error) {
				// An incorrect length cannot accidentally be a valid current code.
				return "000", nil
			}},
		{name: "missing second factor", factor: "totp", password: tests.TestPwd1, wantErr: authclient.ErrInputRequired, requests: 2},
		{name: "canceled password input", wantErr: context.Canceled, requests: 1,
			prompt: func(context.Context, authclient.PromptKind) (string, error) { return "", context.Canceled }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newE2EPortal(t, e2ePortalOptions{basePath: "/auth", factor: tc.factor})
			cfg := f.config()
			cfg.Password = tc.password
			client, err := authclient.NewClient(&cfg, authclient.Options{HTTPClient: f.server.Client(), Prompt: tc.prompt})
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := client.Authenticate(t.Context())
			if credentials != nil || err == nil {
				t.Fatal("unsuccessful authentication returned credentials or no error")
			}
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("got %v, want %v", err, tc.wantErr)
				}
			} else {
				var httpErr *authclient.HTTPError
				if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
					t.Fatalf("expected portal rejection with HTTP 401, got %v", err)
				}
			}
			f.assertLoginRequests(t, tc.requests)
		})
	}
}

func TestE2EAPIKeyAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name   string
		portal e2ePortalOptions
		key    string
		realm  string
		denied bool
	}{
		{name: "API key at root", portal: e2ePortalOptions{keyState: "active"}},
		{name: "API key and custom token name", portal: e2ePortalOptions{basePath: "/auth", keyState: "active", tokenName: "KEY_ACCESS_TOKEN"}},
		{name: "API key for account enrolled in MFA", portal: e2ePortalOptions{basePath: "/auth", keyState: "active", factor: "totp"}},
		{name: "API key in refresh realm remains access only", portal: e2ePortalOptions{basePath: "/auth", keyState: "active", refresh: true}},
		{name: "wrong secret with known prefix", portal: e2ePortalOptions{keyState: "active"}, key: e2eAPIKey[:63] + "C", denied: true},
		{name: "unknown key", portal: e2ePortalOptions{keyState: "active"}, key: strings.Repeat("Z", 64), denied: true},
		{name: "malformed key", portal: e2ePortalOptions{keyState: "active"}, key: "short-key", denied: true},
		{name: "disabled key", portal: e2ePortalOptions{keyState: "disabled"}, denied: true},
		{name: "revoked key", portal: e2ePortalOptions{keyState: "revoked"}, denied: true},
		{name: "disabled account", portal: e2ePortalOptions{keyState: "active", disabledUser: true}, denied: true},
		{name: "unknown realm", portal: e2ePortalOptions{keyState: "active"}, realm: "unknown", denied: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newE2EPortal(t, tc.portal)
			cfg := authclient.Config{BaseURL: f.server.URL + tc.portal.basePath, Realm: "local", APIKey: e2eAPIKey}
			if tc.key != "" {
				cfg.APIKey = tc.key
			}
			if tc.realm != "" {
				cfg.Realm = tc.realm
			}
			client, err := authclient.NewClient(&cfg, authclient.Options{HTTPClient: f.server.Client(), Prompt: func(context.Context, authclient.PromptKind) (string, error) {
				t.Error("API key authentication requested interactive input")
				return "", authclient.ErrInputRequired
			}})
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := client.Authenticate(t.Context())
			f.assertLoginRequests(t, 1)
			if tc.denied {
				var httpErr *authclient.HTTPError
				if credentials != nil || !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusUnauthorized {
					t.Fatalf("expected API key rejection with no credentials and HTTP 401, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if credentials.RefreshToken != "" || credentials.SessionID != "" {
				t.Fatal("API key login created a renewable session")
			}
			f.assertPersistedCredentialAccess(t, credentials)
		})
	}
}

type e2ePortalOptions struct {
	basePath, factor, tokenName, keyState string
	disabledUser, refresh                 bool
}

type e2ePortal struct {
	server   *httptest.Server
	basePath string
	mu       sync.Mutex
	routes   []string
}

func newE2EPortal(t *testing.T, opts e2ePortalOptions) *e2ePortal {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "users.json")
	db, err := identity.NewDatabase(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	req := &requests.Request{User: requests.User{
		Username: tests.TestUser1, Email: tests.TestEmail1, Password: tests.TestPwd1,
		Roles: []string{"authp/user"},
	}}
	if err := db.AddUser(req); err != nil {
		t.Fatal(err)
	}
	if opts.factor != "" {
		req.MfaToken = requests.MfaToken{Type: "totp", Comment: "E2E factor", Secret: e2eTOTPSecret, Algorithm: "sha1", Digits: 6, Period: 30, SkipVerification: true}
		if err := db.AddMfaToken(req); err != nil {
			t.Fatal(err)
		}
	}
	if opts.factor == "mfa" {
		// Exercise the portal's combined MFA challenge using its challenge rules.
		req.User.Challenges = []string{"password mfa"}
		if err := db.OverwriteUserAuthChallengeRules(req); err != nil {
			t.Fatal(err)
		}
	}
	if opts.keyState != "" {
		req.Key.Payload = e2eAPIKey
		req.Key.Usage = "api"
		req.Key.Comment = "E2E API key"
		req.Key.Disabled = opts.keyState == "disabled"
		if err := db.AddAPIKey(req); err != nil {
			t.Fatal(err)
		}
		if opts.keyState == "revoked" {
			if err := db.GetAPIKeys(req); err != nil {
				t.Fatal(err)
			}
			key := req.Response.Payload.(*identity.APIKeyBundle).Get()[0]
			req.Key.ID, req.Key.Prefix = key.ID, key.Prefix
			if err := db.DeleteAPIKey(req); err != nil {
				t.Fatal(err)
			}
		}
	}
	if opts.disabledUser {
		if err := db.DisableUser(req); err != nil {
			t.Fatal(err)
		}
	}
	store, err := ids.NewIdentityStore(&ids.IdentityStoreConfig{
		Name: "localdb", Kind: "local", Params: map[string]any{"path": dbPath, "realm": "local"},
	}, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Configure(); err != nil {
		t.Fatal(err)
	}
	cookies := cookie.NewConfig()
	if opts.tokenName != "" {
		cookies.AccessTokenCookieName = opts.tokenName
	}
	f := &e2ePortal{basePath: opts.basePath, server: httptest.NewUnstartedServer(nil)}
	cfg := &authn.PortalConfig{
		Name: "authclient-e2e", IdentityStores: []string{"localdb"}, CookieConfig: cookies,
		API: &authn.APIConfig{AdminEnabled: false, ProfileEnabled: false},
	}
	if opts.refresh {
		cfg.RefreshTokens = &authn.RefreshConfig{Enabled: true, Realms: []string{"local"}, PublicOrigin: "https://" + f.server.Listener.Addr().String(), BasePath: opts.basePath, BodyTransportEnabled: true}
	}
	portal, err := authn.NewPortal(authn.PortalParameters{
		Config: cfg,
		Logger: zap.NewNop(), IdentityStores: []ids.IdentityStore{store},
	})
	if err != nil {
		f.server.Close()
		t.Fatal(err)
	}
	f.server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.routes = append(f.routes, r.Method+" "+r.URL.Path)
		f.mu.Unlock()
		if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
			t.Errorf("portal handler failed: %v", err)
		}
	})
	f.server.StartTLS()
	f.server.Client().Timeout = 10 * time.Second
	t.Cleanup(func() { f.server.Close(); portal.Close() })
	return f
}

func (f *e2ePortal) config() authclient.Config {
	return authclient.Config{
		BaseURL: f.server.URL + f.basePath, Username: tests.TestUser1, Realm: "local", Password: tests.TestPwd1,
	}
}

func (f *e2ePortal) assertLoginRequests(t *testing.T, count int) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.routes) != count {
		t.Fatalf("login requests: got %d, want %d", len(f.routes), count)
	}
	for _, route := range f.routes {
		if route != http.MethodPost+" "+f.basePath+"/login" {
			t.Fatalf("authentication used an unexpected endpoint: %s", route)
		}
	}
}

func (f *e2ePortal) assertPersistedCredentialAccess(t *testing.T, credentials *authclient.Credentials) {
	t.Helper()
	// Reopen an application's credential file and use it without login cookies.
	path := filepath.Join(t.TempDir(), ".config", "caddy-authenticator", "token.jwt")
	store, err := authclient.NewFileTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(credentials); err != nil {
		t.Fatal(err)
	}
	reopened, err := authclient.NewFileTokenStore(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := reopened.Load()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(loaded, credentials) {
		t.Fatal("credential file did not preserve the login result")
	}
	f.assertCredentialAccess(t, loaded)
}

func (f *e2ePortal) assertCredentialAccess(t *testing.T, credentials *authclient.Credentials) {
	t.Helper()
	header, err := credentials.Authorization()
	if err != nil {
		t.Fatal(err)
	}
	// A fresh client has the test TLS trust but no login cookies. Disable
	// redirects so a login page cannot disguise failed authorization as success.
	consumer := *f.server.Client()
	consumer.Jar = nil
	consumer.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	probe := func(path, authorization string, wantStatus int) map[string]any {
		t.Helper()
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, f.server.URL+f.basePath+path, nil)
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Accept", "application/json")
		if authorization != "" {
			r.Header.Set("Authorization", authorization)
		}
		resp, err := consumer.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != wantStatus {
			t.Fatalf("%s returned HTTP %d, want %d", path, resp.StatusCode, wantStatus)
		}
		var claims map[string]any
		if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&claims); err != nil {
			t.Fatalf("%s returned invalid JSON: %v", path, err)
		}
		return claims
	}
	probe("/whoami?probe=true", "", http.StatusUnauthorized)
	claims := probe("/whoami?probe=true", header, http.StatusOK)
	if claims["authenticated"] != true || claims["sub"] != tests.TestUser1 || claims["email"] != tests.TestEmail1 {
		t.Fatal("issued credential did not authenticate the expected identity")
	}
	if !reflect.DeepEqual(claims["roles"], []any{"authp/user"}) {
		t.Fatal("issued credential has unexpected roles")
	}
	if expiresIn, ok := claims["expires_in"].(float64); !ok || expiresIn <= 0 {
		t.Fatal("issued credential has no remaining lifetime")
	}
	// A bad signature must fail through the real validator, even after a valid
	// request. Change the first signature character to avoid base64 padding bits.
	parts := strings.Split(credentials.AccessToken, ".")
	if len(parts) != 3 || parts[2] == "" {
		t.Fatal("portal did not issue a signed JWT")
	}
	replacement := "A"
	if parts[2][0] == 'A' {
		replacement = "B"
	}
	parts[2] = replacement + parts[2][1:]
	tampered := *credentials
	tampered.AccessToken = strings.Join(parts, ".")
	tamperedHeader, err := tampered.Authorization()
	if err != nil {
		t.Fatal(err)
	}
	probe("/whoami?probe=true", tamperedHeader, http.StatusUnauthorized)
	// This explicit test probe confirms the fixture has no management API.
	// Authenticate's own requests were checked separately before these probes.
	probe("/api/server/metadata", header, http.StatusBadRequest)
}

// Compute the prompt answer independently of authclient's private generator,
// as an authenticator app would, using the raw secret convention of the portal.
func e2eTOTP() string {
	mac := hmac.New(sha1.New, []byte(e2eTOTPSecret))
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
	mac.Write(counter[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 15
	value := binary.BigEndian.Uint32(digest[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000)
}
