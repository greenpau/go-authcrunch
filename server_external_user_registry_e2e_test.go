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

package authcrunch_test

import (
	"encoding/json"
	"html"
	"io"
	"mime/quotedprintable"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	authcrunch "github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/credentials"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/messaging"
	"github.com/greenpau/go-authcrunch/pkg/registry"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	accounts "github.com/greenpau/go-authcrunch/plugins/identity-stores/sqlite"
	notifications "github.com/greenpau/go-authcrunch/plugins/messaging/sqlite"
	enrollment "github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite"
	enrollmentparser "github.com/greenpau/go-authcrunch/plugins/registration-workflows/sqlite/parser"
	"go.uber.org/zap"
)

type observedExternalRegistry struct {
	*enrollment.Workflow
	mutations int
}

func (w *observedExternalRegistry) Activate(*zap.Logger) error { w.mutations++; return nil }
func (w *observedExternalRegistry) SetRealmName(string)        { w.mutations++ }
func (w *observedExternalRegistry) SetCredentials(*credentials.Config) error {
	w.mutations++
	return nil
}
func (w *observedExternalRegistry) SetMessaging(*messaging.Config) error { w.mutations++; return nil }
func (w *observedExternalRegistry) Close() error                         { w.mutations++; return nil }

func TestE2EServerExternalSQLiteUserRegistry(t *testing.T) {
	for _, mount := range []string{"/tenant/auth", "/"} {
		t.Run(mount, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			accountConfig := &accounts.Config{Name: "accounts", Realm: "staff", Path: filepath.Join(dir, "accounts.db"), Timeout: "5s"}
			if err := accountConfig.Validate(); err != nil {
				t.Fatal(err)
			}
			identityDescriptor, err := ids.NewExternalIdentityStoreConfig("accounts", "sqlite", "staff", accountConfig)
			if err != nil {
				t.Fatal(err)
			}
			store, err := accounts.New(t.Context(), accountConfig)
			if err != nil {
				t.Fatal(err)
			}
			defer store.Close()
			out, err := notifications.New(t.Context(), &notifications.Config{Name: "mail", Path: filepath.Join(dir, "mail.db"), Timeout: "5s"})
			if err != nil {
				t.Fatal(err)
			}
			defer out.Close()
			var runtime *authcrunch.Server
			var mu sync.RWMutex
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.RLock()
				defer mu.RUnlock()
				name := "portal"
				if strings.HasPrefix(r.URL.Path, "/unselected/") {
					name = "unselected"
				}
				portal, err := runtime.GetPortalByName(name)
				if err != nil {
					http.Error(w, "unavailable", 503)
					return
				}
				if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
					t.Error("registry root request failed", err)
				}
			}))
			defer server.Close()
			prefix := strings.TrimSuffix(mount, "/")
			cfg, err := enrollmentparser.NewSQLiteRegistrationConfigFromDirectives([]string{"name signup", "path " + filepath.Join(dir, "pending.db"), "identity_store accounts", "realm staff", "email_provider mail", "public_origin " + server.URL, "base_path " + mount, "timeout 5s"})
			if err != nil {
				t.Fatal(err)
			}
			workflow, err := enrollment.New(t.Context(), cfg, store, out)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if runtime != nil {
					runtime.Close()
				}
				workflow.Close()
			}()
			observed := &observedExternalRegistry{Workflow: workflow}
			descriptor, err := registry.NewExternalUserRegistryConfig(cfg.Name, "sqlite", cfg.IdentityStore, cfg.Realm, cfg.EmailProvider, cfg)
			if err != nil {
				t.Fatal(err)
			}
			configuration := &authcrunch.Config{State: &state.Config{Directory: filepath.Join(dir, "state")}, ExternalIdentityStores: []*ids.ExternalIdentityStoreConfig{identityDescriptor}, ExternalUserRegistries: []*registry.ExternalUserRegistryConfig{descriptor}, AuthenticationPortals: []*authn.PortalConfig{
				{Name: "portal", UserRegistries: []string{"signup"}, RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + externalIdentityKey}, RefreshTokens: &authn.TokenRefreshConfig{Enabled: true, Realms: []string{"staff"}, PublicOrigin: server.URL, BasePath: mount, BodyTransportEnabled: true}},
				{Name: "unselected", RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + externalIdentityKey}},
			}}
			restored := func() *authcrunch.Config {
				t.Helper()
				raw, err := json.Marshal(configuration)
				if err != nil {
					t.Fatal(err)
				}
				var c authcrunch.Config
				if err := json.Unmarshal(raw, &c); err != nil {
					t.Fatal(err)
				}
				return &c
			}
			if err := restored().Validate(); err != nil {
				t.Fatal("pure descriptor validation", err)
			}
			options := func() authcrunch.ServerOptions {
				return authcrunch.ServerOptions{IdentityStores: map[string]ids.IdentityStore{"accounts": store}, UserRegistries: map[string]registry.Provider{"signup": observed}}
			}
			newRoot := func() *authcrunch.Server {
				t.Helper()
				c := restored()
				c.Messaging = &messaging.Config{}
				if err := c.Messaging.AddProvider("mail", out); err != nil {
					t.Fatal(err)
				}
				root, err := authcrunch.NewServerWithOptions(c, zap.NewNop(), options())
				if err != nil {
					t.Fatal(err)
				}
				return root
			}
			runtime = newRoot()
			client := server.Client()
			client.Timeout = 10 * time.Second
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			request := func(method, target string, form url.Values, host string) (int, string, string) {
				t.Helper()
				if strings.HasPrefix(target, "/") {
					target = server.URL + target
				}
				var body io.Reader
				if form != nil {
					body = strings.NewReader(form.Encode())
				}
				req, err := http.NewRequestWithContext(t.Context(), method, target, body)
				if err != nil {
					t.Fatal(err)
				}
				if form != nil {
					req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				}
				req.Host = host
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				defer resp.Body.Close()
				data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
				if err != nil {
					t.Fatal(err)
				}
				return resp.StatusCode, resp.Header.Get("Location"), string(data)
			}
			status, _, page := request("GET", prefix+"/login", nil, "")
			signupLink := ""
			for _, match := range regexp.MustCompile(`href="([^"]+)"`).FindAllStringSubmatch(page, -1) {
				link := html.UnescapeString(match[1])
				if strings.Contains(link, prefix+"/register/staff") {
					signupLink = link
					break
				}
			}
			if status != 200 || signupLink == "" || strings.Contains(page, `<div id="user_register_link" class="hidden">`) {
				t.Fatal("selected registration absent from actual login", status)
			}
			if status, _, page := request("GET", "/unselected/login", nil, ""); status != 200 || !strings.Contains(page, `<div id="user_register_link" class="hidden">`) {
				t.Fatal("unselected portal gained signup", status)
			}
			if status, _, _ := request("GET", "/unselected/register/staff", nil, ""); status != http.StatusServiceUnavailable {
				t.Fatal("unselected portal accepted registration", status)
			}
			if status, _, _ := request("GET", signupLink, nil, ""); status != 200 {
				t.Fatal("rendered signup link unusable", status)
			}
			if status, _, _ := request("POST", prefix+"/register/staff", url.Values{"registrant": {"alice"}, "registrant_password": {externalIdentityPassword}, "registrant_email": {"alice@example.test"}}, "attacker.example.test"); status != 200 {
				t.Fatal("signup failed", status)
			}
			if _, err := store.FetchUserData("alice", "alice@example.test"); err == nil {
				t.Fatal("unconfirmed account exists")
			}
			message, err := out.Claim(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(message.Body)))
			if err != nil {
				t.Fatal(err)
			}
			if len(message.Recipients) != 1 || message.Recipients[0] != "alice@example.test" || strings.Contains(string(decoded), "attacker.example.test") || strings.Contains(string(decoded), externalIdentityPassword) {
				t.Fatal("unsafe confirmation notification")
			}
			links := regexp.MustCompile(`href="([^"]+)"`).FindStringSubmatch(string(decoded))
			codes := regexp.MustCompile(`<code>([A-Za-z0-9]{6,8})</code>`).FindStringSubmatch(string(decoded))
			if len(links) != 2 || len(codes) != 2 || !strings.HasPrefix(links[1], server.URL+prefix+"/register/staff/ack/") {
				t.Fatal("invalid canonical confirmation")
			}
			link, code := html.UnescapeString(links[1]), codes[1]
			if err := out.Acknowledge(t.Context(), message.ID, message.Lease); err != nil {
				t.Fatal(err)
			}
			// Failed construction leaves the currently serving workflow usable.
			candidate := restored()
			candidate.State = nil
			candidate.Messaging = &messaging.Config{}
			candidate.Messaging.AddProvider("mail", out)
			candidate.AuthenticationPortals[0].RawCryptoKeyStoreConfig = []string{"malformed key"}
			if failed, err := authcrunch.NewServerWithOptions(candidate, zap.NewNop(), options()); failed != nil || err == nil {
				if failed != nil {
					failed.Close()
				}
				t.Fatal("invalid replacement accepted")
			}
			if observed.mutations != 0 || workflow.Validate() != nil {
				t.Fatal("failed root mutated borrowed workflow")
			}
			mu.Lock()
			runtime.Close()
			if observed.mutations != 0 || workflow.Validate() != nil {
				mu.Unlock()
				t.Fatal("root close mutated borrowed workflow")
			}
			workflow.Close()
			workflow, err = enrollment.New(t.Context(), cfg, store, out)
			if err != nil {
				mu.Unlock()
				t.Fatal(err)
			}
			observed = &observedExternalRegistry{Workflow: workflow}
			runtime = newRoot()
			mu.Unlock()
			for _, bad := range []struct {
				target string
				values url.Values
			}{{link, url.Values{"registration_code": {"wrong"}}}, {link, url.Values{"registration_code": {code, code}}}, {link + "?registration_code=" + code, url.Values{"unused": {"value"}}}} {
				status, location, body := request("POST", bad.target, bad.values, "")
				if status != 200 || location != "" || !strings.Contains(body, "Registration confirmation denied") {
					t.Fatal("invalid confirmation admitted", status)
				}
			}
			if status, location, _ := request("POST", link, url.Values{"registration_code": {code}}, ""); status != 303 || !strings.Contains(location, prefix+"/login") {
				t.Fatal("confirmation did not lead to mounted login", status)
			}
			if status, location, body := request("POST", link, url.Values{"registration_code": {code}}, ""); status != 200 || location != "" || !strings.Contains(body, "Registration confirmation denied") {
				t.Fatal("confirmation replay accepted", status)
			}
			native, err := authclient.NewClient(&authclient.Config{BaseURL: server.URL + prefix, Realm: "staff", Username: "alice", Password: externalIdentityPassword, RefreshTransport: authclient.RefreshTransportBody}, authclient.Options{HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			result, err := native.Authenticate(t.Context())
			if err != nil {
				t.Fatal("confirmed account login", err)
			}
			token, err := jwt.Parse(result.AccessToken, func(*jwt.Token) (any, error) { return []byte(externalIdentityKey), nil }, jwt.WithValidMethods([]string{"HS512"}))
			if err != nil || !token.Valid {
				t.Fatal("invalid root JWT", err)
			}
			claims := token.Claims.(jwt.MapClaims)
			roles := claims["roles"].([]any)
			if claims["sub"] != "alice" || claims["origin"] != "staff" || len(roles) != 1 || roles[0] != "authp/user" {
				t.Fatal("unexpected enrollment identity")
			}
			// Changing normalized workflow configuration retires persisted refresh state.
			mu.Lock()
			runtime.Close()
			workflow.Close()
			cfg.Timeout = "4s"
			workflow, err = enrollment.New(t.Context(), cfg, store, out)
			if err != nil {
				mu.Unlock()
				t.Fatal(err)
			}
			observed = &observedExternalRegistry{Workflow: workflow}
			configuration.ExternalUserRegistries[0], err = registry.NewExternalUserRegistryConfig(cfg.Name, "sqlite", cfg.IdentityStore, cfg.Realm, cfg.EmailProvider, cfg)
			if err != nil {
				mu.Unlock()
				t.Fatal(err)
			}
			runtime = newRoot()
			mu.Unlock()
			data, _ := json.Marshal(map[string]string{"refresh_token": result.RefreshToken})
			req, err := http.NewRequestWithContext(t.Context(), "POST", server.URL+prefix+"/api/refresh_token", strings.NewReader(string(data)))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("Content-Type", "application/json")
			resp, err := client.Do(req)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != 401 {
				t.Fatal("changed registry digest retained session", resp.StatusCode)
			}
			if observed.mutations != 0 || workflow.Validate() != nil || !store.Configured() || out.CheckReady(t.Context()) != nil {
				t.Fatal("borrowed resources were mutated or closed")
			}
		})
	}
}
