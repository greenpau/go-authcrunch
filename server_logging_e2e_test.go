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
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/logging"
	loggingparser "github.com/greenpau/go-authcrunch/pkg/logging/parser"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestE2EServerLogging(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		rules                  [][]string
		omit                   bool
		hostErrors, gateErrors int
	}{
		{name: "omitted", omit: true, hostErrors: 2, gateErrors: 2},
		{name: "empty", hostErrors: 2, gateErrors: 2},
		{name: "partial error", rules: [][]string{{"skip", "partial", "text", "reason: no token found"}}, hostErrors: 1, gateErrors: 2},
		{name: "exact message", rules: [][]string{{"skip", "exact", "text", "auth provider returned error"}}, gateErrors: 2},
		{name: "prefix error", rules: [][]string{{"skip", "prefix", "text", "user authorization failed:"}}, gateErrors: 2},
		{name: "suffix error", rules: [][]string{{"skip", "suffix", "text", "reason: no token found"}}, hostErrors: 1, gateErrors: 2},
		{name: "regex error", rules: [][]string{{"skip", "regex", "text", `reason: (no token found|keystore: failed to parse token)$`}}, gateErrors: 2},
		{name: "combined", rules: [][]string{
			{"skip", "partial", "text", "auth provider returned error"},
			{"skip", "partial", "text", "reason: no token found"},
			{"skip", "exact", "text", "token validation error"},
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dbPath := filepath.Join(dir, "users.json")
			db, err := identity.NewDatabase(dbPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := db.AddUser(&requests.Request{User: requests.User{Username: "alice", Email: "alice@example.test", Password: tests.TestPwd1Hash(t), Roles: []string{"authp/user"}}}); err != nil {
				t.Fatal("provision logging identity")
			}
			key := []string{"crypto key logging sign-verify from file testdata/rskeys/test_2_pri.pem"}
			cfg := &authcrunch.Config{
				IdentityStores:        []*ids.IdentityStoreConfig{{Name: "local", Kind: "local", Params: map[string]any{"realm": "local", "path": dbPath}}},
				AuthenticationPortals: []*authn.PortalConfig{{Name: "portal", IdentityStores: []string{"local"}, RawCryptoKeyStoreConfig: key}},
				AuthorizationPolicies: []*authz.PolicyConfig{{Name: "policy", RawCryptoKeyStoreConfig: key, AuthRedirectDisabled: true, ValidateBearerHeader: true, AccessListRules: []*acl.RuleConfiguration{{Conditions: []string{"match roles authp/user"}, Action: "allow stop"}}}},
			}
			if !tc.omit {
				var statements []string
				for _, args := range tc.rules {
					statements = append(statements, cfgutil.EncodeArgs(args))
				}
				cfg.Logging, err = loggingparser.NewLoggingConfigFromDirectives(statements)
				if err != nil {
					t.Fatal(err)
				}
			}
			configPath := filepath.Join(dir, "security.json")
			if err := cfg.DumpToJSONFile(configPath); err != nil {
				t.Fatal(err)
			}
			var restored authcrunch.Config
			if err := restored.LoadFromJSONFile(configPath); err != nil {
				t.Fatal(err)
			}
			logPath := filepath.Join(dir, "security.log")
			output, err := os.Create(logPath)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = output.Close() })
			base := zap.New(zapcore.NewCore(zapcore.NewJSONEncoder(zap.NewProductionEncoderConfig()), zapcore.Lock(output), zap.DebugLevel))
			runtime, err := authcrunch.NewServer(&restored, base.Named("authcrunch"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := runtime.Close(); err != nil {
					t.Error(err)
				}
			})
			filter, err := logging.NewFilter(restored.Logging)
			if err != nil {
				t.Fatal(err)
			}
			hostLogger, err := filter.WrapLogger(base.Named("host.authentication"))
			if err != nil {
				t.Fatal(err)
			}
			portal, err := runtime.GetPortalByName("portal")
			if err != nil {
				t.Fatal(err)
			}
			gate, err := runtime.GetGatekeeperByName("policy")
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/protected" {
					if err := portal.ServeHTTP(r.Context(), w, r, requests.NewRequest()); err != nil {
						t.Error("logging portal request failed")
					}
					return
				}
				ar := requests.NewAuthorizationRequest()
				if err := gate.Authenticate(w, r, ar); err != nil {
					// Model the embedding middleware's separate logger with the
					// real gatekeeper error. Filtering must never permit access.
					hostLogger.Error("auth provider returned error", zap.String("provider", "authorizer"), zap.Error(fmt.Errorf("user authorization failed: reason: %w", err)))
					http.Error(w, "unauthorized", http.StatusUnauthorized)
					return
				}
				if ar.Response.Authorized {
					w.WriteHeader(http.StatusNoContent)
				}
			}))
			t.Cleanup(server.Close)
			client := server.Client()
			client.Timeout = 10 * time.Second
			authorize := func(token string, want int) {
				t.Helper()
				req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/protected", nil)
				if err != nil {
					t.Fatal(err)
				}
				if token != "" {
					req.Header.Set("Authorization", "Bearer "+token)
				}
				response, err := client.Do(req)
				if err != nil {
					t.Fatal("protected logging request failed")
				}
				defer response.Body.Close()
				_, _ = io.Copy(io.Discard, response.Body)
				if response.StatusCode != want {
					t.Fatalf("HTTP %d, want %d", response.StatusCode, want)
				}
			}
			authorize("", http.StatusUnauthorized)
			authorize("invalid-token", http.StatusUnauthorized)
			login, err := authclient.NewClient(&authclient.Config{BaseURL: server.URL + "/auth", Realm: "local", Username: "alice", Password: tests.TestPwd1}, authclient.Options{HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := login.Authenticate(t.Context())
			if err != nil {
				t.Fatal("logging test login failed")
			}
			authorize(credentials.AccessToken, http.StatusNoContent)
			hostLogger.Error("unrelated failure", zap.String("component", "storage"))
			// An independent owner of the supplied logger must remain unfiltered.
			base.Named("unrelated").Error("auth provider returned error")
			server.Close()
			if err := runtime.Close(); err != nil {
				t.Fatal(err)
			}
			if err := base.Sync(); err != nil {
				t.Fatal(err)
			}
			logFile, err := os.Open(logPath)
			if err != nil {
				t.Fatal(err)
			}
			defer logFile.Close()
			decoder := json.NewDecoder(logFile)
			var hostErrors, gateErrors, unrelated, loginEvents int
			for {
				var entry map[string]any
				if err := decoder.Decode(&entry); err == io.EOF {
					break
				} else if err != nil {
					t.Fatal("invalid JSON log output")
				}
				message, _ := entry["msg"].(string)
				switch {
				case entry["logger"] == "host.authentication" && message == "auth provider returned error":
					hostErrors++
				case entry["logger"] == "authcrunch" && message == "token validation error":
					gateErrors++
				case message == "unrelated failure" || entry["logger"] == "unrelated":
					unrelated++
				case entry["logger"] == "authcrunch" && strings.Contains(message, "authenticated"):
					loginEvents++
				}
			}
			if hostErrors != tc.hostErrors || gateErrors != tc.gateErrors || unrelated != 2 || loginEvents == 0 {
				t.Fatalf("log counts host=%d/%d gate=%d/%d unrelated=%d login=%d", hostErrors, tc.hostErrors, gateErrors, tc.gateErrors, unrelated, loginEvents)
			}
		})
	}
}

func TestE2EServerLoggingPersistentSessions(t *testing.T) {
	f := newDirectOAuthFixtureWithRoot(t, nil, func(c *authcrunch.Config) { c.State = persistentTestConfig(t) })
	callback := f.callback(t, f.client, "/private")
	directOAuthStatus(t, f.request(t, f.client, "GET", callback, nil), http.StatusSeeOther)
	directOAuthStatus(t, f.request(t, f.client, "POST", "/private", nil), http.StatusOK)
	exchanges := f.exchanges.Load()
	for _, statements := range [][]string{
		{`skip partial text "reason: no token found"`},
		{`skip regex text "auth.*error"`},
		{},
		nil,
	} {
		var config authcrunch.Config
		if err := json.Unmarshal(f.config, &config); err != nil {
			t.Fatal(err)
		}
		var err error
		config.Logging, err = loggingparser.NewLoggingConfigFromDirectives(statements)
		if err != nil {
			t.Fatal(err)
		}
		if statements == nil {
			config.Logging = nil
		}
		f.config, err = json.Marshal(&config)
		if err != nil {
			t.Fatal(err)
		}
		restartDirectOAuth(t, f)
		directOAuthStatus(t, f.request(t, f.client, "POST", "/private", nil), http.StatusOK)
		if f.exchanges.Load() != exchanges {
			t.Fatal("logging-only change required upstream authentication")
		}
	}
}
