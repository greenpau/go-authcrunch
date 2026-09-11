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

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

func writeCLIConfig(t *testing.T, baseURL, tokenPath string) string {
	t.Helper()
	cfg := Config{
		Config:    authclient.Config{BaseURL: baseURL, Username: "test-user", Realm: "local", Password: "test-password"},
		TokenPath: tokenPath,
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func runCLIAction(ctx context.Context, configPath, tokenPath string, action cli.ActionFunc, extra ...string) error {
	app := cli.NewApp()
	app.Flags = sh.Flags
	app.Action = action
	args := []string{"authdbctl", "--config", configPath, "--token-path", tokenPath, "--access-token-name", "fallback", "--retry-interval", "0s", "--retries", "3"}
	return app.RunContext(ctx, append(args, extra...))
}

func TestConnectWithoutAdminAPI(t *testing.T) {
	var logins atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/auth/login" {
			t.Error("connect accessed an endpoint other than login")
			w.WriteHeader(404)
			return
		}
		logins.Add(1)
		request, err := apiauth.ParseAuthRequest(r.Context(), w, r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if request.Username != "test-user" || request.Realm != "local" {
			t.Error("CLI config identity not supplied")
		}
		if !request.HasChallengeResponse() {
			_, _ = w.Write([]byte(`{"sandbox_id":"id","sandbox_secret":"secret","next_challenge":"password"}`))
			return
		}
		if request.ChallengeKind != "password" || request.ChallengeResponse != "test-password" {
			t.Error("CLI config password not supplied")
		}
		_, _ = w.Write([]byte(`{"authenticated":true,"access_token":"new-access","access_token_name":"CUSTOM"}`))
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "authdbctl", "token.jwt")
	configPath := writeCLIConfig(t, server.URL+"/auth", "")
	if err := runCLIAction(context.Background(), configPath, tokenPath, connect); err != nil {
		t.Fatal(err)
	}
	store, err := authclient.NewFileTokenStore(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if got.AccessToken != "new-access" || got.AccessTokenName != "custom" || logins.Load() != 2 {
		t.Fatal("connect did not persist authentication credentials")
	}
}

func TestConnectWithAPIKey(t *testing.T) {
	// A regression that prompts for a username must fail promptly, including
	// when this suite is run from an interactive terminal.
	stdin, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	previousStdin := os.Stdin
	os.Stdin = stdin
	t.Cleanup(func() { os.Stdin = previousStdin; stdin.Close() })
	key := strings.Repeat("a", 64)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost || r.URL.Path != "/auth/login" {
			t.Error("unexpected API key endpoint")
			w.WriteHeader(404)
			return
		}
		request, err := apiauth.ParseAuthRequest(r.Context(), w, r)
		if err != nil {
			t.Error(err)
			w.WriteHeader(400)
			return
		}
		if request.APIKey != key || request.Username != "" || request.Realm != "local" || request.HasChallengeResponse() {
			t.Error("API key configuration was not forwarded correctly")
		}
		_, _ = w.Write([]byte(`{"authenticated":true,"access_token":"key-access","access_token_name":"CUSTOM"}`))
	}))
	defer server.Close()
	cfg := Config{Config: authclient.Config{BaseURL: server.URL + "/auth", Realm: "local", APIKey: key}}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	tokenPath := filepath.Join(t.TempDir(), "token.jwt")
	if err := runCLIAction(t.Context(), configPath, tokenPath, connect); err != nil {
		t.Fatal(err)
	}
	store, err := authclient.NewFileTokenStore(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := store.Load()
	if err != nil {
		t.Fatal(err)
	}
	if credentials.AccessToken != "key-access" || credentials.AccessTokenName != "custom" || calls.Load() != 1 {
		t.Fatal("API key connect failed to persist issued credentials")
	}
}

func TestCLIConfigurationCompatibility(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	if got := getConfigPath("config.yaml"); got != filepath.Join(home, ".config", "authdbctl", "config.yaml") {
		t.Fatal("default application directory changed")
	}
	for _, tc := range []struct{ name, cachedName, expected string }{
		{"cached name wins", "cached_name", "cached_name"},
		{"flag name fallback", "", "fallback"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tokenPath := filepath.Join(t.TempDir(), "from-config.jwt")
			cache := map[string]string{"access_token": "cached", "access_token_name": tc.cachedName, "refresh_token": "old-refresh", "created_at": "2026-03-03T12:00:00Z"}
			data, err := json.Marshal(cache)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(tokenPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			configPath := writeCLIConfig(t, "https://portal.test/auth/", tokenPath)
			err = runCLIAction(context.Background(), configPath, filepath.Join(t.TempDir(), "ignored-flag.jwt"), func(c *cli.Context) error {
				wr := &wrapper{}
				if err := wr.configure(c); err != nil {
					return err
				}
				if wr.config.TokenPath != tokenPath || wr.credentials.AccessTokenName != tc.expected || wr.config.BaseURL != "https://portal.test/auth" {
					t.Error("configuration precedence or URL normalization changed")
				}
				if wr.config.TOTPCodeLength != 6 || wr.config.TOTPCodeLifetime != 30 || wr.config.CookieName != "AUTHP_ACCESS_TOKEN" {
					t.Error("configuration defaults missing")
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
		})
	}
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte("base_url: https://portal.test\nusername: user\nrealm: local\npassword: private\ntotp_secret: raw-secret\ntotp_code_length: 8\ntotp_code_lifetime: 60\ncookie_name: LEGACY\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := runCLIAction(context.Background(), configPath, filepath.Join(t.TempDir(), "token.jwt"), func(c *cli.Context) error {
		wr := &wrapper{}
		if err := wr.configure(c); err != nil {
			return err
		}
		if wr.config.Password != "private" || wr.config.TOTPSecret != "raw-secret" || wr.config.TOTPCodeLength != 8 || wr.config.TOTPCodeLifetime != 60 || wr.config.CookieName != "LEGACY" {
			t.Error("legacy YAML schema changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestCLIRequestAuthentication(t *testing.T) {
	for _, tc := range []struct {
		name, cache, message     string
		disable                  bool
		max                      int
		wantRequests, wantLogins int32
		wantErr                  bool
	}{
		{name: "cache reuse", cache: "valid", wantRequests: 1},
		{name: "first authentication", wantRequests: 1, wantLogins: 1},
		{name: "expired credential", cache: "expired", wantRequests: 2, wantLogins: 1},
		{name: "forbidden", cache: "valid", message: "forbidden", wantRequests: 1, wantErr: true},
		{name: "not implemented", cache: "valid", message: "not implemented", wantRequests: 1, wantErr: true},
		{name: "unauthenticated system request", disable: true, message: "access denied", wantRequests: 3, wantErr: true},
		{name: "exhausted retry", cache: "expired", max: 1, wantRequests: 1, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests, logins atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/auth/login" {
					logins.Add(1)
					_, _ = w.Write([]byte(`{"authenticated":true,"access_token":"valid","access_token_name":"portal_token"}`))
					return
				}
				if r.URL.Path != "/auth/api/server/metadata" {
					t.Error("wrong management endpoint")
					w.WriteHeader(404)
					return
				}
				requests.Add(1)
				header := r.Header.Get("Authorization")
				if tc.disable && header != "" {
					t.Error("unauthenticated request carried credentials")
				}
				if !tc.disable && header != "portal_token=valid" && header != "portal_token=expired" {
					t.Error("incorrect management authorization")
				}
				msg := tc.message
				if header == "portal_token=expired" {
					msg = "access denied"
				}
				if msg != "" {
					w.WriteHeader(401)
					_ = json.NewEncoder(w).Encode(map[string]string{"message": msg})
					return
				}
				_, _ = w.Write([]byte(`{"name":"authp"}`))
			}))
			defer server.Close()
			tokenPath := filepath.Join(t.TempDir(), "token.jwt")
			if tc.cache != "" {
				store, err := authclient.NewFileTokenStore(tokenPath)
				if err != nil {
					t.Fatal(err)
				}
				if err := store.Save(&authclient.Credentials{AccessToken: tc.cache, AccessTokenName: "portal_token", RefreshToken: "old-refresh"}); err != nil {
					t.Fatal(err)
				}
			}
			configPath := writeCLIConfig(t, server.URL+"/auth", "")
			err := runCLIAction(context.Background(), configPath, tokenPath, func(c *cli.Context) error {
				wr := &wrapper{}
				if err := wr.configure(c); err != nil {
					return err
				}
				body, err := wr.doRequestWithRetry(c, http.MethodGet, wr.config.BaseURL+"/api/server/metadata", &requestOpts{disableAccessToken: tc.disable, maxAttempts: tc.max}, nil)
				if err == nil && body != `{"name":"authp"}` {
					t.Error("response body changed")
				}
				if tc.wantLogins > 0 && wr.credentials.RefreshToken != "" {
					t.Error("reauthentication kept an old refresh token")
				}
				return err
			})
			if (err != nil) != tc.wantErr {
				t.Fatalf("unexpected request error: %v", err)
			}
			if requests.Load() != tc.wantRequests || logins.Load() != tc.wantLogins {
				t.Fatalf("requests=%d logins=%d", requests.Load(), logins.Load())
			}
		})
	}
}

func TestCLIRetryCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "token.jwt")
	configPath := writeCLIConfig(t, server.URL, "")
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runCLIAction(ctx, configPath, tokenPath, func(c *cli.Context) error {
			wr := &wrapper{}
			if err := wr.configure(c); err != nil {
				return err
			}
			close(started)
			_, err := wr.doRequestWithRetry(c, http.MethodGet, server.URL, &requestOpts{disableAccessToken: true}, nil)
			return err
		}, "--retry-interval", "1h")
	}()
	<-started
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("request cancellation blocked")
	}
}

func TestCLIRejectsMalformedCredentialFiles(t *testing.T) {
	tokenPath := filepath.Join(t.TempDir(), "token.jwt")
	if err := os.WriteFile(tokenPath, []byte(`{"access_token":`), 0600); err != nil {
		t.Fatal(err)
	}
	configPath := writeCLIConfig(t, "https://portal.test", "")
	if err := runCLIAction(context.Background(), configPath, tokenPath, connect); err == nil || !strings.Contains(err.Error(), "invalid token file JSON") {
		t.Fatalf("got %v", err)
	}
	if err := os.WriteFile(configPath, []byte("totp_code_length: private"), 0600); err != nil {
		t.Fatal(err)
	}
	err := runCLIAction(context.Background(), configPath, tokenPath, connect)
	if err == nil || strings.Contains(fmt.Sprint(err), "private") {
		t.Fatal("malformed config was accepted or exposed its contents")
	}
}
