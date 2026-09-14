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

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

func TestConnectNativeTransportYAML(t *testing.T) {
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var request apiauth.AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
		}
		if request.RefreshTransport != authclient.RefreshTransportBody {
			t.Error("CLI lost configured native mode")
		}
		if calls == 1 {
			_ = json.NewEncoder(w).Encode(apiauth.AuthResponse{SandboxID: "sandbox", SandboxSecret: "secret", NextChallenge: "password"})
			return
		}
		_ = json.NewEncoder(w).Encode(apiauth.AuthResponse{Authenticated: true, AccessToken: "fresh-access", AccessTokenName: "CUSTOM_ACCESS_TOKEN", RefreshToken: "fresh-refresh", RefreshTokenName: "CUSTOM_REFRESH_TOKEN", SessionID: "fresh-session"})
	}))
	defer server.Close()
	tokenPath := filepath.Join(t.TempDir(), "token.jwt")
	configPath := writeCLIConfig(t, server.URL, tokenPath)
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.RefreshTransport = authclient.RefreshTransportBody
	data, err = yaml.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, data, 0600); err != nil {
		t.Fatal(err)
	}
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
	if calls != 2 || credentials.RefreshToken != "fresh-refresh" || credentials.SessionID != "fresh-session" || credentials.AccessTokenName != "custom_access_token" {
		t.Fatal("CLI did not persist complete new credentials")
	}
}
