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

package httpserver

import (
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"go.uber.org/zap"
)

func TestSecurityConfigurationObjects(t *testing.T) {
	for _, body := range []string{
		`{"credentials":{"generic":[null]}}`,
		`{"messaging":{"email_providers":[null]}}`,
		`{"messaging":{"file_providers":[null]}}`,
		`{"authentication_portals":[{"trusted_login_redirect_uri_configs":[null]}]}`,
		`{"authentication_portals":[{"trusted_logout_redirect_uri_configs":[null]}]}`,
		`{"authentication_portals":[{"access_list_configs":[null]}]}`,
		`{"authentication_portals":[{"user_transformer_configs":[null]}]}`,
		`{"authentication_portals":[{"ui":{"static_assets":[null]}}]}`,
		`{"authentication_portals":[{"ui":{"private_links":[null]}}]}`,
		`{"authentication_portals":[{"ui":{"realms":[null]}}]}`,
		`{"authentication_portals":[{"cookie_config":{"domains":{"SECRET":null}}}]}`,
		`{"authorization_policies":[{"bypass_configs":[null]}]}`,
		`{"authorization_policies":[{"header_injection_configs":[null]}]}`,
	} {
		t.Run(body, func(t *testing.T) {
			var cfg authcrunch.Config
			if err := json.Unmarshal([]byte(body), &cfg); err != nil {
				t.Fatal(err)
			}
			err := validateConfigurationObjects(&cfg)
			if err == nil || strings.Contains(err.Error(), "SECRET") {
				t.Fatal("null configuration entry was accepted or disclosed its map key")
			}
		})
	}
	// Absent optional objects and opaque provider data keep their existing
	// semantics. Component validators own values inside params.
	var cfg authcrunch.Config
	if err := json.Unmarshal([]byte(`{"credentials":null,"identity_stores":[{"params":{"optional":null,"list":[null]}}],"authentication_portals":[{"ui":null}]}`), &cfg); err != nil {
		t.Fatal(err)
	}
	cfg.AuthenticationPortals = append(cfg.AuthenticationPortals, cfg.AuthenticationPortals[0])
	if err := validateConfigurationObjects(&cfg); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityCryptoStatements(t *testing.T) {
	for _, statement := range []string{"", "crypto", `"unfinished`} {
		for _, subject := range []string{"authentication_portals", "authorization_policies"} {
			var cfg authcrunch.Config
			body, err := json.Marshal(map[string]any{subject: []any{map[string]any{"name": "portal", "raw_crypto_key_store_config": []string{statement}}}})
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(body, &cfg); err != nil {
				t.Fatal(err)
			}
			if err := validateSecurity(validConfig(), &cfg); err == nil || !strings.Contains(err.Error(), "crypto configuration") {
				t.Fatal("incomplete crypto statement accepted")
			}
		}
	}
	if err := validateCryptoStatements([]string{"crypto default token lifetime 3600"}); err != nil {
		t.Fatal(err)
	}
}

func TestServeRedactsInitializationErrors(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	var cfg authcrunch.Config
	if err := json.Unmarshal([]byte(`{"credentials":{"raw_credential_configs":[["SECRET do-not-print extra"]]},"authentication_portals":[{"name":"portal"}]}`), &cfg); err != nil {
		t.Fatal(err)
	}
	err = Serve(t.Context(), listener, validConfig(), &cfg, zap.NewNop())
	if err == nil || strings.Contains(err.Error(), "SECRET") || strings.Contains(err.Error(), "do-not-print") {
		t.Fatal("initialization error disclosed configuration")
	}
	if cause := errors.Unwrap(err); cause == nil || !strings.Contains(cause.Error(), "SECRET") {
		t.Fatal("private diagnostic cause was lost")
	}
	if _, err := listener.Accept(); !errors.Is(err, net.ErrClosed) {
		t.Fatal("failed initialization left listener open")
	}
}
