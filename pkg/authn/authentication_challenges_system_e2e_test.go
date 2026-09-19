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

package authn_test

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/system"
)

const challengeSystemKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func challengeSystemConfig(cfg *authn.PortalConfig) {
	cfg.RawCryptoKeyStoreConfig = append(cfg.RawCryptoKeyStoreConfig, "crypto key internal system "+challengeSystemKey)
}

func challengeSystemEncryptor(t *testing.T) *system.Encryptor {
	t.Helper()
	key, err := system.ParseKeyFromString(challengeSystemKey)
	if err != nil {
		t.Fatal(err)
	}
	encryptor, err := system.NewEncryptor("internal", key)
	if err != nil {
		t.Fatal(err)
	}
	return encryptor
}

func challengeSystemRequest(t *testing.T, endpoint string, apiKey bool, secret string) *http.Request {
	t.Helper()
	var msg system.Message = &system.BasicAuthRequestMessage{Kind: system.BasicAuthRequestKindKeyword, Realm: "local", Username: "alice", Password: secret, Address: "198.51.100.10"}
	if apiKey {
		msg = &system.APIKeyAuthRequestMessage{Kind: system.APIKeyAuthRequestKindKeyword, Realm: "local", APIKey: secret, Address: "198.51.100.10"}
	}
	encoded, err := challengeSystemEncryptor(t).EncryptMessage(msg)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, strings.NewReader(encoded))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "text/plain; charset=UTF-8")
	return req
}

func challengeSystemClaims(t *testing.T, data []byte) map[string]any {
	t.Helper()
	msg, err := challengeSystemEncryptor(t).DecryptMessage(string(data))
	if err != nil {
		t.Fatal("invalid encrypted authentication response")
	}
	response, ok := msg.(*system.AuthResponseMessage)
	if !ok || !response.Authenticated || response.UserData["sub"] != "alice" {
		t.Fatal("system authentication did not attest the expected identity")
	}
	for _, key := range []string{"auth_methods", "challenges", "frontend_links"} {
		if _, exists := response.UserData[key]; exists {
			t.Fatal("internal authentication state leaked into remote claims")
		}
	}
	return response.UserData
}

func TestE2EAuthenticationChallengeSystemContext(t *testing.T) {
	for _, actions := range [][]string{
		{"prefix match iss https://", "require totp"},
		{"exact match addr 198.51.100.10", "require totp"},
	} {
		t.Run(actions[0], func(t *testing.T) {
			f, _, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", func(cfg *authn.PortalConfig) {
				challengeSystemConfig(cfg)
				authenticationChallengeConfig(t, actions)(cfg)
			})
			response, err := f.client.Do(challengeSystemRequest(t, f.issuer+"/api/system", false, tests.TestPwd1))
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != http.StatusForbidden {
				t.Fatalf("contextual remote policy bypass: HTTP %d", response.StatusCode)
			}
		})
	}
}

func TestE2EAuthenticationChallengeSystemInvalidCredentials(t *testing.T) {
	f, _, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", challengeSystemConfig)
	for _, apiKey := range []bool{false, true} {
		response, err := f.client.Do(challengeSystemRequest(t, f.issuer+"/api/system", apiKey, strings.Repeat("a", 64)))
		if err != nil {
			t.Fatal("invalid credential did not receive an HTTP response", err)
		}
		io.Copy(io.Discard, response.Body)
		response.Body.Close()
		if response.StatusCode != http.StatusUnauthorized {
			t.Fatalf("invalid credential HTTP %d", response.StatusCode)
		}
	}
}

func TestE2EAuthenticationChallengeSystemBodyErrors(t *testing.T) {
	f, _, _ := newLoginIdentityConfiguredE2E(t, false, false, false, "", challengeSystemConfig)
	for _, tc := range []struct {
		name         string
		size, status int
		chunked      bool
	}{
		{"malformed within limit", 1 << 20, http.StatusBadRequest, false},
		{"oversized", (1 << 20) + 1, http.StatusRequestEntityTooLarge, false},
		{"chunked within limit", 1 << 20, http.StatusBadRequest, true},
		{"chunked oversized", (1 << 20) + 1, http.StatusRequestEntityTooLarge, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, f.issuer+"/api/system", strings.NewReader(strings.Repeat("x", tc.size)))
			if err != nil {
				t.Fatal(err)
			}
			if tc.chunked {
				req.ContentLength = -1
			}
			response, err := f.client.Do(req)
			if err != nil {
				t.Fatal("invalid body did not receive an HTTP response", err)
			}
			defer response.Body.Close()
			var result map[string]any
			if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
				t.Fatal(err)
			}
			if response.StatusCode != tc.status || result["error"] != http.StatusText(tc.status) || result["authenticated"] != nil {
				t.Fatalf("invalid system body HTTP %d", response.StatusCode)
			}
		})
	}
	// A malformed request must not prevent a subsequent valid encrypted login.
	response, err := f.client.Do(challengeSystemRequest(t, f.issuer+"/api/system", false, tests.TestPwd1))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("valid system login HTTP %d", response.StatusCode)
	}
	challengeSystemClaims(t, body)
}
