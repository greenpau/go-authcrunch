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

package oauth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestFetchClaimsRejectsMalformedTokenAndUserInfo(t *testing.T) {
	provider := &IdentityProvider{config: &Config{Driver: "linkedin"}, logger: zap.NewNop()}
	for _, token := range []map[string]any{{}, {"access_token": 7}, {"access_token": ""}} {
		if _, err := provider.fetchClaims(token); err == nil {
			t.Fatalf("malformed access token accepted: %#v", token)
		}
	}

	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantErr bool
	}{
		{name: "http error", status: http.StatusUnauthorized, body: `{"profile":"https://gitlab.example/alice"}`, wantErr: true},
		{name: "near limit", status: http.StatusOK, body: validLargeUserInfo(maxUserInfoResponseSize - 1)},
		{name: "oversized", status: http.StatusOK, body: validLargeUserInfo(maxUserInfoResponseSize + 1), wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			provider := &IdentityProvider{
				config:        &Config{Driver: "gitlab"},
				logger:        zap.NewNop(),
				userInfoURL:   server.URL,
				browserConfig: &browserConfig{TLSInsecureSkipVerify: true},
			}
			_, err := provider.fetchClaims(map[string]any{"access_token": "opaque"})
			if (err != nil) != tc.wantErr {
				t.Fatalf("fetchClaims() error = %v, want error %t", err, tc.wantErr)
			}
		})
	}
}

func validLargeUserInfo(size int) string {
	const prefix = `{"profile":"https://gitlab.example/alice","padding":"`
	const suffix = `"}`
	return prefix + strings.Repeat("x", size-len(prefix)-len(suffix)) + suffix
}
