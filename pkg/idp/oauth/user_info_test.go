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
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestFetchUserInfoRejectsUnsafeResponses(t *testing.T) {
	testcases := []struct {
		name    string
		body    string
		status  int
		wantErr string
		want    map[string]any
	}{
		{
			name: "bounded valid response",
			body: `{"roles":["reader"]}` + strings.Repeat(" ", maxOAuthResponseSize-len(`{"roles":["reader"]}`)),
			want: map[string]any{"subject": "alice", "roles": []string{"reader"}},
		},
		{
			name:    "oversized valid response",
			body:    `{"roles":["administrator"],"padding":"` + strings.Repeat("x", maxOAuthResponseSize) + `"}`,
			wantErr: "OAuth UserInfo response exceeds",
			want:    map[string]any{"subject": "alice"},
		},
		{
			name:    "non-success response",
			body:    `{"roles":["administrator"]}`,
			status:  http.StatusUnauthorized,
			wantErr: "UserInfo endpoint returned HTTP 401",
			want:    map[string]any{"subject": "alice"},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if got := r.Header.Get("Authorization"); got != "Bearer opaque-access-token" {
					t.Errorf("Authorization header = %q", got)
				}
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()

			provider := &IdentityProvider{
				config:                 &Config{Driver: "generic"},
				userInfoURL:            server.URL,
				scopeMap:               map[string]any{"openid": true},
				userInfoFields:         map[string]any{"roles": true},
				userInfoRolesFieldName: "roles",
				browserConfig:          &browserConfig{TLSInsecureSkipVerify: true},
				logger:                 zap.NewNop(),
			}
			userData := map[string]any{"subject": "alice"}
			err := provider.fetchUserInfo(map[string]any{"access_token": "opaque-access-token"}, userData)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("fetchUserInfo error = %v, want substring %q", err, tc.wantErr)
			}
			if !reflect.DeepEqual(userData, tc.want) {
				t.Fatalf("user data = %#v, want %#v", userData, tc.want)
			}
		})
	}

	t.Run("invalid access token type", func(t *testing.T) {
		provider := &IdentityProvider{
			config:         &Config{Driver: "generic"},
			userInfoURL:    "https://userinfo.example.test",
			scopeMap:       map[string]any{"openid": true},
			userInfoFields: map[string]any{"roles": true},
			logger:         zap.NewNop(),
		}
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("fetchUserInfo panicked on provider-controlled token data: %v", recovered)
			}
		}()
		err := provider.fetchUserInfo(map[string]any{"access_token": 7}, map[string]any{"subject": "alice"})
		if err == nil || !strings.Contains(err.Error(), "access_token") {
			t.Fatalf("fetchUserInfo error = %v, want access_token validation error", err)
		}
	})
}
