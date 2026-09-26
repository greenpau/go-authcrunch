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

package oauth_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/idp/oauth"
	"go.uber.org/zap"
)

func TestE2EGoogleRejectsUnsafeGroupResponses(t *testing.T) {
	if os.Getenv("AUTHCRUNCH_GOOGLE_GROUPS_CHILD") == "1" {
		testGoogleUnsafeGroupResponsesChild(t)
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestE2EGoogleRejectsUnsafeGroupResponses$", "-test.count=1")
	cmd.Env = append(os.Environ(), "AUTHCRUNCH_GOOGLE_GROUPS_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Google group response child failed: %v\n%s", err, output)
	}
}

func testGoogleUnsafeGroupResponsesChild(t *testing.T) {
	var mu sync.Mutex
	var body string
	var status, calls int
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		calls++
		if r.URL.Path != "/v1/groups/-/memberships:getMembershipGraph" {
			t.Errorf("Google group path = %q", r.URL.Path)
		}
		if query := r.URL.Query().Get("query"); !strings.Contains(query, "member_key_id=='alice@example.test'") {
			t.Errorf("Google group query = %q", query)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer opaque" {
			t.Errorf("Google authorization header = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		if status != 0 {
			w.WriteHeader(status)
		}
		_, _ = io.WriteString(w, body)
	}))
	defer upstream.Close()
	proxy := newNamedDriverConnectProxy(t, upstream.Listener.Addr().String())
	defer proxy.Close()
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)
	t.Setenv("NO_PROXY", "127.0.0.1,localhost")
	t.Setenv("no_proxy", "127.0.0.1,localhost")

	for _, tc := range []struct {
		name              string
		token, email      any
		roles             any
		body              string
		status, wantCalls int
		wantErr           bool
		wantRoles         []string
	}{
		{
			name: "valid groups", token: "opaque", email: "alice@example.test", roles: []string{"viewer"},
			body:      `{"response":{"groups":[{"displayName":"engineering"},{"displayName":"operators"}]}}`,
			wantCalls: 1, wantRoles: []string{"viewer", "engineering", "operators"},
		},
		{
			name: "numeric email", token: "opaque", email: 7, roles: []string{"viewer"},
			body: `{"response":{"groups":[]}}`, wantErr: true,
		},
		{
			name: "numeric access token", token: 7, email: "alice@example.test", roles: []string{"viewer"},
			body: `{"response":{"groups":[]}}`, wantErr: true,
		},
		{
			name: "invalid existing roles", token: "opaque", email: "alice@example.test", roles: []any{"viewer", 7},
			body: `{"response":{"groups":[{"displayName":"engineering"}]}}`, wantCalls: 1, wantErr: true,
			wantRoles: nil,
		},
		{
			name: "HTTP failure", token: "opaque", email: "alice@example.test", roles: []string{"viewer"},
			body: `{"response":{"groups":[{"displayName":"administrators"}]}}`, status: http.StatusUnauthorized,
			wantCalls: 1, wantErr: true, wantRoles: []string{"viewer"},
		},
		{
			name: "oversized groups", token: "opaque", email: "alice@example.test", roles: []string{"viewer"},
			body:      `{"response":{"groups":[{"displayName":"administrators","padding":"` + strings.Repeat("x", 1<<20) + `"}]}}`,
			wantCalls: 1, wantErr: true, wantRoles: []string{"viewer"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mu.Lock()
			body, status, calls = tc.body, tc.status, 0
			mu.Unlock()
			provider, err := oauth.NewIdentityProvider(&oauth.Config{
				Name: "google", Realm: "google", Driver: "google",
				ClientID: "client", ClientSecret: "secret",
				Scopes:      []string{"https://www.googleapis.com/auth/cloud-identity.groups.readonly"},
				BaseAuthURL: "https://accounts.google.com/o/oauth2/v2/auth",
				MetadataURL: "https://metadata.example.test/.well-known/openid-configuration",
				DelayStart:  3600, TLSInsecureSkipVerify: true,
			}, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			if err := provider.Configure(); err != nil {
				provider.Close()
				t.Fatal(err)
			}
			userData := map[string]any{"email": tc.email, "roles": tc.roles}
			err = provider.FetchUserGroupsForTesting(map[string]any{"access_token": tc.token}, userData)
			provider.Close()
			if (err != nil) != tc.wantErr {
				t.Fatalf("group enrichment error = %v, want error %t", err, tc.wantErr)
			}
			if tc.wantRoles != nil && !reflect.DeepEqual(userData["roles"], tc.wantRoles) {
				t.Fatalf("roles = %#v, want %#v", userData["roles"], tc.wantRoles)
			}
			mu.Lock()
			gotCalls := calls
			mu.Unlock()
			if gotCalls != tc.wantCalls {
				t.Fatalf("Google group calls = %d, want %d", gotCalls, tc.wantCalls)
			}
		})
	}
}
