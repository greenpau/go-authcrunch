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

package authclient

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

func TestRefreshTransportConfig(t *testing.T) {
	for _, mode := range []string{"", RefreshTransportCookie, RefreshTransportBody} {
		cfg := Config{BaseURL: "https://portal.test", Username: "alice", Realm: "local", RefreshTransport: mode}
		client, err := NewClient(&cfg, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if cfg.RefreshTransport != mode {
			t.Fatal("caller configuration mutated")
		}
		want := mode
		if mode == "" {
			want = RefreshTransportCookie
		}
		if client.config.RefreshTransport != want {
			t.Fatal("unexpected transport")
		}
	}
	for _, cfg := range []Config{
		{BaseURL: "https://portal.test", Username: "alice", Realm: "local", RefreshTransport: "unknown-private-value"},
		{BaseURL: "https://portal.test", Realm: "local", APIKey: "fixture", RefreshTransport: RefreshTransportBody},
	} {
		if _, err := NewClient(&cfg, Options{}); err == nil {
			t.Fatal("invalid transport accepted")
		}
	}
}

func TestNativeTransportIsolation(t *testing.T) {
	var requests int
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		for _, name := range []string{"Cookie", "Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
			if len(r.Header.Values(name)) != 0 {
				t.Error("native login carried browser state")
			}
		}
		var body apiauth.AuthRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		if body.RefreshTransport != RefreshTransportBody {
			t.Error("native transport not carried through exchange")
		}
		http.SetCookie(w, &http.Cookie{Name: "AUTHP_SESSION_ID", Value: "server-cookie", Path: "/"})
		if requests%2 == 1 {
			_ = json.NewEncoder(w).Encode(apiauth.AuthResponse{SandboxID: "id", SandboxSecret: "secret", NextChallenge: "password"})
		} else {
			_ = json.NewEncoder(w).Encode(apiauth.AuthResponse{Authenticated: true, AccessToken: "new-access", RefreshToken: "new-refresh", SessionID: "new-session"})
		}
	}))
	defer server.Close()
	shared := server.Client()
	shared.Jar, _ = cookiejar.New(nil)
	u, _ := url.Parse(server.URL)
	shared.Jar.SetCookies(u, []*http.Cookie{{Name: "AUTHP_SESSION_ID", Value: "browser-session", Path: "/"}})
	before := shared.Jar.Cookies(u)
	client, err := NewClient(&Config{BaseURL: server.URL, Username: "alice", Realm: "local", Password: "fixture-password", RefreshTransport: RefreshTransportBody}, Options{HTTPClient: shared})
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := client.Authenticate(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if requests != 4 || client.http.Jar != nil || !reflect.DeepEqual(shared.Jar.Cookies(u), before) {
		t.Fatal("native client read or mutated shared cookie state")
	}
}

func TestCredentialTransportResponses(t *testing.T) {
	for _, tc := range []struct {
		name, mode string
		response   apiauth.AuthResponse
		want       error
	}{
		{"browser metadata", RefreshTransportCookie, apiauth.AuthResponse{Authenticated: true, SessionID: "session"}, ErrNativeTransportRequired},
		{"native missing refresh", RefreshTransportBody, apiauth.AuthResponse{Authenticated: true, AccessToken: "token", SessionID: "session"}, nil},
		{"native missing session", RefreshTransportBody, apiauth.AuthResponse{Authenticated: true, AccessToken: "token", RefreshToken: "refresh"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests++; _ = json.NewEncoder(w).Encode(tc.response) }))
			defer server.Close()
			client, err := NewClient(&Config{BaseURL: server.URL, Username: "alice", Realm: "local", RefreshTransport: tc.mode}, Options{HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := client.Authenticate(t.Context())
			if credentials != nil || err == nil || requests != 1 {
				t.Fatal("invalid result returned credentials or triggered retry")
			}
			if tc.want != nil && !errors.Is(err, tc.want) {
				t.Fatal("missing inspectable transport error")
			}
		})
	}
}

func TestLegacyCookieTransportRequest(t *testing.T) {
	for _, mode := range []string{"", RefreshTransportCookie} {
		t.Run("mode="+mode, func(t *testing.T) {
			calls := 0
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				// v1.1.41's request shape and unknown-field rejection. Decode
				// each exchange independently, including its password checkpoint.
				var request struct {
					Username          string `json:"username"`
					Realm             string `json:"realm"`
					SandboxID         string `json:"sandbox_id"`
					SandboxSecret     string `json:"sandbox_secret"`
					ChallengeKind     string `json:"challenge_kind"`
					ChallengeResponse string `json:"challenge_response"`
				}
				decoder := json.NewDecoder(r.Body)
				decoder.DisallowUnknownFields()
				if err := decoder.Decode(&request); err != nil {
					t.Error("default login sent a field unsupported by the legacy portal")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				if calls == 1 {
					_ = json.NewEncoder(w).Encode(apiauth.AuthResponse{SandboxID: "sandbox", SandboxSecret: "secret", NextChallenge: "password"})
					return
				}
				if request.ChallengeKind != "password" || request.ChallengeResponse != "fixture-password" {
					t.Error("legacy password checkpoint was not answered")
				}
				_ = json.NewEncoder(w).Encode(apiauth.AuthResponse{Authenticated: true, AccessToken: "legacy-access"})
			}))
			defer server.Close()
			client, err := NewClient(&Config{BaseURL: server.URL, Username: "alice", Realm: "local", Password: "fixture-password", RefreshTransport: mode}, Options{HTTPClient: server.Client()})
			if err != nil {
				t.Fatal(err)
			}
			credentials, err := client.Authenticate(t.Context())
			if err != nil || credentials == nil || credentials.AccessToken != "legacy-access" || calls != 2 {
				t.Fatal("legacy cookie/default password login failed")
			}
		})
	}
}
