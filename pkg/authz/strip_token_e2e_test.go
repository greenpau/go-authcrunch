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

package authz_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	autherrors "github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func newStripTokenE2EToken(t *testing.T) string {
	t.Helper()
	data, err := json.Marshal(map[string]any{
		"sub": "strip-user", "roles": []string{"viewer"},
		"exp": time.Now().Add(5 * time.Minute).Unix(), "iat": time.Now().Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	usr, err := user.NewUser(data)
	if err != nil {
		t.Fatal(err)
	}
	keys, err := testutils.NewTestCryptoKeyStore()
	if err != nil {
		t.Fatal(err)
	}
	if err := keys.SignToken("access_token", "HS512", usr); err != nil {
		t.Fatal(err)
	}
	return usr.Token
}

func TestE2EStripAcceptedTokenPreservesApplicationCredentials(t *testing.T) {
	token := newStripTokenE2EToken(t)
	for _, tc := range []struct {
		name  string
		input http.Header
		want  map[string][]string
	}{
		{
			name:  "bearer",
			input: http.Header{"Authorization": {`Digest username="a,b", Bearer ` + token}},
			want:  map[string][]string{"Authorization": {`Digest username="a,b"`}},
		},
		{
			name:  "named authorization token",
			input: http.Header{"Authorization": {"access_token=" + token + ", Application keep"}},
			want:  map[string][]string{"Authorization": {"Application keep"}},
		},
		{
			name:  "quoted cookie",
			input: http.Header{"Cookie": {`application=keep; access_token="` + token + `"; access_token=other`}},
			want:  map[string][]string{"Cookie": {"application=keep; access_token=other"}},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newPathServer(t, &authz.PolicyConfig{StripTokenEnabled: true}, headerApplication("Authorization", "Cookie"))
			for round := range 2 {
				got := s.requestHeaders(t, "/private", "", tc.input)
				if diff := cmp.Diff(tc.want, got.Values); diff != "" {
					t.Fatalf("round %d downstream credentials mismatch (-want +got):\n%s", round, diff)
				}
			}
		})
	}

	t.Run("query", func(t *testing.T) {
		application := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(downstreamHeaders{Values: map[string][]string{
				"RawQuery":   {r.URL.RawQuery},
				"RequestURI": {r.RequestURI},
			}})
		})
		s := newPathServer(t, &authz.PolicyConfig{StripTokenEnabled: true}, application)
		target := "/private?" + url.Values{
			"access_token": {token, "other"}, "application": {"keep"},
		}.Encode()
		got := s.requestHeaders(t, target, "", nil)
		want := map[string][]string{
			"RawQuery":   {"access_token=other&application=keep"},
			"RequestURI": {"/private?access_token=other&application=keep"},
		}
		if diff := cmp.Diff(want, got.Values); diff != "" {
			t.Fatalf("downstream query mismatch (-want +got):\n%s", diff)
		}
	})
}

type stripTokenAuthenticator struct {
	token string
}

func (a *stripTokenAuthenticator) GetName() string { return "portal" }
func (a *stripTokenAuthenticator) APIKeyAuth(*authproxy.Request) error {
	return autherrors.ErrAPIKeyAuthFailed
}
func (a *stripTokenAuthenticator) BasicAuth(r *authproxy.Request) error {
	r.Response.Name = "access_token"
	r.Response.Payload = a.token
	return nil
}

func TestE2EStripBasicPasswordBeforeDownstream(t *testing.T) {
	cfg := &authz.PolicyConfig{
		Name: "strip-basic", AuthRedirectDisabled: true, StripTokenEnabled: true,
		RawCryptoKeyStoreConfig: []string{"crypto key verify " + testutils.GetSharedKey()},
		AuthProxyRawConfig:      []string{"basic auth realm local portal portal"},
		AccessListRules: []*acl.RuleConfiguration{{
			Conditions: []string{"match roles viewer"}, Action: "allow stop",
		}},
	}
	gate, err := authz.NewGatekeeper(cfg, zap.NewNop())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(gate.Close)
	if err := gate.AddAuthenticators([]authproxy.Authenticator{&stripTokenAuthenticator{token: newStripTokenE2EToken(t)}}); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ar := requests.NewAuthorizationRequest()
		if err := gate.Authenticate(w, r, ar); err != nil || !ar.Response.Authorized {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(downstreamHeaders{Values: map[string][]string{
			"Authorization": r.Header.Values("Authorization"),
		}})
	}))
	t.Cleanup(server.Close)

	secret := base64.StdEncoding.EncodeToString([]byte("alice:secret"))
	for round := range 2 {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, server.URL+"/private", nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Basic "+secret+", Application keep")
		req.Header.Set("X-Auth-Realm", "local")
		resp, err := server.Client().Do(req)
		if err != nil {
			t.Fatal(err)
		}
		var got downstreamHeaders
		err = json.NewDecoder(resp.Body).Decode(&got)
		resp.Body.Close()
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("round %d status=%d decode=%v", round, resp.StatusCode, err)
		}
		want := map[string][]string{"Authorization": {"Application keep"}}
		if diff := cmp.Diff(want, got.Values); diff != "" {
			t.Fatalf("round %d downstream credentials mismatch (-want +got):\n%s", round, diff)
		}
	}
}
