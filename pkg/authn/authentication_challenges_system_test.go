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

package authn

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	transformerparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

func TestSystemAuthenticationChallengePolicy(t *testing.T) {
	for _, tc := range []struct {
		name, action        string
		selected, key, deny bool
		required            []string
	}{
		{name: "default password", required: []string{"password"}},
		{name: "default MFA denies Basic", required: []string{"password", "totp"}, deny: true},
		{name: "default MFA permits API key", required: []string{"password", "totp"}, key: true},
		{name: "stored password denies API key", required: []string{"password"}, selected: true, key: true, deny: true},
		{name: "stored TOTP denies Basic", required: []string{"totp"}, selected: true, deny: true},
		{name: "additive factor", required: []string{"password"}, action: "require totp", deny: true},
		{name: "AMR forgery", required: []string{"password"}, action: "overwrite amr hwk"},
		{name: "API key AMR forgery", required: []string{"password"}, action: "overwrite amr hwk", key: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := &Portal{config: &PortalConfig{}, logger: zap.NewNop()}
			if tc.action != "" {
				cfg, err := transformerparser.NewUserTransformerConfigFromDirectives([]string{"match realm local", tc.action})
				if err != nil {
					t.Fatal(err)
				}
				p.transformer, err = transformer.NewFactory([]*transformer.Config{cfg})
				if err != nil {
					t.Fatal(err)
				}
			}
			rr := &requests.Request{Upstream: requests.Upstream{Realm: "local", Method: "local"}, User: requests.User{Username: "alice", Email: "alice@example.test", Challenges: tc.required, AuthMethods: []string{"password", "totp"}, AuthChallengePolicy: tc.selected}}
			completed := []string{"password"}
			if tc.key {
				completed = nil
			}
			claims := map[string]any{"addr": "198.51.100.10"}
			err := p.handleAPIExtractUserIdentity(t.Context(), rr, claims, completed)
			if (err != nil) != tc.deny {
				t.Fatal("incorrect remote authentication policy decision", err)
			}
			if tc.deny {
				if rr.Response.Code != http.StatusForbidden {
					t.Fatal("denied policy returned a successful status")
				}
				return
			}
			if tc.key && claims["amr"] != nil || !tc.key && !reflect.DeepEqual(claims["amr"], []string{"pwd"}) {
				t.Fatal("remote claims misstated verified methods")
			}
			if claims["challenges"] != nil || claims["auth_methods"] != nil {
				t.Fatal("internal challenge state leaked")
			}
		})
	}
}

func TestSystemAPIKeyAuthenticationEvidence(t *testing.T) {
	f := newRefreshPortal(t, false, false)
	const secret = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"
	if err := f.store.Request(operator.AddAPIKey, &requests.Request{User: requests.User{Username: tests.TestUser1, Email: tests.TestEmail1}, Key: requests.Key{Payload: secret, Usage: "api", Comment: "system verification"}}); err != nil {
		t.Fatal(err)
	}
	rr := requests.NewRequest()
	r := httptest.NewRequest(http.MethodPost, "https://portal.example.test/auth/api/system", nil)
	if err := f.portal.authenticateAPIKeyAuthRequest(t.Context(), httptest.NewRecorder(), r, rr, "local", secret); err != nil {
		t.Fatal(err)
	}
	if rr.Authentication.Method != "api_key" || rr.Authentication.AuthenticatedAt == 0 || rr.Authentication.APIKeyID == "" || rr.User.Username != tests.TestUser1 {
		t.Fatal("identification replaced verified API key evidence")
	}
	if err := f.portal.authenticateAPIKeyAuthRequest(t.Context(), httptest.NewRecorder(), r, rr, "local", secret[:63]+"C"); err == nil || rr.Response.Code != http.StatusUnauthorized || rr.Authentication != (requests.AuthenticationEvidence{}) {
		t.Fatal("failed key verification retained evidence or successful status")
	}
}
