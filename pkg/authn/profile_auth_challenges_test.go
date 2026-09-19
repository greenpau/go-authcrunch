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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	transformerparser "github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

func TestProfileAuthChallengesDecode(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		want       []string
	}{
		{"reset", `{"challenges":[]}`, []string{}},
		{"conditional", `{"challenges":["u2f","password totp if u2f not available","password if u2f and totp not available"]}`, []string{"u2f", "password totp if u2f not available", "password if u2f and totp not available"}},
		{"or", `{"challenges":["u2f or totp"]}`, []string{"u2f or totp"}},
		{"missing", `{}`, nil},
		{"null", `{"challenges":null}`, nil},
		{"scalar", `{"challenges":"password"}`, nil},
		{"mixed", `{"challenges":["password",42]}`, nil},
		{"nested", `{"challenges":[["password"]]}`, nil},
		{"empty rule", `{"challenges":[""]}`, nil},
		{"duplicate", `{"challenges":["password","password"]}`, nil},
		{"unknown", `{"challenges":["private-secret"]}`, nil},
		{"email", `{"challenges":["email"]}`, nil},
		{"email condition", `{"challenges":["password if email not available"]}`, nil},
		{"operator", `{"challenges":["password or"]}`, nil},
		{"multiline", `{"challenges":["password\nu2f"]}`, nil},
		{"transform action", `{"challenges":["require auth challenges password"]}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var body map[string]any
			if err := json.Unmarshal([]byte(tc.body), &body); err != nil {
				t.Fatal(err)
			}
			got, err := parseProfileAuthChallenges(body)
			if (err != nil) != (tc.want == nil) || !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rules %v, error %v; want %v", got, err, tc.want)
			}
			if err != nil && strings.Contains(err.Error(), "private-secret") {
				t.Fatal("validation reflected request content")
			}
		})
	}
}

func profileAuthChallengeTestPortal(t *testing.T, actions []string) *Portal {
	t.Helper()
	p := &Portal{logger: zap.NewNop()}
	if len(actions) > 0 {
		cfg, err := transformerparser.NewUserTransformerConfigFromDirectives(append([]string{"match realm local"}, actions...))
		if err != nil {
			t.Fatal(err)
		}
		p.transformer, err = transformer.NewFactory([]*transformer.Config{cfg})
		if err != nil {
			t.Fatal(err)
		}
	}
	return p
}

func TestProfileAuthChallengePolicy(t *testing.T) {
	for _, tc := range []struct {
		name, source                          string
		rules, actions, effective, additional []string
		tokens                                []*identity.MfaToken
		invalid                               bool
	}{
		{name: "defaults", source: "default", effective: []string{"password"}},
		{name: "password preference", rules: []string{"password"}, source: "user", effective: []string{"password"}, tokens: []*identity.MfaToken{{Type: "u2f"}}},
		{name: "hardware preference", rules: []string{"u2f"}, source: "user", effective: []string{"u2f"}, tokens: []*identity.MfaToken{{Type: "u2f"}}},
		{name: "portal override", rules: []string{"password"}, actions: []string{"require auth challenges u2f"}, source: "portal", effective: []string{"u2f"}, tokens: []*identity.MfaToken{{Type: "u2f"}}},
		{name: "additive requirement", rules: []string{"u2f"}, actions: []string{"require password"}, source: "user", effective: []string{"u2f", "password"}, additional: []string{"password"}, tokens: []*identity.MfaToken{{Type: "u2f"}}},
		{name: "missing factor", rules: []string{"u2f"}, invalid: true},
		{name: "disabled factor", rules: []string{"u2f"}, tokens: []*identity.MfaToken{{Type: "u2f", Disabled: true}}, invalid: true},
		{name: "unsupported generic MFA", rules: []string{"mfa"}, tokens: []*identity.MfaToken{{Type: "email"}}, invalid: true},
		{name: "unavailable portal policy", actions: []string{"require auth challenges u2f"}, invalid: true},
		{name: "denied by portal", actions: []string{"block"}, invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profileAuthChallengeTestPortal(t, tc.actions)
			current := &identity.User{Username: "alice", AuthChallengeRules: tc.rules, MfaTokens: tc.tokens, EmailAddresses: []*identity.EmailAddress{{Address: "alice@example.test"}}}
			usr := &user.User{Authenticator: user.Authenticator{Name: "database", Realm: "local", Method: "local"}}
			rr := requests.NewRequest()
			rr.Upstream.BasePath = "/auth"
			r := httptest.NewRequest(http.MethodPost, "https://portal.example.test/auth/api/profile?unchanged=yes", nil)
			got, err := p.profileAuthChallengePolicy(t.Context(), r, rr, usr, current)
			if (err != nil) != tc.invalid {
				t.Fatalf("unexpected preview error: %v", err)
			}
			if r.URL.Path != "/auth/api/profile" || r.URL.RawQuery != "unchanged=yes" || rr.Upstream.Realm != "" {
				t.Fatal("preview modified original request")
			}
			if tc.invalid {
				return
			}
			if got["policy_source"] != tc.source || !slices.Equal(got["effective_challenges"].([]string), tc.effective) || !slices.Equal(got["additional_challenges"].([]string), tc.additional) {
				t.Fatalf("unexpected preview: %v", got)
			}
			for _, field := range []string{"entries", "registered_methods", "effective_challenges", "additional_challenges"} {
				if got[field].([]string) == nil {
					t.Fatalf("%s must be a non-null array", field)
				}
			}
		})
	}
}

type profileAuthChallengeTestStore struct {
	ids.IdentityStore
	current           any
	readErr, writeErr error
	writes            int
	rules             []string
}

func (s *profileAuthChallengeTestStore) Request(op operator.Type, rr *requests.Request) error {
	switch op {
	case operator.GetUser:
		rr.Response.Payload = s.current
		return s.readErr
	case operator.OverwriteAuthChallengeRules:
		s.writes++
		s.rules = slices.Clone(rr.User.Challenges)
		return s.writeErr
	}
	return fmt.Errorf("unexpected operation")
}

func TestProfileAuthChallengeHandlers(t *testing.T) {
	for _, tc := range []struct {
		name              string
		fetch             bool
		body              map[string]any
		current           any
		readErr, writeErr error
		status, writes    int
	}{
		{name: "fetch", fetch: true, current: &identity.User{}, status: 200},
		{name: "reset", body: map[string]any{"challenges": []any{}}, current: &identity.User{AuthChallengeRules: []string{"password"}}, status: 200, writes: 1},
		{name: "set", body: map[string]any{"challenges": []any{"password"}}, current: &identity.User{}, status: 200, writes: 1},
		{name: "invalid body", body: map[string]any{"challenges": []any{"password", false}}, status: 400},
		{name: "unavailable", body: map[string]any{"challenges": []any{"u2f"}}, current: &identity.User{}, status: 400},
		{name: "stale read", fetch: true, readErr: identity.ErrIdentityRequestDenied, status: 401},
		{name: "binding denied", fetch: true, readErr: errProfileIdentity, status: 401},
		{name: "backend failure", fetch: true, readErr: errors.New("private-database-path"), status: 500},
		{name: "unexpected payload", fetch: true, current: "private-database-path", status: 500},
		{name: "nil payload", fetch: true, current: (*identity.User)(nil), status: 500},
		{name: "invalid saved policy", fetch: true, current: &identity.User{AuthChallengeRules: []string{"u2f"}}, status: 409},
		{name: "revoked before write", body: map[string]any{"challenges": []any{"password"}}, current: &identity.User{}, writeErr: identity.ErrIdentityRequestDenied, status: 401, writes: 1},
		{name: "failed persistence", body: map[string]any{"challenges": []any{"password"}}, current: &identity.User{}, writeErr: errors.New("private-database-path"), status: 500, writes: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := profileAuthChallengeTestPortal(t, nil)
			store := &profileAuthChallengeTestStore{current: tc.current, readErr: tc.readErr, writeErr: tc.writeErr}
			before, _ := json.Marshal(tc.current)
			usr := &user.User{Authenticator: user.Authenticator{Name: "database", Realm: "local", Method: "local"}}
			r := httptest.NewRequest(http.MethodPost, "https://portal.example.test/auth/api/profile", nil)
			rr, w, resp := requests.NewRequest(), httptest.NewRecorder(), map[string]any{}
			var err error
			if tc.fetch {
				err = p.FetchUserAuthChallenges(t.Context(), w, r, rr, usr, resp, usr, store)
			} else {
				err = p.OverwriteUserAuthChallenges(t.Context(), w, r, rr, usr, resp, usr, store, tc.body)
			}
			if err != nil || w.Code != tc.status || store.writes != tc.writes {
				t.Fatalf("status %d, writes %d, error %v", w.Code, store.writes, err)
			}
			if strings.Contains(w.Body.String(), "private-database-path") {
				t.Fatal("backend error leaked into response")
			}
			after, _ := json.Marshal(tc.current)
			if string(before) != string(after) {
				t.Fatal("validation mutated the original user snapshot")
			}
			if !tc.fetch && tc.status == 200 {
				if resp["reauthentication_required"] != true || store.rules == nil {
					t.Fatal("successful replacement omitted reset or fresh-login contract")
				}
			} else if _, ok := resp["reauthentication_required"]; ok {
				t.Fatal("failed or read operation reported successful mutation")
			}
		})
	}
}
