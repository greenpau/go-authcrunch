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

package parser_test

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/authz/oauth/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestOAuthAuthorizationDirectives(t *testing.T) {
	for _, tc := range []struct {
		name    string
		lines   [][]string
		wantErr bool
	}{
		{"defaults", [][]string{{"use", "oauth", "identity", "provider", "company"}}, false},
		{"complete", [][]string{{"use", "oauth", "identity", "provider", "company"}, {"oauth", "public", "origin", "https://app.example.test/"}, {"oauth", "base", "path", "/app/oauth"}, {"oauth", "session", "cookie", "name", "session"}, {"oauth", "login", "cookie", "name", "login"}, {"oauth", "session", "lifetime", "60"}, {"oauth", "maximum", "sessions", "2"}, {"oauth", "maximum", "pending", "logins", "3"}}, false},
		{"unknown", [][]string{{"secret", "must-not-appear"}}, true},
		{"missing provider", [][]string{{"oauth", "session", "lifetime", "60"}}, true},
		{"duplicate", [][]string{{"use", "oauth", "identity", "provider", "a"}, {"use", "oauth", "identity", "provider", "b"}}, true},
		{"quoted keywords", [][]string{{"use oauth", "identity", "provider", "company"}}, true},
		{"empty value", [][]string{{"use", "oauth", "identity", "provider", ""}}, true},
		{"arity", [][]string{{"use", "oauth", "identity", "provider", "a", "b"}}, true},
		{"zero", [][]string{{"oauth", "maximum", "sessions", "0"}}, true},
		{"negative", [][]string{{"oauth", "session", "lifetime", "-1"}}, true},
		{"fraction", [][]string{{"oauth", "session", "lifetime", "1.5"}}, true},
		{"overflow", [][]string{{"oauth", "maximum", "pending", "logins", "99999999999999999999"}}, true},
		{"bounds", [][]string{{"use", "oauth", "identity", "provider", "a"}, {"oauth", "maximum", "sessions", "65537"}}, true},
		{"collision", [][]string{{"use", "oauth", "identity", "provider", "a"}, {"oauth", "session", "cookie", "name", "same"}, {"oauth", "login", "cookie", "name", "same"}}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var statements []string
			for _, args := range tc.lines {
				statements = append(statements, cfgutil.EncodeArgs(args))
			}
			original := append([]string(nil), statements...)
			got, err := parser.NewOAuthAuthorizationConfigFromDirectives("policy", statements)
			if (err != nil) != tc.wantErr {
				t.Fatalf("error presence %v, want %v", err != nil, tc.wantErr)
			}
			if err != nil {
				if got != nil || strings.Contains(err.Error(), "must-not-appear") {
					t.Fatal("partial config or unredacted error")
				}
				return
			}
			if !reflect.DeepEqual(statements, original) {
				t.Fatal("modified parser inputs")
			}
			b, err := json.Marshal(got)
			if err != nil {
				t.Fatal(err)
			}
			var restored authz.OAuthAuthorizationConfig
			if err = json.Unmarshal(b, &restored); err != nil {
				t.Fatal(err)
			}
			if err = restored.Validate("policy"); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, &restored) {
				t.Fatal("configuration changed on reload")
			}
			if tc.name == "complete" && (got.PublicOrigin != "https://app.example.test" || got.CallbackPath() != "/app/oauth/authorization-code-callback" || got.SessionLifetime != 60 || got.MaxSessions != 2 || got.MaxPendingLogins != 3 || got.SessionCookieName != "session" || got.LoginCookieName != "login") {
				t.Fatal("settings lost")
			}
		})
	}
	for _, statement := range []string{"use oauth identity provider a\nsecret", "use oauth identity provider a\rsecret", `"unterminated`} {
		got, err := parser.NewOAuthAuthorizationConfigFromDirectives("policy", []string{statement})
		if got != nil || err == nil {
			t.Fatal("malformed statement accepted")
		}
	}
	got, err := parser.NewOAuthAuthorizationConfigFromDirectives("policy", nil)
	if got != nil || err != nil {
		t.Fatal("omitted config must disable")
	}
}

func ExampleNewOAuthAuthorizationConfigFromDirectives() {
	c, err := parser.NewOAuthAuthorizationConfigFromDirectives("linkedin_policy", []string{cfgutil.EncodeArgs([]string{"use", "oauth", "identity", "provider", "linkedin"})})
	if err != nil {
		panic(err)
	}
	fmt.Println(c.IdentityProvider)
	fmt.Println(c.CallbackPath())
	fmt.Println(c.SessionLifetime)
	// Output:
	// linkedin
	// /_authcrunch/oauth2/linkedin_policy/authorization-code-callback
	// 900
}
