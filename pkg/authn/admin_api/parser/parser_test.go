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
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	adminparser "github.com/greenpau/go-authcrunch/pkg/authn/admin_api/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestNewAdminAPIConfigFromDirectives(t *testing.T) {
	for _, tc := range []struct {
		name       string
		directives [][]string
		want       authn.AdminAPIConfig
	}{
		{name: "omitted"},
		{name: "empty", directives: [][]string{}},
		{name: "admin enabled", directives: [][]string{{"enable", "admin", "api"}}, want: authn.AdminAPIConfig{Enabled: true}},
		{name: "admin disabled", directives: [][]string{{"disable", "admin", "api"}}},
		{name: "export enabled", directives: [][]string{{"enable", "admin", "api", "private", "key", "export"}}, want: authn.AdminAPIConfig{FetchPrivateKeysEnabled: true}},
		{name: "export disabled", directives: [][]string{{"disable", "admin", "api", "private", "key", "export"}}},
		{
			name: "both enabled",
			directives: [][]string{
				{"enable", "admin", "api"},
				{"enable", "admin", "api", "private", "key", "export"},
			},
			want: authn.AdminAPIConfig{Enabled: true, FetchPrivateKeysEnabled: true},
		},
		{
			name: "both disabled",
			directives: [][]string{
				{"disable", "admin", "api"},
				{"disable", "admin", "api", "private", "key", "export"},
			},
		},
		{
			name: "admin enabled export disabled",
			directives: [][]string{
				{"enable", "admin", "api"},
				{"disable", "admin", "api", "private", "key", "export"},
			},
			want: authn.AdminAPIConfig{Enabled: true},
		},
		{
			name: "export does not enable admin",
			directives: [][]string{
				{"disable", "admin", "api"},
				{"enable", "admin", "api", "private", "key", "export"},
			},
			want: authn.AdminAPIConfig{FetchPrivateKeysEnabled: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var statements []string
			if tc.directives != nil {
				statements = make([]string, 0, len(tc.directives))
			}
			for _, args := range tc.directives {
				statements = append(statements, cfgutil.EncodeArgs(args))
			}
			original := slices.Clone(statements)
			got, err := adminparser.NewAdminAPIConfigFromDirectives(statements)
			if err != nil || got == nil || *got != tc.want {
				t.Fatalf("configuration = %+v, error = %v; want %+v", got, err, tc.want)
			}
			if !slices.Equal(statements, original) {
				t.Fatal("parser changed input directives")
			}
			// Independent settings must also work in the opposite order.
			slices.Reverse(statements)
			reversed, err := adminparser.NewAdminAPIConfigFromDirectives(statements)
			if err != nil || reversed == nil || *reversed != tc.want {
				t.Fatal("directive order changed the resulting configuration")
			}
		})
	}
}

func TestNewAdminAPIConfigFromDirectivesGrammar(t *testing.T) {
	for _, tc := range []struct {
		name, statement, kind string
	}{
		{"empty", "", "invalid"},
		{"whitespace", " \t ", "invalid"},
		{"missing subject", "enable", "invalid"},
		{"missing api", "enable admin", "invalid"},
		{"missing export", "enable admin api private key", "invalid"},
		{"unknown action", "enabled admin api", "unsupported"},
		{"boolean action", "true admin api", "unsupported"},
		{"numeric action", "1 admin api", "unsupported"},
		{"boolean value", "enable admin api true", "invalid"},
		{"export boolean value", "enable admin api private key export true", "invalid"},
		{"underscore key", "enable admin_api true", "unsupported"},
		{"serialized key", "admin_fetch_private_keys_enabled true", "invalid"},
		{"profile api", "enable profile api", "unsupported"},
		{"unknown api", "enable admin other", "unsupported"},
		{"unknown option", "enable admin api public key export", "unsupported"},
		{"unknown key", "enable admin api private certificate export", "unsupported"},
		{"unknown operation", "enable admin api private key import", "unsupported"},
		{"case sensitive", "Enable admin api", "unsupported"},
		{"block header", "admin api {", "unsupported"},
		{"block end", "}", "invalid"},
		{"extra argument", "enable admin api unexpected", "invalid"},
		{"trailing comment", "enable admin api # comment", "invalid"},
		{"empty interior argument", "enable  admin api", "invalid"},
		{"empty quoted argument", `enable admin ""`, "unsupported"},
		{"empty trailing argument", `enable admin api ""`, "invalid"},
		{"grouped subject", cfgutil.EncodeArgs([]string{"enable", "admin api", "private key export"}), "unsupported"},
		{"grouped directive", cfgutil.EncodeArgs([]string{"enable admin api"}), "invalid"},
		{"unclosed quote", `enable admin "api`, "invalid"},
		{"bare quote", `enable adm"in api`, "invalid"},
		{"tab inside keyword", "enable adm\tin api", "unsupported"},
		{"NUL inside keyword", "enable adm\x00in api", "unsupported"},
		{"multiple records", "enable admin api\ndisable admin api", "invalid"},
		{"CRLF records", "enable admin api\r\ndisable admin api", "invalid"},
		{"trailing newline", "enable admin api\n", "invalid"},
		{"leading carriage return", "\renable admin api", "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Also verify failure after a valid directive: never return a partial
			// enabled configuration which a consumer could accidentally apply.
			for _, prefix := range [][]string{nil, {"enable admin api"}} {
				statements := append(slices.Clone(prefix), tc.statement)
				got, err := adminparser.NewAdminAPIConfigFromDirectives(statements)
				want := fmt.Sprintf("%s admin API directive at line %d", tc.kind, len(statements))
				if got != nil || err == nil || err.Error() != want {
					t.Fatalf("configuration = %+v, error = %v; want nil and %q", got, err, want)
				}
			}
		})
	}
	// CSV quoting of individual keywords retains token boundaries and is valid.
	got, err := adminparser.NewAdminAPIConfigFromDirectives([]string{`"enable" "admin" "api"`})
	if err != nil || got == nil || !got.Enabled || got.FetchPrivateKeysEnabled {
		t.Fatal("separately quoted keywords did not preserve the directive")
	}
}

func TestNewAdminAPIConfigFromDirectivesDuplicates(t *testing.T) {
	for _, setting := range []string{"admin api", "admin api private key export"} {
		for _, first := range []string{"enable", "disable"} {
			for _, second := range []string{"enable", "disable"} {
				t.Run(setting+"/"+first+"/"+second, func(t *testing.T) {
					got, err := adminparser.NewAdminAPIConfigFromDirectives([]string{first + " " + setting, second + " " + setting})
					want := "duplicate admin API setting " + setting + " at line 2"
					if got != nil || err == nil || err.Error() != want {
						t.Fatalf("configuration = %+v, error = %v; want nil and %q", got, err, want)
					}
				})
			}
		}
	}
}

func TestNewAdminAPIConfigFromDirectivesErrorRedaction(t *testing.T) {
	const sensitive = "synthetic-sensitive-argument"
	for _, statement := range []string{"enable admin api", "enable admin api private key export"} {
		args := strings.Fields(statement)
		for i := range args {
			input := slices.Clone(args)
			input[i] = sensitive
			got, err := adminparser.NewAdminAPIConfigFromDirectives([]string{cfgutil.EncodeArgs(input)})
			if got != nil || err == nil || strings.Contains(err.Error(), sensitive) {
				t.Fatal("unexpected argument must fail without disclosing its value")
			}
		}
	}
}

func TestNewAdminAPIConfigFromDirectivesIndependentConfigurations(t *testing.T) {
	statements := []string{"enable admin api", "enable admin api private key export"}
	first, err := adminparser.NewAdminAPIConfigFromDirectives(statements)
	if err != nil {
		t.Fatal(err)
	}
	first.Enabled, first.FetchPrivateKeysEnabled = false, false
	second, err := adminparser.NewAdminAPIConfigFromDirectives(statements)
	if err != nil || second == nil || !second.Enabled || !second.FetchPrivateKeysEnabled {
		t.Fatal("mutating an earlier result changed a subsequent configuration")
	}
	defaults, err := adminparser.NewAdminAPIConfigFromDirectives(nil)
	if err != nil || defaults == nil || *defaults != (authn.AdminAPIConfig{}) {
		t.Fatal("omitted directives inherited previously enabled settings")
	}
}

func ExampleNewAdminAPIConfigFromDirectives() {
	admin, err := adminparser.NewAdminAPIConfigFromDirectives([]string{
		cfgutil.EncodeArgs([]string{"enable", "admin", "api"}),
		cfgutil.EncodeArgs([]string{"enable", "admin", "api", "private", "key", "export"}),
	})
	if err != nil {
		panic(err)
	}
	// Apply the admin settings without changing existing profile access.
	portal := &authn.PortalConfig{API: &authn.APIConfig{ProfileEnabled: true}}
	if err := portal.ConfigureAdminAPI(admin); err != nil {
		panic(err)
	}
	fmt.Println(portal.API.ProfileEnabled, portal.API.AdminEnabled, portal.API.AdminFetchPrivateKeysEnabled)
	// Output:
	// true true true
}
