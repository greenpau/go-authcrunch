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

package transformer_test

import (
	"reflect"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
	"github.com/greenpau/go-authcrunch/pkg/authn/transformer/parser"
)

func TestUserTransformerNestedClaimCollision(t *testing.T) {
	cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{"match realm local", "add nested context flow with totp as string", "require auth challenges totp"})
	if err != nil {
		t.Fatal(err)
	}
	f, err := transformer.NewFactory([]*transformer.Config{cfg})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		value any
	}{
		{"string", "text"}, {"number", 3}, {"list", []string{"role"}}, {"null", nil}, {"nil map", map[string]any(nil)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("claim collision panicked: %v", v)
				}
			}()
			claims := map[string]any{"realm": "local", "context": tc.value}
			if selected, err := f.TransformWithAuthMethods(claims, []string{"password", "totp"}); err == nil || selected != nil {
				t.Fatal("invalid nested parent authorized a policy")
			}
		})
	}
	claims := map[string]any{"realm": "local", "context": map[string]any{"existing": "preserved"}}
	if _, err := f.TransformWithAuthMethods(claims, []string{"totp"}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(claims["context"], map[string]any{"existing": "preserved", "flow": "totp"}) {
		t.Fatal("valid nested map not updated")
	}
}

func TestUserTransformerClaimValuesAreLiteral(t *testing.T) {
	cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{"match realm local", "add display_name {claims.name} as string", "require auth challenges password"})
	if err != nil {
		t.Fatal(err)
	}
	f, err := transformer.NewFactory([]*transformer.Config{cfg})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, value string }{
		{"braces", "}}{claims.sub}"},
		{"indirection", "{claims.sub}"},
		{"self reference", "{claims.name}"},
		{"growing reference", "x{claims.name}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if v := recover(); v != nil {
					t.Errorf("claim value panicked: %v", v)
				}
			}()
			claims := map[string]any{"realm": "local", "name": tc.value, "sub": "alice"}
			if _, err := f.TransformWithAuthMethods(claims, []string{"password"}); err != nil {
				t.Fatal(err)
			}
			if claims["display_name"] != tc.value {
				t.Fatal("claim value was evaluated as another template")
			}
		})
	}
}

func TestUserTransformerPreservesExistingClaimText(t *testing.T) {
	cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{"match realm local", "add name suffix", "add role stable", "add label prefix-{claims.sub}-{claims.sub} as string"})
	if err != nil {
		t.Fatal(err)
	}
	f, err := transformer.NewFactory([]*transformer.Config{cfg})
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"realm": "local", "name": "{claims.name}", "roles": []string{"{claims.sub}"}, "sub": "alice"}
	if err := f.Transform(claims); err != nil {
		t.Fatal(err)
	}
	if claims["name"] != "{claims.name} suffix" || !reflect.DeepEqual(claims["roles"], []string{"{claims.sub}", "stable"}) || claims["label"] != "prefix-alice-alice" {
		t.Fatal("existing data or repeated placeholders changed")
	}
}

func FuzzUserTransformerLiteralClaims(f *testing.F) {
	for _, value := range []string{"Alice", "{claims.name}", "x{claims.name}", "}}{claims.sub}", "{claims.missing}"} {
		f.Add(value)
	}
	cfg, err := parser.NewUserTransformerConfigFromDirectives([]string{"match realm local", "add display_name {claims.name} as string", "add name suffix", "add role stable"})
	if err != nil {
		f.Fatal(err)
	}
	factory, err := transformer.NewFactory([]*transformer.Config{cfg})
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			t.Skip()
		}
		claims := map[string]any{"realm": "local", "name": value, "roles": []string{"{claims.name}"}}
		if err := factory.Transform(claims); err != nil {
			t.Fatal(err)
		}
		if claims["display_name"] != value || claims["name"] != value+" suffix" || !reflect.DeepEqual(claims["roles"], []string{"{claims.name}", "stable"}) {
			t.Fatal("claim text was evaluated")
		}
	})
}
