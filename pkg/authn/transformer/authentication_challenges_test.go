// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"errors"
	"fmt"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/transformer"
)

func TestAuthenticationChallengeSelection(t *testing.T) {
	chain := []string{"require auth challenges u2f", "require auth challenges password totp if u2f not available", "require auth challenges password if u2f and totp not available", "require mfa"}
	for _, tc := range []struct {
		methods []string
		want    string
	}{{[]string{"password", "u2f", "totp"}, "[u2f]"}, {[]string{"password", "totp"}, "[password totp]"}, {[]string{"password"}, "[password]"}, {nil, ""}} {
		t.Run(fmt.Sprint(tc.methods), func(t *testing.T) {
			factory, err := transformer.NewFactory([]*transformer.Config{{Matchers: []string{"match realm local"}, Actions: chain}})
			if err != nil {
				t.Fatal(err)
			}
			claims := map[string]any{"realm": "local", "auth_methods": []string{"u2f"}, "challenges": []string{"forged"}}
			selected, err := factory.TransformWithAuthMethods(claims, tc.methods)
			if tc.want == "" {
				if !errors.Is(err, transformer.ErrAuthChallengesUnavailable) {
					t.Fatal("missing evidence accepted", err)
				}
				return
			}
			if err != nil || fmt.Sprint(selected) != tc.want {
				t.Fatal("incorrect selection", selected, err)
			}
			if fmt.Sprint(claims["challenges"]) != "[mfa]" {
				t.Fatal("legacy requirement lost")
			}
			if _, ok := claims["auth_methods"]; ok {
				t.Fatal("inventory leaked")
			}
		})
	}
}

func TestAuthenticationChallengeTransformOrdering(t *testing.T) {
	configs := []*transformer.Config{
		{Matchers: []string{"match realm local"}, Actions: []string{"require auth challenges u2f"}},
		{Matchers: []string{"match realm local"}, Actions: []string{"require auth challenges password", "add role app/user"}},
	}
	factory, err := transformer.NewFactory(configs)
	if err != nil {
		t.Fatal(err)
	}
	for _, methods := range [][]string{{"password"}, {"password", "u2f"}} {
		claims := map[string]any{"realm": "local", "auth_methods": methods}
		if err := factory.Transform(claims); err != nil {
			t.Fatal(err)
		}
		want := "[password]"
		if len(methods) > 1 {
			want = "[u2f]"
		}
		if fmt.Sprint(claims["challenges"]) != want || fmt.Sprint(claims["roles"]) != "[app/user]" {
			t.Fatal("first eligible rule or later action lost")
		}
	}
	configs = append(configs, &transformer.Config{Matchers: []string{"match realm local"}, Actions: []string{"deny"}})
	factory, err = transformer.NewFactory(configs)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := factory.TransformWithAuthMethods(map[string]any{"realm": "local"}, []string{"password"}); err == nil {
		t.Fatal("selection bypassed later deny")
	}
	if _, err := factory.TransformWithAuthMethods(map[string]any{"realm": "other"}, nil); err != nil {
		t.Fatal("unmatched policy affected other realm", err)
	}
}
