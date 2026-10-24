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
	"github.com/greenpau/go-authcrunch/pkg/kms/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"slices"
	"testing"
)

func TestAccessTokenProfileParser(t *testing.T) {
	good := []string{"issuer https://login.example.test/auth", "audience api", "key ids current retiring", "max lifetime 300"}
	cfg, err := parser.NewAccessTokenProfileConfigFromDirectives(good)
	if err != nil || cfg.Issuer != "https://login.example.test/auth" || !slices.Equal(cfg.KeyIDs, []string{"current", "retiring"}) {
		t.Fatal("complete profile failed", err)
	}
	for name, input := range map[string][]string{"missing": good[:3], "duplicate": append(slices.Clone(good), good[0]), "unknown": append(slices.Clone(good), "issuer alias x"), "newline": append(slices.Clone(good[:3]), "max lifetime 300\nissuer https://other.test"), "carriage return": append(slices.Clone(good[:3]), "max lifetime 300\r"), "nul": append(slices.Clone(good[:3]), "max lifetime 300\x00"), "utf8": append(slices.Clone(good[:3]), string([]byte{255})), "duplicate id": {good[0], good[1], "key ids current current", good[3]}, "opaque issuer": {"issuer opaque", good[1], good[2], good[3]}, "duration": {good[0], good[1], good[2], "max lifetime 5m"}} {
		t.Run(name, func(t *testing.T) {
			if _, err := parser.NewAccessTokenProfileConfigFromDirectives(input); err == nil {
				t.Fatal("invalid complete body accepted")
			}
		})
	}
	input := slices.Clone(good)
	input[1] = cfgutil.EncodeArgs([]string{"audience", "an application"})
	cfg, err = parser.NewAccessTokenProfileConfigFromDirectives(input)
	if err != nil || cfg.Audience != "an application" {
		t.Fatal("encoded value changed")
	}
}

func ExampleNewAccessTokenProfileConfigFromDirectives() {
	profile, err := parser.NewAccessTokenProfileConfigFromDirectives([]string{"issuer https://login.example.test/auth", "audience api", "key ids retiring current", "max lifetime 300"})
	if err != nil {
		panic(err)
	}
	fmt.Println(profile.Issuer, profile.Audience, profile.KeyIDs, profile.MaxLifetimeSeconds)
	// Output: https://login.example.test/auth api [current retiring] 300
}
