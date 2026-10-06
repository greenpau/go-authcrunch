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
	"strings"
	"testing"

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	signing "github.com/greenpau/go-authcrunch/plugins/cryptographic-signing/rsapss"
	"github.com/greenpau/go-authcrunch/plugins/cryptographic-signing/rsapss/parser"
)

func directives() []string {
	return []string{cfgutil.EncodeArgs([]string{"key", "file", "/missing/private key.pem"}), "key id key-v1", "issuer https://issuer.example.test/auth", "audience api"}
}

func TestParser(t *testing.T) {
	cfg, err := parser.NewRSAPSSSigningConfigFromDirectives(directives())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.KeyFile != "/missing/private key.pem" || cfg.KeyID != "key-v1" || cfg.Algorithm != "PS256" || cfg.MaxLifetime != "15m" {
		t.Fatal("incorrect configuration")
	}
	// Parsing validates without accessing the deliberately nonexistent key file.
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var restored signing.Config
	if json.Unmarshal(data, &restored) != nil || restored != *cfg {
		t.Fatal("config serialization changed")
	}
	cfg, err = parser.NewRSAPSSSigningConfigFromDirectives(append(directives(), "algorithm PS256", "max lifetime 5m"))
	if err != nil || cfg.MaxLifetime != "5m" {
		t.Fatal("explicit settings rejected")
	}
	invalid := []string{"", "key", "key file", "key file a b", "key unknown secret", "max unknown secret", "issuer a b", "algorithm RS256", "algorithm ps256", "max lifetime 500ms", "unknown secret", "audience secret", "key id duplicate", "key file duplicate", "issuer duplicate", "issuer secret\nvalue", "audience \xff", "audience \x00", `audience "unterminated`, `audience ""`}
	for i, line := range invalid {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			cfg, err := parser.NewRSAPSSSigningConfigFromDirectives(append(directives(), line))
			if err == nil || cfg != nil || strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "unterminated") {
				t.Fatal("invalid directive accepted or disclosed")
			}
		})
	}
	for _, lines := range [][]string{nil, {}, {"key file a"}, append(directives(), "algorithm PS256", "algorithm PS256"), append(directives(), "max lifetime 5m", "max lifetime 5m")} {
		if cfg, err := parser.NewRSAPSSSigningConfigFromDirectives(lines); err == nil || cfg != nil {
			t.Fatal("incomplete or repeated config accepted")
		}
	}
}

func ExampleNewRSAPSSSigningConfigFromDirectives() {
	cfg, err := parser.NewRSAPSSSigningConfigFromDirectives([]string{
		"key file /run/keys/access.pem", "key id access-v1", "issuer https://login.example.test/auth", "audience api", "max lifetime 5m",
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(cfg.Algorithm, cfg.KeyID, cfg.MaxLifetime)
	// Output: PS256 access-v1 5m
}
