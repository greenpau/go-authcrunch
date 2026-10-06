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
	"reflect"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authz/enrichment/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func directives() []string {
	return []string{"source directory", "version v1", "audience api", "attribute enrichment.access string list", "issuer issuer", "realm realm", "subject claim immutable_id", "tenant claim tenant", "max age 1m", "timeout 250ms"}
}

func TestParser(t *testing.T) {
	input := directives()
	before := append([]string(nil), input...)
	c, err := parser.NewClaimsEnrichmentConfigFromDirectives(input)
	if err != nil || c == nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, input) {
		t.Fatal("parser mutated input")
	}
	for _, bad := range []string{"", "source", "source duplicate", "unknown canary-value", "failure true", "attribute roles string", "attribute enrichment.access string list", "attribute enrichment.other number", "source canary\nextra", "source canary\r", "source canary\x00", `source "unterminated`, "attribute enrichment.other string list extra", "attribute enrichment.other", "delay -1s"} {
		if got, err := parser.NewClaimsEnrichmentConfigFromDirectives(append(directives(), bad)); err == nil || got != nil {
			t.Errorf("invalid directive accepted (%q)", strings.Split(bad, " ")[0])
		} else if strings.Contains(err.Error(), "canary") {
			t.Fatal("parser disclosed input")
		}
	}
	if got, err := parser.NewClaimsEnrichmentConfigFromDirectives(nil); err == nil || got != nil {
		t.Fatal("incomplete configuration accepted")
	}
	input = directives()
	input[0] = cfgutil.EncodeArgs([]string{"source", "directory, with spaces"})
	c, err = parser.NewClaimsEnrichmentConfigFromDirectives(input)
	if err != nil || c.Source != "directory, with spaces" {
		t.Fatal("quoted token boundary lost")
	}
	c.Attributes[0].Name = "changed"
	other, err := parser.NewClaimsEnrichmentConfigFromDirectives(directives())
	if err != nil || other.Attributes[0].Name != "enrichment.access" {
		t.Fatal("parser results share state")
	}
}

func ExampleNewClaimsEnrichmentConfigFromDirectives() {
	c, err := parser.NewClaimsEnrichmentConfigFromDirectives([]string{"source directory", "version v1", "audience api", "attribute enrichment.access string list", "issuer issuer", "realm realm", "subject claim immutable_id", "tenant claim tenant", "max age 1m", "timeout 250ms"})
	fmt.Println(c.Source, c.Attributes[0].Type, c.Timeout, err)
	// Output: directory string_list 250ms <nil>
}

func TestJSONAndLiteralClaimDeclarations(t *testing.T) {
	input := directives()
	input = append(input, "attribute settings json", cfgutil.EncodeArgs([]string{"attribute", "https://example.test/claims/feature", "json"}))
	config, err := parser.NewClaimsEnrichmentConfigFromDirectives(input)
	if err != nil || config.Attributes[1].Type != "json" || config.Attributes[2].Name != "https://example.test/claims/feature" {
		t.Fatal("JSON or literal claim declaration rejected", err)
	}
	for _, bad := range []string{"attribute settings json list", "attribute immutable_id json", "attribute tenant json", "attribute github_id json", "attribute roles json"} {
		if result, err := parser.NewClaimsEnrichmentConfigFromDirectives(append(directives(), bad)); result != nil || err == nil {
			t.Fatal("unsafe attribute declaration accepted")
		}
	}
}
