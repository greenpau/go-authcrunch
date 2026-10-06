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

	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
	"github.com/greenpau/go-authcrunch/plugins/claims-enrichment/static"
	"github.com/greenpau/go-authcrunch/plugins/claims-enrichment/static/parser"
)

func TestStaticParser(t *testing.T) {
	input := []string{"claim foo bar", cfgutil.EncodeArgs([]string{"claim", "message", "hello, world"}), cfgutil.EncodeArgs([]string{"claim", "empty", "json", `""`})}
	before := append([]string(nil), input...)
	config, err := parser.NewStaticClaimsEnrichmentConfigFromDirectives(input)
	if err != nil || !reflect.DeepEqual(config.Claims, map[string]any{"foo": "bar", "message": "hello, world", "empty": ""}) || !reflect.DeepEqual(input, before) {
		t.Fatal("literal values or input ownership lost", err)
	}
	serialized, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var restored static.Config
	if err := json.Unmarshal(serialized, &restored); err != nil || !reflect.DeepEqual(config, &restored) {
		t.Fatal("typed configuration did not round trip")
	}
	config.Claims["foo"] = "changed"
	again, err := parser.NewStaticClaimsEnrichmentConfigFromDirectives(input)
	if err != nil || again.Claims["foo"] != "bar" {
		t.Fatal("parser configurations share state")
	}
}

func TestStaticParserRejections(t *testing.T) {
	for _, statements := range [][]string{
		nil, {""}, {"claim foo"}, {"claim foo bar extra"}, {"unknown canary"},
		{"claim foo bar", "claim foo other"}, {"claim roles admin"},
		{"claim foo canary\nextra"}, {"claim foo canary\r"}, {"claim foo canary\x00"},
		{`claim foo "canary`}, {"failure enabled"}, {"delay 1s"}, {"record {}"},
	} {
		config, err := parser.NewStaticClaimsEnrichmentConfigFromDirectives(statements)
		if err == nil || config != nil || strings.Contains(err.Error(), "canary") {
			t.Fatal("invalid input accepted or disclosed")
		}
	}
}

func ExampleNewStaticClaimsEnrichmentConfigFromDirectives() {
	config, err := parser.NewStaticClaimsEnrichmentConfigFromDirectives([]string{"claim foo bar"})
	fmt.Println(config.Claims["foo"], err)
	// Output: bar <nil>
}

func TestStaticParserJSONValues(t *testing.T) {
	for _, tc := range []struct {
		name  string
		input string
		want  any
	}{
		{"string", `"hello, world"`, "hello, world"},
		{"boolean", "true", true},
		{"number", "9007199254740993", json.Number("9007199254740993")},
		{"fraction", "1.25", json.Number("1.25")},
		{"null", "null", nil},
		{"array", `["read",42,false,null,{"nested":["write"]}]`, []any{"read", json.Number("42"), false, nil, map[string]any{"nested": []any{"write"}}}},
		{"object", `{"active":true,"limit":5}`, map[string]any{"active": true, "limit": json.Number("5")}},
		{"escapes", `"line\n\twith spaces "`, "line\n\twith spaces "},
	} {
		t.Run(tc.name, func(t *testing.T) {
			statement := cfgutil.EncodeArgs([]string{"claim", "https://example.test/claims/custom", "json", tc.input})
			config, err := parser.NewStaticClaimsEnrichmentConfigFromDirectives([]string{statement})
			if err != nil || !reflect.DeepEqual(config.Claims["https://example.test/claims/custom"], tc.want) {
				t.Fatal("JSON value was not preserved", err)
			}
			encoded, err := json.Marshal(config)
			if err != nil {
				t.Fatal(err)
			}
			var restored static.Config
			decoder := json.NewDecoder(strings.NewReader(string(encoded)))
			decoder.UseNumber()
			if err := decoder.Decode(&restored); err != nil || !reflect.DeepEqual(restored.Claims, config.Claims) {
				t.Fatal("JSON round trip lost data")
			}
		})
	}
	for _, raw := range []string{"{", "true false", "NaN", "01", `{"a":}`, strings.Repeat(" ", 65537)} {
		config, err := parser.NewStaticClaimsEnrichmentConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"claim", "foo", "json", raw})})
		if err == nil || config != nil {
			t.Fatal("invalid JSON accepted")
		}
	}
}

func TestStaticParserRejectsInvalidUTF8(t *testing.T) {
	for _, raw := range []string{"\"canary-\xff\"", "{\"canary-\xff\":true}"} {
		config, err := parser.NewStaticClaimsEnrichmentConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"claim", "foo", "json", raw})})
		if err == nil || config != nil {
			t.Fatal("invalid UTF-8 was silently replaced while decoding configured claims")
		}
		if strings.Contains(err.Error(), "canary") {
			t.Fatal("parser exposed the rejected value")
		}
	}
}
