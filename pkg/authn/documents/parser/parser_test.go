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

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func directives(lines ...[]string) []string {
	result := []string{}
	for _, line := range lines {
		result = append(result, cfgutil.EncodeArgs(line))
	}
	return result
}
func storageDirectives(lines ...[]string) []string {
	result := []string{}
	for _, line := range lines {
		result = append(result, cfgutil.EncodeArgs(append([]string{"documents", "api"}, line...)))
	}
	return result
}
func TestDocumentsDirectives(t *testing.T) {
	storage := storageDirectives([]string{"database", "/private/documents.db"}, []string{"public", "origin", "https://portal.example.test"}, []string{"base", "path", "/auth"}, []string{"realms", "local"})
	for _, input := range [][]string{nil, storage, directives([]string{"disable", "documents", "api"})} {
		c, err := parser.NewDocumentsAPIConfigFromDirectives(input)
		if err != nil || c == nil || c.Enabled {
			t.Fatal("Documents must default to disabled", err)
		}
	}
	base := append(directives([]string{"enable", "documents", "api"}), storage...)
	c, err := parser.NewDocumentsAPIConfigFromDirectives(base)
	if err != nil || !c.Enabled || c.Storage.BasePath != "/auth" || c.Storage.MaxFileBytes != 268435456 {
		t.Fatal("explicit enable failed", err)
	}
	reversed := append(append([]string(nil), storage...), base[0])
	r, err := parser.NewDocumentsAPIConfigFromDirectives(reversed)
	if err != nil || !reflect.DeepEqual(c, r) {
		t.Fatal("directive order changed configuration")
	}
	for _, extra := range [][]string{{"public", "origin", "https://another.test"}, {"database", "/other"}, {"realms", "other"}, {"max", "file", "bytes", "-1"}, {"max", "file", "bytes", "1.5"}, {"max_file_bytes", "42"}, {"enabled", "true"}, {"unsupported", "42"}, {"base", "path"}} {
		if got, err := parser.NewDocumentsAPIConfigFromDirectives(append(append([]string(nil), base...), storageDirectives(extra)...)); err == nil || got != nil {
			t.Fatal("invalid directive accepted")
		}
	}
	for _, extra := range []string{"enable documents api\ndisable documents api", "", "\"bad", "enabled", "database /private/documents.db", "enable documents api true", "enable admin api", "disable documents api", "enable documents api"} {
		if got, err := parser.NewDocumentsAPIConfigFromDirectives(append(append([]string(nil), base...), extra)); err == nil || got != nil {
			t.Fatal("malformed or duplicate record accepted")
		}
	}
	if got, err := parser.NewDocumentsAPIConfigFromDirectives(directives([]string{"enable", "documents", "api"})); err == nil || got != nil {
		t.Fatal("enabled API without storage accepted")
	}
	limits := storageDirectives([]string{"max", "file", "bytes", "64"}, []string{"max", "user", "bytes", "128"}, []string{"max", "total", "bytes", "256"}, []string{"max", "user", "files", "2"}, []string{"max", "total", "files", "3"}, []string{"max", "keys", "4"}, []string{"max", "recipients", "1"}, []string{"upload", "ttl", "seconds", "120"})
	got, err := parser.NewDocumentsAPIConfigFromDirectives(append(base, limits...))
	if err != nil || got.Storage.MaxKeys != 4 || got.Storage.MaxTotalFiles != 3 || got.Storage.MaxRecipients != 1 || got.Storage.UploadTTLSeconds != 120 {
		t.Fatal("limits not applied", err)
	}
	marker := "secret-setting-must-not-leak"
	if got, err := parser.NewDocumentsAPIConfigFromDirectives(directives([]string{"documents", "api", "unknown", marker})); err == nil || got != nil || strings.Contains(err.Error(), marker) {
		t.Fatal("invalid directive error exposed input")
	}
}
func ExampleNewDocumentsAPIConfigFromDirectives() {
	config, err := parser.NewDocumentsAPIConfigFromDirectives([]string{
		cfgutil.EncodeArgs([]string{"enable", "documents", "api"}),
		cfgutil.EncodeArgs([]string{"documents", "api", "database", "/private/documents.db"}),
		cfgutil.EncodeArgs([]string{"documents", "api", "public", "origin", "https://portal.example.test"}),
		cfgutil.EncodeArgs([]string{"documents", "api", "base", "path", "/auth"}),
		cfgutil.EncodeArgs([]string{"documents", "api", "realms", "local"}),
	})
	if err != nil {
		panic(err)
	}
	portal := &authn.PortalConfig{API: &authn.APIConfig{ProfileEnabled: true}}
	if err := portal.ConfigureDocumentsAPI(config); err != nil {
		panic(err)
	}
	fmt.Println(portal.API.DocumentsEnabled, portal.API.ProfileEnabled, portal.API.AdminEnabled, portal.Documents.MaxFileBytes)
	// Output: true true false 268435456
}

func TestDocumentsDirectiveKeywordTokens(t *testing.T) {
	for _, args := range [][]string{
		{"public origin", "https://portal.example.test"},
		{"base path", "/auth"},
		{"max file", "bytes", "256"},
		{"max", "user bytes", "512"},
		{"max total bytes", "1024"},
		{"upload ttl", "seconds", "60"},
	} {
		t.Run(args[0], func(t *testing.T) {
			settings, err := parser.NewDocumentsAPIConfigFromDirectives(storageDirectives(args))
			if err == nil || settings != nil {
				t.Fatal("combined keyword token accepted")
			}
		})
	}
	settings, err := parser.NewDocumentsAPIConfigFromDirectives(storageDirectives([]string{"database", "/private/path with spaces/documents.db"}))
	if err != nil || settings.Storage.Database != "/private/path with spaces/documents.db" {
		t.Fatal("quoted value with spaces rejected", err)
	}
}
