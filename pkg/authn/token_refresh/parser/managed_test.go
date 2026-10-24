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
	"slices"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	refreshparser "github.com/greenpau/go-authcrunch/pkg/authn/token_refresh/parser"
)

func TestTokenRefreshManagedStoreParser(t *testing.T) {
	base := []string{"realms local", "public origin https://login.test", "base path /auth"}
	statements := append(slices.Clone(base), "store durable")
	config, err := refreshparser.NewTokenRefreshConfigFromDirectives(statements)
	if err != nil || config.Store != "durable" {
		t.Fatal("single-word store selection did not parse")
	}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	var restored authn.TokenRefreshConfig
	if json.Unmarshal(data, &restored) != nil || restored.Validate() != nil || restored.Store != "durable" {
		t.Fatal("managed selector did not survive native configuration")
	}
	for _, extra := range [][]string{{"store"}, {"store durable other"}, {"store durable", "store other"}, {"disabled", "store durable"}, {"store bad\x00name"}, {"store bad\xffname"}, {"store durable\nstore other"}} {
		if _, err := refreshparser.NewTokenRefreshConfigFromDirectives(append(slices.Clone(base), extra...)); err == nil {
			t.Fatal("invalid managed selector accepted")
		}
	}
	omitted, err := refreshparser.NewTokenRefreshConfigFromDirectives(base)
	if err != nil || omitted.Store != "" {
		t.Fatal("omission lost legacy store selection")
	}
	disabled, err := refreshparser.NewTokenRefreshConfigFromDirectives([]string{"disabled"})
	if err != nil || disabled.Enabled || disabled.Store != "" {
		t.Fatal("legacy disabled block changed")
	}
}
