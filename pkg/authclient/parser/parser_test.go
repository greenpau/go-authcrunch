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

	"github.com/greenpau/go-authcrunch/pkg/authclient"
	"github.com/greenpau/go-authcrunch/pkg/authclient/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func statements(args ...[]string) []string {
	var result []string
	for _, arg := range args {
		result = append(result, cfgutil.EncodeArgs(arg))
	}
	return result
}

func base() []string {
	return statements([]string{"base", "url", "https://portal.test/auth/"}, []string{"username", " alice "}, []string{"realm", " local "})
}

func TestAuthenticationClientConfig(t *testing.T) {
	input := append(base(), statements(
		[]string{"password", ` pass, word "with quotes" `},
		[]string{"totp", "secret", "raw, secret"},
		[]string{"totp", "code", "length", "8"},
		[]string{"totp", "code", "lifetime", "45"},
		[]string{"access", "token", "name", "CUSTOM_ACCESS_TOKEN"},
		[]string{"refresh", "transport", "body"},
	)...)
	saved := append([]string(nil), input...)
	got, err := parser.NewAuthenticationClientConfigFromDirectives(input)
	if err != nil {
		t.Fatal(err)
	}
	want := &authclient.Config{BaseURL: "https://portal.test/auth", Username: "alice", Realm: "local", Password: ` pass, word "with quotes" `, TOTPSecret: "raw, secret", TOTPCodeLength: 8, TOTPCodeLifetime: 45, AccessTokenName: "CUSTOM_ACCESS_TOKEN", RefreshTransport: authclient.RefreshTransportBody}
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(input, saved) {
		t.Fatal("configuration or caller input changed unexpectedly")
	}
	payload, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	var reopened authclient.Config
	if err := json.Unmarshal(payload, &reopened); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Validate(); err != nil || !reflect.DeepEqual(&reopened, want) {
		t.Fatal("serialization lost settings")
	}
	second, err := parser.NewAuthenticationClientConfigFromDirectives(input)
	if err != nil {
		t.Fatal(err)
	}
	got.Password = "changed"
	if second.Password != want.Password {
		t.Fatal("parser results share state")
	}
	defaults, err := parser.NewAuthenticationClientConfigFromDirectives(base())
	if err != nil || defaults.RefreshTransport != authclient.RefreshTransportCookie || defaults.TOTPCodeLength != 6 || defaults.TOTPCodeLifetime != 30 || defaults.AccessTokenName != authclient.DefaultAccessTokenName {
		t.Fatal("typed defaults missing")
	}
	key, err := parser.NewAuthenticationClientConfigFromDirectives(statements([]string{"base", "url", "https://portal.test"}, []string{"realm", "local"}, []string{"api", "key", "fixture-api-key"}))
	if err != nil || key.APIKey != "fixture-api-key" || key.Username != "" {
		t.Fatal("API key configuration failed")
	}
}

func TestAuthenticationClientConfigRejectsDirectives(t *testing.T) {
	for _, args := range [][]string{
		{"unknown", "private-marker"}, {"refresh_transport", "private-marker"},
		{"refresh", "transport"}, {"refresh", "transport", "body", "private-marker"},
		{"refresh transport", "body"}, {"refresh", "transport", "private-marker"},
		{"totp", "code", "length", "private-marker"}, {"totp", "code", "length", "9999999999999999999999999999999999"},
		{"totp", "code", "length", "3"}, {"totp", "code", "lifetime", "-1"},
		{"access", "token", "name", "private-marker bad name"},
		{"password", " "}, {"password", "first", "private-marker"},
		{"api", "key", "private-marker"},
	} {
		t.Run(strings.Join(args[:len(args)-1], "/"), func(t *testing.T) {
			input := append(base(), cfgutil.EncodeArgs(args))
			result, err := parser.NewAuthenticationClientConfigFromDirectives(input)
			if result != nil || err == nil || strings.Contains(err.Error(), "private-marker") {
				t.Fatal("invalid input did not return a redacted error and nil configuration")
			}
		})
	}
	for _, raw := range []string{"", "password", "password,", "password,private-marker\nrealm,local", "password,private-marker\rrealm,local", "password,\"private-marker", "password,\xff"} {
		result, err := parser.NewAuthenticationClientConfigFromDirectives(append(base(), raw))
		if result != nil || err == nil || strings.Contains(err.Error(), "private-marker") {
			t.Fatal("malformed record accepted or leaked")
		}
	}
	for _, field := range [][]string{{"base", "url", "https://portal.test"}, {"username", "alice"}, {"realm", "local"}, {"password", "private-marker"}, {"api", "key", "private-marker"}, {"totp", "secret", "private-marker"}, {"totp", "code", "length", "6"}, {"totp", "code", "lifetime", "30"}, {"access", "token", "name", "CUSTOM_ACCESS_TOKEN"}, {"refresh", "transport", "cookie"}} {
		input := append(base(), cfgutil.EncodeArgs(field), cfgutil.EncodeArgs(field))
		got, err := parser.NewAuthenticationClientConfigFromDirectives(input)
		if got != nil || err == nil || strings.Contains(err.Error(), "private-marker") {
			t.Fatal("duplicate accepted or leaked")
		}
	}
	for _, input := range [][]string{nil, {}, statements([]string{"base", "url", "https://private-marker:secret@portal.test"}, []string{"username", "alice"}, []string{"realm", "local"})} {
		got, err := parser.NewAuthenticationClientConfigFromDirectives(input)
		if got != nil || err == nil || strings.Contains(err.Error(), "private-marker") {
			t.Fatal("invalid required settings accepted or leaked")
		}
	}
}

func ExampleNewAuthenticationClientConfigFromDirectives() {
	cfg, err := parser.NewAuthenticationClientConfigFromDirectives([]string{
		cfgutil.EncodeArgs([]string{"base", "url", "https://auth.example.com/auth"}),
		cfgutil.EncodeArgs([]string{"username", "alice"}),
		cfgutil.EncodeArgs([]string{"realm", "local"}),
		cfgutil.EncodeArgs([]string{"refresh", "transport", "body"}),
	})
	if err != nil {
		panic(err)
	}
	fmt.Println(cfg.BaseURL, cfg.RefreshTransport)
	// Output: https://auth.example.com/auth body
}
