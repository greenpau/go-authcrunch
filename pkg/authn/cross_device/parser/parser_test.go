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

	"github.com/greenpau/go-authcrunch/pkg/authn"
	parser "github.com/greenpau/go-authcrunch/pkg/authn/cross_device/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func TestCrossDeviceLoginParser(t *testing.T) {
	for _, tc := range []struct {
		name         string
		in           []string
		enabled, bad bool
	}{
		{name: "omitted"}, {name: "empty", in: []string{}},
		{name: "enabled", in: []string{"enable cross-device login"}, enabled: true},
		{name: "disabled", in: []string{"disable cross-device login"}},
		{name: "encoded", in: []string{cfgutil.EncodeArgs([]string{"enable", "cross-device", "login"})}, enabled: true},
		{name: "duplicate", in: []string{"enable cross-device login", "enable cross-device login"}, bad: true},
		{name: "conflict", in: []string{"enable cross-device login", "disable cross-device login"}, bad: true},
		{name: "missing", in: []string{"enable cross-device"}, bad: true},
		{name: "extra", in: []string{"enable cross-device login secret-value"}, bad: true},
		{name: "unknown", in: []string{"secret-value cross-device login"}, bad: true},
		{name: "quoted keywords", in: []string{cfgutil.EncodeArgs([]string{"enable", "cross-device login"})}, bad: true},
		{name: "multiline", in: []string{"enable cross-device login\nsecret-value"}, bad: true},
		{name: "CR", in: []string{"enable cross-device login\r"}, bad: true},
		{name: "empty record", in: []string{""}, bad: true},
		{name: "malformed", in: []string{`"secret-value`}, bad: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := append([]string(nil), tc.in...)
			config, err := parser.NewCrossDeviceLoginConfigFromDirectives(tc.in)
			if tc.bad {
				if err == nil || config != nil || strings.Contains(err.Error(), "secret-value") {
					t.Fatal("invalid directive was accepted or disclosed")
				}
				return
			}
			if err != nil || config.Enabled != tc.enabled {
				t.Fatalf("unexpected parser result: %v", err)
			}
			if len(tc.in) > 0 && !reflect.DeepEqual(before, tc.in) {
				t.Fatal("input changed")
			}
			data, err := json.Marshal(&authn.PortalConfig{Name: "portal", CrossDeviceLogin: config})
			if err != nil {
				t.Fatal(err)
			}
			var restored authn.PortalConfig
			if json.Unmarshal(data, &restored) != nil || restored.CrossDeviceLogin.Enabled != tc.enabled {
				t.Fatal("configuration lost on reload")
			}
			config.Enabled = !config.Enabled
			next, err := parser.NewCrossDeviceLoginConfigFromDirectives(tc.in)
			if err != nil || next.Enabled != tc.enabled {
				t.Fatal("parser shared mutable configuration")
			}
		})
	}
}

func ExampleNewCrossDeviceLoginConfigFromDirectives() {
	config, err := parser.NewCrossDeviceLoginConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"enable", "cross-device", "login"})})
	if err != nil {
		panic(err)
	}
	portal := authn.PortalConfig{Name: "example", CrossDeviceLogin: config}
	fmt.Println(portal.CrossDeviceLogin.Enabled)
	// Output: true
}
