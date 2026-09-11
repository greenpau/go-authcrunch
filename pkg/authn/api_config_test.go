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

package authn

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAPIConfigAdminFetchPrivateKeys(t *testing.T) {
	for _, tc := range []struct {
		name      string
		marshal   func(any) ([]byte, error)
		unmarshal func([]byte, any) error
	}{
		{"JSON", json.Marshal, json.Unmarshal},
		{"XML", xml.Marshal, xml.Unmarshal},
		{"YAML", yaml.Marshal, yaml.Unmarshal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, enabled := range []bool{false, true} {
				config := APIConfig{AdminEnabled: true, AdminFetchPrivateKeysEnabled: enabled}
				data, err := tc.marshal(config)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(data, []byte("admin_fetch_private_keys_enabled")) != enabled {
					t.Fatal("private-key export flag has incorrect serialization or default")
				}
				var decoded APIConfig
				if err := tc.unmarshal(data, &decoded); err != nil {
					t.Fatal(err)
				}
				if decoded != config {
					t.Fatal("private-key export configuration did not round trip")
				}
			}
		})
	}
	for _, input := range []string{`{}`, `{"api":{}}`, `{"api":{"admin_enabled":true}}`, `{"api":{"admin_enabled":true,"admin_fetch_private_keys_enabled":true}}`} {
		var config PortalConfig
		if err := json.Unmarshal([]byte(input), &config); err != nil {
			t.Fatal(err)
		}
		config.Name = "private-export-config-test"
		if err := config.Validate(); err != nil {
			t.Fatal(err)
		}
		enabled := config.API != nil && config.API.AdminFetchPrivateKeysEnabled
		if enabled != bytes.Contains([]byte(input), []byte("admin_fetch_private_keys_enabled")) {
			t.Fatal("portal validation changed the private-key export opt-in")
		}
	}
}
