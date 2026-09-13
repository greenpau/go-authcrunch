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

package authn_test

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/greenpau/go-authcrunch/pkg/authn"
)

func TestPortalConfigConfigureAdminAPI(t *testing.T) {
	if err := (*authn.PortalConfig)(nil).ConfigureAdminAPI(&authn.AdminAPIConfig{}); err == nil || err.Error() != "portal config is nil" {
		t.Fatal("nil portal must return a configuration error")
	}
	for _, existing := range []*authn.APIConfig{nil, {}, {ProfileEnabled: true, AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}} {
		var original authn.APIConfig
		if existing != nil {
			original = *existing
		}
		portal := &authn.PortalConfig{API: existing}
		if err := portal.ConfigureAdminAPI(nil); err == nil || err.Error() != "admin API config is nil" || portal.API != existing {
			t.Fatal("nil admin config must fail without changing portal configuration")
		}
		for _, enabled := range []bool{false, true} {
			for _, export := range []bool{false, true} {
				admin := &authn.AdminAPIConfig{Enabled: enabled, FetchPrivateKeysEnabled: export}
				want := authn.APIConfig{AdminEnabled: enabled, AdminFetchPrivateKeysEnabled: export}
				if existing != nil {
					want.ProfileEnabled = existing.ProfileEnabled
				}
				if err := portal.ConfigureAdminAPI(admin); err != nil || portal.API == nil || *portal.API != want {
					t.Fatalf("configuration = %+v, error = %v; want %+v", portal.API, err, want)
				}
				admin.Enabled, admin.FetchPrivateKeysEnabled = !enabled, !export
				if *portal.API != want || portal.API == existing {
					t.Fatal("portal configuration must own an independent snapshot")
				}
			}
		}
		if err := portal.ConfigureAdminAPI(&authn.AdminAPIConfig{}); err != nil || portal.API.AdminEnabled || portal.API.AdminFetchPrivateKeysEnabled {
			t.Fatal("replacement config must clear previous admin opt-ins")
		}
		if existing != nil && *existing != original {
			t.Fatal("configuration changed the original shared API settings")
		}
	}
}

func TestAdminAPIConfigSerialization(t *testing.T) {
	for _, codec := range []struct {
		name      string
		marshal   func(any) ([]byte, error)
		unmarshal func([]byte, any) error
	}{
		{"JSON", json.Marshal, json.Unmarshal},
		{"XML", xml.Marshal, xml.Unmarshal},
		{"YAML", yaml.Marshal, yaml.Unmarshal},
	} {
		for _, enabled := range []bool{false, true} {
			for _, export := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/admin_%t/export_%t", codec.name, enabled, export), func(t *testing.T) {
					original := authn.AdminAPIConfig{Enabled: enabled, FetchPrivateKeysEnabled: export}
					data, err := codec.marshal(original)
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Contains(data, []byte("fetch_private_keys_enabled")) != export {
						t.Fatal("admin config has incorrect export serialization or default")
					}
					var admin authn.AdminAPIConfig
					if err := codec.unmarshal(data, &admin); err != nil || admin != original {
						t.Fatal("admin config did not round trip")
					}
					portal := &authn.PortalConfig{API: &authn.APIConfig{ProfileEnabled: true}}
					if err := portal.ConfigureAdminAPI(&admin); err != nil {
						t.Fatal(err)
					}
					data, err = codec.marshal(portal.API)
					if err != nil {
						t.Fatal(err)
					}
					if bytes.Contains(data, []byte("admin_enabled")) != enabled || bytes.Contains(data, []byte("admin_fetch_private_keys_enabled")) != export {
						t.Fatal("portal API config changed its established serialization fields")
					}
					var restored authn.APIConfig
					if err := codec.unmarshal(data, &restored); err != nil || restored != *portal.API || !restored.ProfileEnabled {
						t.Fatal("portal API settings did not round trip with profile access preserved")
					}
				})
			}
		}
	}
}
