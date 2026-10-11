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
	"errors"
	"fmt"
	"reflect"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/greenpau/go-authcrunch/pkg/authn"
	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
)

func documentsSettings() *authn.DocumentsAPIConfig {
	return &authn.DocumentsAPIConfig{Enabled: true, Storage: &documents.Config{Database: "/private/documents.db", PublicOrigin: "https://portal.example.test", Realms: []string{"local"}}}
}

func TestPortalConfigConfigureDocumentsAPI(t *testing.T) {
	if err := (*authn.PortalConfig)(nil).ConfigureDocumentsAPI(&authn.DocumentsAPIConfig{}); err == nil {
		t.Fatal("nil portal accepted")
	}
	existing := &authn.APIConfig{ProfileEnabled: true, AdminEnabled: true, AdminFetchPrivateKeysEnabled: true}
	original := *existing
	portal := &authn.PortalConfig{API: existing}
	for _, bad := range []*authn.DocumentsAPIConfig{nil, {Enabled: true}, {Enabled: true, Storage: &documents.Config{}}} {
		if err := portal.ConfigureDocumentsAPI(bad); err == nil || portal.API != existing || portal.Documents != nil {
			t.Fatal("invalid settings changed portal")
		}
	}
	settings := documentsSettings()
	if err := portal.ConfigureDocumentsAPI(settings); err != nil {
		t.Fatal(err)
	}
	if !portal.API.DocumentsEnabled || !portal.API.ProfileEnabled || !portal.API.AdminEnabled || !portal.API.AdminFetchPrivateKeysEnabled {
		t.Fatal("Documents changed another API flag")
	}
	if portal.API == existing || portal.Documents == settings.Storage || settings.Storage.MaxFileBytes != 0 || *existing != original {
		t.Fatal("configuration did not snapshot caller inputs")
	}
	settings.Storage.Realms[0] = "changed"
	settings.Storage.Database = "changed"
	settings.Enabled = false
	if !portal.API.DocumentsEnabled || portal.Documents.Realms[0] != "local" || portal.Documents.Database == "changed" {
		t.Fatal("caller mutation changed portal")
	}
	if err := portal.ConfigureAdminAPI(&authn.AdminAPIConfig{}); err != nil || !portal.API.DocumentsEnabled || !portal.API.ProfileEnabled {
		t.Fatal("Admin configuration changed Documents or Profile")
	}
	if err := portal.ConfigureDocumentsAPI(&authn.DocumentsAPIConfig{}); err != nil || portal.API.DocumentsEnabled || portal.Documents != nil || !portal.API.ProfileEnabled {
		t.Fatal("zero config must disable only Documents")
	}
	if err := portal.ConfigureDocumentsAPI(&authn.DocumentsAPIConfig{Storage: &documents.Config{Database: "unavailable"}}); err != nil || portal.API.DocumentsEnabled {
		t.Fatal("unused storage must not enable or provision Documents")
	}
}

func TestDocumentsAPIRequiresStorage(t *testing.T) {
	for _, storage := range []*documents.Config{nil, {}} {
		portal := &authn.PortalConfig{Name: "documents", API: &authn.APIConfig{DocumentsEnabled: true}, Documents: storage}
		if err := portal.Validate(); !errors.Is(err, documents.ErrConfig) {
			t.Fatal("raw portal configuration enabled Documents without valid storage")
		}
	}
}

func TestDocumentsAPIConfigSerialization(t *testing.T) {
	for _, codec := range []struct {
		name      string
		marshal   func(any) ([]byte, error)
		unmarshal func([]byte, any) error
	}{{"JSON", json.Marshal, json.Unmarshal}, {"XML", xml.Marshal, xml.Unmarshal}, {"YAML", yaml.Marshal, yaml.Unmarshal}} {
		for _, enabled := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/enabled_%t", codec.name, enabled), func(t *testing.T) {
				settings := documentsSettings()
				settings.Enabled = enabled
				data, err := codec.marshal(settings)
				if err != nil {
					t.Fatal(err)
				}
				var restored authn.DocumentsAPIConfig
				if err := codec.unmarshal(data, &restored); err != nil || !reflect.DeepEqual(settings, &restored) {
					t.Fatal("Documents settings did not round trip")
				}
				portal := &authn.PortalConfig{API: &authn.APIConfig{AdminEnabled: true, ProfileEnabled: true}}
				if err := portal.ConfigureDocumentsAPI(&restored); err != nil {
					t.Fatal(err)
				}
				data, err = codec.marshal(portal.API)
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(data, []byte("documents_enabled")) != enabled {
					t.Fatal("incorrect Documents enablement serialization")
				}
				var flags authn.APIConfig
				if err := codec.unmarshal(data, &flags); err != nil || flags != *portal.API {
					t.Fatal("API flags did not round trip")
				}
			})
		}
	}
}
