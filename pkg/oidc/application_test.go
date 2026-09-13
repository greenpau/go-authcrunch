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

package oidc_test

import (
	"encoding/json"
	"encoding/xml"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/greenpau/go-authcrunch/pkg/oidc"
)

func TestNewOAuthApplicationConfig(t *testing.T) {
	client := &oidc.ClientConfig{ClientID: "protocol-id", ClientSecret: strings.Repeat("s", 32), RedirectURIs: []string{"https://app.example.test/callback"}}
	application, err := oidc.NewOAuthApplicationConfig("web", client)
	if err != nil {
		t.Fatal(err)
	}
	if application.Name != "web" || application.Client.ClientID != "protocol-id" || application.Client.TokenEndpointAuthMethod != "client_secret_basic" || len(application.Client.Scopes) != 3 {
		t.Fatal("application registration did not preserve identity or apply defaults")
	}
	if client.TokenEndpointAuthMethod != "" || client.Scopes != nil {
		t.Fatal("construction mutated the supplied client")
	}
	client.RedirectURIs[0] = "https://changed.example.test/"
	if application.Client.RedirectURIs[0] != "https://app.example.test/callback" {
		t.Fatal("application shares client slices")
	}
	for _, format := range []struct {
		name      string
		marshal   func(any) ([]byte, error)
		unmarshal func([]byte, any) error
	}{
		{"json", json.Marshal, json.Unmarshal},
		{"xml", xml.Marshal, xml.Unmarshal},
		{"yaml", yaml.Marshal, yaml.Unmarshal},
	} {
		t.Run(format.name, func(t *testing.T) {
			data, err := format.marshal(application)
			if err != nil {
				t.Fatal(err)
			}
			var restored oidc.OAuthApplicationConfig
			if err := format.unmarshal(data, &restored); err != nil {
				t.Fatal(err)
			}
			if err := restored.Validate(); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(application, &restored) {
				t.Fatal("registration changed during serialization")
			}
		})
	}
}

func TestOAuthApplicationConfigValidation(t *testing.T) {
	valid := &oidc.ClientConfig{ClientID: "public", TokenEndpointAuthMethod: "none", RedirectURIs: []string{"https://app.example.test/callback"}}
	for _, name := range []string{"", " padded", "trailing ", "tab\tname", "line\nname", "line\rname", strings.Repeat("a", 257)} {
		if result, err := oidc.NewOAuthApplicationConfig(name, valid); result != nil || err == nil {
			t.Fatal("invalid nickname accepted")
		}
	}
	if result, err := oidc.NewOAuthApplicationConfig("my application", valid); err != nil || result == nil {
		t.Fatal("quoted nickname rejected")
	}
	if result, err := oidc.NewOAuthApplicationConfig(strings.Repeat("a", 256), valid); err != nil || result == nil {
		t.Fatal("maximum-length nickname rejected")
	}
	for _, client := range []*oidc.ClientConfig{nil, {}, {ClientID: "missing-secret", RedirectURIs: []string{"https://app.example.test/callback"}}} {
		if result, err := oidc.NewOAuthApplicationConfig("web", client); result != nil || err == nil {
			t.Fatal("incomplete registration was provisioned or accepted")
		}
	}
	if err := (*oidc.OAuthApplicationConfig)(nil).Validate(); err == nil {
		t.Fatal("nil application accepted")
	}
}
