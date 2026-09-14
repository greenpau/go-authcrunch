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

package user_test

import (
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestLoginIdentitySnapshot(t *testing.T) {
	original := &user.User{
		LoginUsername: "canonical-account", LoginEmail: "canonical@example.test",
		LoginEvidence: requests.AuthenticationEvidence{UserID: "immutable-record", BackendVersion: "epoch", CredentialVersion: 3},
		LoginMethods:  []string{"pwd", "otp"}, Claims: &user.Claims{Subject: "public-subject", Email: "public@example.test"},
	}
	clone := original.Clone()
	original.LoginUsername, original.LoginEmail = "changed", "changed@example.test"
	original.LoginEvidence.UserID = "different"
	original.LoginMethods[0] = "changed"
	original.Claims.Subject = "changed"
	if clone.LoginUsername != "canonical-account" || clone.LoginEmail != "canonical@example.test" || clone.LoginEvidence.UserID != "immutable-record" || clone.LoginMethods[0] != "pwd" || clone.Claims.Subject != "public-subject" {
		t.Fatal("cloning did not preserve independent canonical identity and claims")
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
			encoded, err := format.marshal(clone)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(encoded), "canonical") || strings.Contains(string(encoded), "immutable-record") {
				t.Fatal("serialization exposed private login identity")
			}
			var restored user.User
			if err := format.unmarshal(encoded, &restored); err != nil {
				t.Fatal(err)
			}
			if restored.LoginUsername != "" || restored.LoginEmail != "" || restored.LoginEvidence.UserID != "" {
				t.Fatal("deserialization supplied server-only identity")
			}
		})
	}
}
