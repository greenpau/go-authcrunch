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

package saml

import (
	"encoding/xml"
	"testing"

	samllib "github.com/crewjam/saml"
)

func TestSAMLSubjectNamespace(t *testing.T) {
	for _, tc := range []struct{ name, body, want string }{
		{"qualified", `<s:NameID>alice</s:NameID>`, "alice"},
		{"default_namespace", `<NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion">alice</NameID>`, "alice"},
		{"foreign", `<NameID xmlns="urn:foreign">attacker</NameID>`, ""},
		{"unqualified", `<NameID>attacker</NameID>`, ""},
		{"foreign_after_valid", `<s:NameID>alice</s:NameID><NameID xmlns="urn:foreign">attacker</NameID>`, "alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var subject samllib.Subject
			if err := xml.Unmarshal([]byte(`<s:Subject xmlns:s="urn:oasis:names:tc:SAML:2.0:assertion">`+tc.body+`</s:Subject>`), &subject); err != nil {
				t.Fatal(err)
			}
			if tc.want == "" {
				if subject.NameID != nil {
					t.Fatal("a foreign namespace supplied the authenticated subject")
				}
			} else if subject.NameID == nil || subject.NameID.Value != tc.want {
				t.Fatal("the SAML subject was lost or replaced")
			}
		})
	}
}
