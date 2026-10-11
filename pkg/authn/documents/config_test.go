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

package documents_test

import (
	"errors"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/authn/documents"
)

func TestDocumentsCanonicalPublicOrigin(t *testing.T) {
	for _, tc := range []struct {
		origin string
		valid  bool
	}{
		{"https://portal.example.test", true},
		{"https://portal.example.test:8443", true},
		{"https://localhost", true},
		{"https://127.0.0.1:65535", true},
		{"https://[::1]:8443", true},
		{"https://[2001:db8::1234]", true},
		{"https://[::ffff:7f00:1]", true},
		{"https://xn--bcher-kva.example", true},
		{"https://portal.example.test.", true},
		{"https://portal.example.test#", false},
		{"https://portal.example.test?", false},
		{"https://portal.example.test:", false},
		{"https://portal.example.test:0443", false},
		{"https://portal.example.test:08443", false},
		{"https://portal.example.test:65536", false},
		{"HTTPS://portal.example.test", false},
		{"https://bücher.example", false},
		{"https://127.1", false},
		{"https://2130706433", false},
		{"https://0x7f000001", false},
		{"https://127.0.0.01", false},
		{"https://127.0.0.1.", false},
		{"https://portal.123", false},
		{"https://[0:0:0:0:0:0:0:1]", false},
		{"https://[::ffff:127.0.0.1]", false},
		{"https://[fe80::1%25en0]", false},
		{"https://[not-an-ip]", false},
		{"https://xn--a.example", false},
		{"https://a..example", false},
		{"https://user@portal.example.test", false},
		{"https://portal.example.test/path", false},
	} {
		t.Run(tc.origin, func(t *testing.T) {
			c := documents.Config{Database: "/private/documents.db", PublicOrigin: tc.origin, Realms: []string{"local"}}
			err := c.Validate()
			if tc.valid && err != nil {
				t.Fatal("canonical origin rejected", err)
			}
			if !tc.valid && !errors.Is(err, documents.ErrConfig) {
				t.Fatal("noncanonical origin accepted")
			}
			if c.PublicOrigin != tc.origin {
				t.Fatal("validation silently changed the cryptographic portal binding")
			}
		})
	}
}
