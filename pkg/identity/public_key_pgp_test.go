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

package identity

import (
	"bytes"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestPublicKeyPGPCompatibility(t *testing.T) {
	data, err := os.ReadFile("../../testdata/gpg/linux_gpg_pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewPublicKey(&requests.Request{Key: requests.Key{Usage: "gpg", Payload: "\n " + string(data) + " \n", Description: "preserved description"}})
	if err != nil {
		t.Fatal(err)
	}
	if key.ID != "a040830f7fac5991" || key.Fingerprint != "4cca1eaf950cee4ab83976dca040830f7fac5991" || key.Type != "dsa" || key.Description != "preserved description" || key.Payload != strings.TrimSpace(string(data)) {
		t.Fatal("legacy public key metadata changed")
	}
	block, err := armor.Decode(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	binary, err := io.ReadAll(block.Body)
	if err != nil {
		t.Fatal(err)
	}
	var multiple bytes.Buffer
	writer, err := armor.Encode(&multiple, "PGP PUBLIC KEY BLOCK", nil)
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := writer.Write(binary); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, payload string }{
		{"binary remains unsupported", string(binary)},
		{"private armor unsupported", strings.ReplaceAll(string(data), "PGP PUBLIC KEY BLOCK", "PGP PRIVATE KEY BLOCK")},
		{"truncated armor", strings.TrimSuffix(strings.TrimSpace(string(data)), "-----END PGP PUBLIC KEY BLOCK-----")},
		{"invalid packet", "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nAA==\n-----END PGP PUBLIC KEY BLOCK-----"},
		{"multiple entities", multiple.String()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if key, err := NewPublicKey(&requests.Request{Key: requests.Key{Usage: "gpg", Payload: tc.payload}}); err == nil || key != nil {
				t.Fatal("invalid public-key input accepted")
			}
		})
	}
}
