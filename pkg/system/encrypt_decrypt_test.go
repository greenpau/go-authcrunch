// Copyright 2022 Paul Greenberg greenpau@outlook.com
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

package system

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestEncryptorRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")

	if err := GenerateKey(keyPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	type payload struct {
		ID      int    `json:"id"`
		Message string `json:"message"`
	}

	var testcases = []struct {
		name      string
		input     interface{}
		shouldErr bool
	}{
		{
			name: "encrypt and decrypt simple struct",
			input: payload{
				ID:      101,
				Message: "foo",
			},
			shouldErr: false,
		},
		{
			name: "encrypt and decrypt map",
			input: map[string]string{
				"foo": "bar",
				"baz": "qux",
			},
			shouldErr: false,
		},
	}

	keyID := "foo"
	enc, err := NewEncryptorFromKey(keyID, keyPath)
	if err != nil {
		t.Fatalf("failed to initialize encryptor: %v", err)
	}

	enc, err = NewEncryptor(keyID, enc.key)
	if err != nil {
		t.Fatalf("failed to initialize encryptor: %v", err)
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			msgs := []string{fmt.Sprintf("test name: %s", tc.name)}

			token, err := enc.EncryptMessage(tc.input)
			if err != nil {
				if !tc.shouldErr {
					t.Fatalf("unexpected encryption error: %v", err)
				}
				return
			}
			msgs = append(msgs, fmt.Sprintf("generated token: %s", token))

			var got interface{}

			if _, ok := tc.input.(payload); ok {
				var p payload
				err = enc.DecryptMessage(token, &p)
				got = p
			} else {
				var m map[string]string
				err = enc.DecryptMessage(token, &m)
				got = m
			}

			if err != nil {
				if !tc.shouldErr {
					t.Fatalf("unexpected decryption error: %v", err)
				}
				return
			}

			if diff := cmp.Diff(tc.input, got); diff != "" {
				for _, m := range msgs {
					t.Log(m)
				}
				t.Fatalf("round-trip mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNewEncryptorErrors(t *testing.T) {
	tmpDir := t.TempDir()

	var testcases = []struct {
		name      string
		keyData   string
		shouldErr bool
	}{
		{
			name:      "invalid hex characters",
			keyData:   "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
			shouldErr: true,
		},
		{
			name:      "key too short",
			keyData:   "aabbccddeeff",
			shouldErr: true,
		},
		{
			name:      "file does not exist",
			keyData:   "none", // handled by file path check
			shouldErr: true,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(tmpDir, "error.key")
			if tc.keyData != "none" {
				os.WriteFile(path, []byte(tc.keyData), 0600)
			} else {
				path = "/non/existent/path"
			}

			keyID := "foo"
			_, err := NewEncryptorFromKey(keyID, path)
			if (err != nil) != tc.shouldErr {
				t.Fatalf("expected error: %v, got: %v", tc.shouldErr, err)
			}
		})
	}
}
