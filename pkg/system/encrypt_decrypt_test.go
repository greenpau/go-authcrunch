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

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func TestEncryptorRoundTrip(t *testing.T) {
	tmpDir := t.TempDir()
	keyPath := filepath.Join(tmpDir, "test.key")

	if err := GenerateKey(keyPath); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	var testcases = []struct {
		name      string
		input     Message
		want      map[string]any
		shouldErr bool
		err       error
	}{
		{
			name: "encrypt and decrypt simple struct",
			input: &BasicAuthRequestMessage{
				Kind:     BasicAuthRequestKindKeyword,
				Username: "foo",
				Password: "bar",
				Realm:    "local",
			},
			want: map[string]any{
				"kind":     "basic_auth_request",
				"username": "foo",
				"password": "bar",
				"realm":    "local",
			},
		},
		{
			name: "encrypt and decrypt map",
			input: &APIKeyAuthRequestMessage{
				Kind:   APIKeyAuthRequestKindKeyword,
				APIKey: "bar",
				Realm:  "local",
			},
			want: map[string]any{
				"kind":    "api_key_auth_request",
				"api_key": "bar",
				"realm":   "local",
			},
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

			msg, err := enc.DecryptMessage(token)
			if tests.EvalErrWithLog(t, err, "DecryptMessage", tc.shouldErr, tc.err, msgs) {
				return
			}
			got, err := msg.AsMap()
			if tests.EvalErrWithLog(t, err, "DecryptMessage", false, nil, msgs) {
				return
			}
			tests.EvalObjectsWithLog(t, "DecryptMessage", tc.want, got, msgs)
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
