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

package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/bcrypt"

	"github.com/greenpau/go-authcrunch/pkg/system"
)

func TestUpdateRequiresOneOperation(t *testing.T) {
	for _, values := range []map[string]string{
		{}, {"enable": "false"}, {"enable": "true", "disable": "true"},
		{"reset-password": "true", "overwrite-roles": "viewer"},
		{"overwrite-roles": "viewer", "add-roles": "editor"},
		{"overwrite-auth-challenges": "password", "disable": "true"},
	} {
		// No configuration is provided: validation must precede IO/login.
		_, err := captureCommand(t, updateUser, commandContext(t, values))
		if err == nil || err.Error() != "select exactly one user update operation" {
			t.Fatalf("ambiguous update was not rejected before configuration: %v", err)
		}
	}
}

func TestGenerateHashes(t *testing.T) {
	const password = "V7!synthetic-password@Q9"
	for _, tc := range []struct {
		name    string
		action  cli.ActionFunc
		flags   map[string]string
		wantErr string
	}{
		{"password", generatePasswordHash, map[string]string{"password": password}, ""},
		{"password short", generatePasswordHash, map[string]string{"password": "short"}, "password is too short"},
		{"password policy", generatePasswordHash, map[string]string{"password": "abcdefg"}, "password"},
		{"password cost", generatePasswordHash, map[string]string{"password": password, "cost": "32"}, "cost"},
		{"password database", generatePasswordHash, map[string]string{"password": password, "db-path": t.TempDir()}, ""},
		{"api key", generateAPIKeyHash, nil, ""},
		{"api key database flag", generateAPIKeyHash, map[string]string{"db-path": "example.json"}, ""},
		{"api key cost", generateAPIKeyHash, map[string]string{"cost": "32"}, "cost"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, err := captureCommand(t, tc.action, commandContext(t, tc.flags))
			if tc.name == "password database" {
				if err == nil {
					t.Fatal("directory accepted as database")
				}
				return
			}
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.wantErr) {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			secret := password
			if strings.HasPrefix(tc.name, "api key") {
				match := regexp.MustCompile(`(?m)^secret: ([A-Za-z0-9]{72})$`).FindStringSubmatch(out)
				if len(match) != 2 {
					t.Fatal("generated API key missing or malformed")
				}
				secret = match[1]
				if !strings.Contains(out, "api key "+secret[:24]+" ") {
					t.Fatal("API key prefix does not match secret")
				}
			} else if strings.Contains(out, password) || strings.Contains(out, password[:2]+"..."+password[len(password)-2:]) {
				t.Fatal("password hash output disclosed password material")
			}
			match := regexp.MustCompile(`"bcrypt:([0-9]+):([^"\n]+)"`).FindStringSubmatch(out)
			if len(match) != 3 {
				t.Fatal("generated hash configuration missing")
			}
			if err := bcrypt.CompareHashAndPassword([]byte(match[2]), []byte(secret)); err != nil {
				t.Fatal("generated hash does not match its credential")
			}
			cost, err := bcrypt.Cost([]byte(match[2]))
			if err != nil || cost != 8 || match[1] != "8" {
				t.Fatal("requested hash cost was not used")
			}
		})
	}
}

func TestSystemGenerateKey(t *testing.T) {
	for _, mode := range []string{"success", "config error", "write error"} {
		t.Run(mode, func(t *testing.T) {
			cfg, token := cachedCommandConfig(t, "http://127.0.0.1:1")
			path := filepath.Join(t.TempDir(), "key")
			if mode == "write error" {
				path = t.TempDir()
			}
			if mode == "config error" {
				cfg = filepath.Join(t.TempDir(), "missing")
			}
			out, err := captureCommand(t, systemGenerateKey, commandContext(t, map[string]string{"config": cfg, "token-path": token, "output-key-file": path}))
			if (err != nil) != (mode != "success") {
				t.Fatalf("unexpected error: %v", err)
			}
			if mode != "success" {
				return
			}
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			key, err := hex.DecodeString(strings.TrimSpace(string(data)))
			if err != nil || len(key) != 32 {
				t.Fatal("invalid generated system key")
			}
			if !strings.Contains(out, path) || strings.Contains(out, string(data)) {
				t.Fatal("key output omitted path or disclosed key")
			}
			st, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if runtime.GOOS != "windows" && st.Mode().Perm() != 0600 {
				t.Fatal("system key permissions are not private")
			}
		})
	}
}

func TestSystemSendMessage(t *testing.T) {
	const request = `{"kind":"basic_auth_request","username":"jsmith","password":"synthetic-private-password","realm":"local","address":"127.0.0.1"}`
	for _, mode := range []string{"success", "config error", "missing message", "missing key", "missing id", "invalid key", "invalid message", "invalid fields", "server error", "plaintext response", "corrupt encrypted response", "wrong response key"} {
		t.Run(mode, func(t *testing.T) {
			key := bytes.Repeat([]byte{42}, 32)
			enc, err := system.NewEncryptor("test-key", key)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.URL.Path != "/api/system" || r.Method != http.MethodPost || r.Header.Get("Authorization") != "" {
					t.Error("system message used login, wrong endpoint, or access token")
					w.WriteHeader(400)
					return
				}
				data, err := io.ReadAll(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				msg, err := enc.DecryptMessage(string(data))
				if err != nil {
					t.Error("system request could not be decrypted")
					w.WriteHeader(400)
					return
				}
				req, ok := msg.(*system.BasicAuthRequestMessage)
				if !ok || req.Username != "jsmith" || req.Password != "synthetic-private-password" || req.Realm != "local" || req.Address != "127.0.0.1" {
					t.Error("decrypted request fields changed")
				}
				switch mode {
				case "server error":
					w.WriteHeader(503)
					return
				case "plaintext response":
					_, _ = io.WriteString(w, "synthetic-private-response")
					return
				case "corrupt encrypted response":
					_, _ = io.WriteString(w, "v4.local.invalid.payload")
					return
				}
				responseEnc := enc
				if mode == "wrong response key" {
					responseEnc, err = system.NewEncryptor("test-key", bytes.Repeat([]byte{43}, 32))
					if err != nil {
						t.Error(err)
						return
					}
				}
				response, err := responseEnc.EncryptMessage(&system.AuthResponseMessage{Kind: system.AuthResponseKindKeyword, ID: "response-1", Authenticated: true, UserData: map[string]any{"sub": "jsmith"}})
				if err != nil {
					t.Error(err)
					return
				}
				_, _ = io.WriteString(w, response)
			}))
			defer server.Close()
			// No token exists: the system request must not authenticate.
			token := filepath.Join(t.TempDir(), "token.jwt")
			cfg := writeCLIConfig(t, server.URL, token)
			dir := t.TempDir()
			messagePath, keyPath := filepath.Join(dir, "message.json"), filepath.Join(dir, "key")
			message, keyData := request, hex.EncodeToString(key)
			if mode == "invalid message" {
				message = `{"kind":`
			}
			if mode == "invalid fields" {
				message = `{"kind":"basic_auth_request"}`
			}
			if mode == "invalid key" {
				keyData = "not-a-key"
			}
			if err := os.WriteFile(messagePath, []byte(message), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(keyPath, []byte(keyData), 0600); err != nil {
				t.Fatal(err)
			}
			values := map[string]string{"config": cfg, "token-path": token, "input-message-file": messagePath, "encryption-key": keyPath, "key-id": "test-key"}
			switch mode {
			case "config error":
				values["config"] = filepath.Join(dir, "missing")
			case "missing message":
				values["input-message-file"] = filepath.Join(dir, "missing")
			case "missing key":
				values["encryption-key"] = filepath.Join(dir, "missing")
			case "missing id":
				values["key-id"] = ""
			}
			out, err := captureCommand(t, systemSendMessage, commandContext(t, values))
			if (err != nil) != (mode != "success") {
				t.Fatalf("unexpected system command result: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "synthetic-private-response") {
				t.Fatal("error disclosed response contents")
			}
			if mode == "success" {
				var response system.AuthResponseMessage
				if err := json.Unmarshal([]byte(out), &response); err != nil {
					t.Fatal(err)
				}
				if !response.Authenticated || response.ID != "response-1" || response.UserData["sub"] != "jsmith" {
					t.Fatal("decrypted response changed")
				}
			}
			wantCalls := int32(0)
			switch mode {
			case "success", "server error", "plaintext response", "corrupt encrypted response", "wrong response key":
				wantCalls = 1
			}
			if calls.Load() != wantCalls {
				t.Fatalf("unexpected system request count %d", calls.Load())
			}
			if _, err := os.Stat(token); !os.IsNotExist(err) {
				t.Fatal("system message created access credentials")
			}
		})
	}
}
