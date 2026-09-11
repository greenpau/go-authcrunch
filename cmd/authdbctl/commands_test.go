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
	"encoding/csv"
	"encoding/json"
	"flag"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/urfave/cli/v2"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

// Fresh flag sets avoid sharing mutable urfave command/flag state across tests.
func commandContext(t *testing.T, values map[string]string) *cli.Context {
	t.Helper()
	fs := flag.NewFlagSet(t.Name(), flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	for _, name := range []string{"config", "token-path", "format", "access-token-name", "realm", "username", "name", "email", "password", "db-path", "output-key-file", "input-message-file", "encryption-key", "key-id"} {
		fs.String(name, "", "")
	}
	for _, name := range []string{"debug", "disable", "enable", "reset-password"} {
		fs.Bool(name, false, "")
	}
	for _, name := range []string{"roles", "overwrite-roles", "add-roles", "overwrite-auth-challenges"} {
		fs.Var(cli.NewStringSlice(), name, "")
	}
	fs.Int("retries", 1, "")
	fs.Int("cost", 8, "")
	fs.Duration("retry-interval", time.Duration(0), "")
	for name, value := range values {
		if err := fs.Set(name, value); err != nil {
			t.Fatal(err)
		}
	}
	c := cli.NewContext(cli.NewApp(), fs, nil)
	c.Context = t.Context()
	return c
}

func captureCommand(t *testing.T, action cli.ActionFunc, c *cli.Context) (string, error) {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stdout")
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = f
	defer func() { os.Stdout = old; f.Close() }()
	actionErr := action(c)
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(data), actionErr
}

func cachedCommandConfig(t *testing.T, baseURL string) (string, string) {
	t.Helper()
	tokenPath := filepath.Join(t.TempDir(), "token.jwt")
	store, err := authclient.NewFileTokenStore(tokenPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(&authclient.Credentials{AccessToken: "test-access", AccessTokenName: "test_token"}); err != nil {
		t.Fatal(err)
	}
	return writeCLIConfig(t, baseURL, tokenPath), tokenPath
}

func TestManagementCommands(t *testing.T) {
	const realm = "local\"realm\nwith newline"
	user := map[string]any{"username": "jsmith", "email": "jsmith@example.test"}
	for _, tc := range []struct {
		name                string
		action              cli.ActionFunc
		endpoint, operation string
		flags               map[string]string
	}{
		{name: "metadata", action: metadata, endpoint: "metadata"},
		{name: "list realms", action: listRealms, endpoint: "realms"},
		{name: "list users", action: listUsers, endpoint: "users"},
		{name: "realm info", action: fetchRealmInfo, endpoint: "info"},
		{name: "reload", action: reload, endpoint: "reload"},
		{name: "user info", action: fetchUserInfo, endpoint: "user", operation: "info"},
		{name: "add user", action: addUser, endpoint: "user", operation: "add", flags: map[string]string{"name": "John Smith", "roles": "viewer"}},
		{name: "delete user", action: deleteUser, endpoint: "user", operation: "delete"},
		{name: "disable user", action: updateUser, endpoint: "user", operation: "disable", flags: map[string]string{"disable": "true"}},
		{name: "enable user", action: updateUser, endpoint: "user", operation: "enable", flags: map[string]string{"enable": "true"}},
		{name: "reset password", action: updateUser, endpoint: "user", operation: "reset_password", flags: map[string]string{"reset-password": "true"}},
		{name: "overwrite roles", action: updateUser, endpoint: "user", operation: "overwrite_roles", flags: map[string]string{"overwrite-roles": "viewer"}},
		{name: "add roles", action: updateUser, endpoint: "user", operation: "add_roles", flags: map[string]string{"add-roles": "viewer"}},
		{name: "overwrite challenges", action: updateUser, endpoint: "user", operation: "overwrite_auth_challenges", flags: map[string]string{"overwrite-auth-challenges": "password totp"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, mode := range []string{"success", "server error", "invalid JSON", "invalid fields", "config error"} {
				if mode == "invalid fields" && tc.endpoint != "users" && tc.endpoint != "realms" {
					continue
				}
				t.Run(mode, func(t *testing.T) {
					var calls int
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						calls++
						if r.URL.Path != "/auth/api/server/"+tc.endpoint || r.Header.Get("Authorization") != "test_token=test-access" {
							t.Error("incorrect endpoint or authorization")
						}
						if tc.endpoint == "metadata" {
							if r.Method != http.MethodGet {
								t.Error("metadata must use GET")
							}
						} else {
							if r.Method != http.MethodPost {
								t.Error("management operation must use POST")
							}
							var body map[string]any
							if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
								t.Error("command sent invalid JSON")
								w.WriteHeader(400)
								return
							}
							want := map[string]any{"realm": realm}
							if tc.endpoint == "realms" {
								want = map[string]any{"query": "all"}
							}
							if tc.endpoint == "users" || tc.endpoint == "info" {
								want["query"] = "all"
							}
							if tc.operation != "" {
								u := map[string]any{"username": user["username"], "email": user["email"]}
								if tc.operation == "add" {
									u["name"], u["roles"] = "John Smith", []any{"viewer"}
								}
								if tc.operation == "overwrite_roles" || tc.operation == "add_roles" {
									u["roles"] = []any{"viewer"}
								}
								if tc.operation == "overwrite_auth_challenges" {
									u["challenges"] = []any{"password totp"}
								}
								want["operation"], want["user"] = tc.operation, u
							}
							if !reflect.DeepEqual(body, want) {
								t.Errorf("wrong request fields for %s", tc.name)
							}
						}
						if mode == "server error" {
							w.WriteHeader(403)
							_, _ = w.Write([]byte(`{"message":"Forbidden"}`))
							return
						}
						if mode == "invalid fields" {
							_, _ = w.Write([]byte(`{"users":true,"realms":true}`))
							return
						}
						if mode == "invalid JSON" {
							_, _ = w.Write([]byte(`{"broken":`))
							return
						}
						_, _ = w.Write([]byte(`{"status":"success"}`))
					}))
					defer server.Close()
					configPath, tokenPath := cachedCommandConfig(t, server.URL+"/auth")
					if mode == "config error" {
						configPath = filepath.Join(t.TempDir(), "missing")
					}
					values := map[string]string{"config": configPath, "token-path": tokenPath, "realm": realm, "username": "jsmith", "email": "jsmith@example.test"}
					for k, v := range tc.flags {
						values[k] = v
					}
					out, err := captureCommand(t, tc.action, commandContext(t, values))
					if (err != nil) != (mode != "success") {
						t.Fatalf("unexpected command result: %v", err)
					}
					if mode == "success" && strings.TrimSpace(out) != `{"status":"success"}` {
						t.Fatal("command did not print the response")
					}
					if mode == "config error" && calls != 0 {
						t.Fatal("invalid config reached the network")
					}
					if mode != "config error" && calls != 1 {
						t.Fatalf("unexpected request count %d", calls)
					}
				})
			}
		})
	}
}

func TestListOutputFormats(t *testing.T) {
	for _, kind := range []string{"realms", "users"} {
		for _, format := range []string{"csv", "table"} {
			t.Run(kind+" "+format, func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if kind == "realms" {
						_, _ = w.Write([]byte(`{"realms":[{"realm":"local","kind":"local","name":"one, two"}]}`))
						return
					}
					_, _ = w.Write([]byte(`{"users":[{"username":"jsmith","name":"Smith, John","email":"jsmith@example.test","roles":["viewer","editor"],"disabled":true}]}`))
				}))
				defer server.Close()
				cfg, token := cachedCommandConfig(t, server.URL)
				action := listRealms
				if kind == "users" {
					action = listUsers
				}
				out, err := captureCommand(t, action, commandContext(t, map[string]string{"config": cfg, "token-path": token, "realm": "local", "format": format}))
				if err != nil {
					t.Fatal(err)
				}
				if format == "csv" {
					rows, err := csv.NewReader(strings.NewReader(out)).ReadAll()
					if err != nil {
						t.Fatal(err)
					}
					want := [][]string{{"realm", "kind", "name"}, {"local", "local", "one, two"}}
					if kind == "users" {
						want = [][]string{{"username", "name", "email", "roles", "disabled"}, {"jsmith", "Smith, John", "jsmith@example.test", "viewer;editor", "true"}}
					}
					if !reflect.DeepEqual(rows, want) {
						t.Fatal("CSV did not preserve columns, quoting, or values")
					}
				} else if !strings.Contains(out, "local") && !strings.Contains(out, "jsmith") {
					t.Fatal("table omitted its data")
				}
			})
		}
	}
}
