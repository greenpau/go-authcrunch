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
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authclient"
)

func TestConfigurationFailures(t *testing.T) {
	for _, mode := range []string{"directory", "missing", "missing URL", "empty token path", "invalid URL", "invalid token name", "missing username", "missing realm", "token directory"} {
		t.Run(mode, func(t *testing.T) {
			cfg, token := cachedCommandConfig(t, "http://127.0.0.1:1")
			values := map[string]string{"config": cfg, "token-path": token, "debug": "true"}
			switch mode {
			case "directory":
				values["config"] = t.TempDir()
			case "missing":
				values["config"] = filepath.Join(t.TempDir(), "missing")
			case "missing URL":
				writeTestFile(t, cfg, "username: user\nrealm: local\n")
			case "empty token path":
				values["config"] = writeCLIConfig(t, "http://127.0.0.1:1", "")
				values["token-path"] = ""
			case "invalid URL":
				values["config"] = writeCLIConfig(t, "ftp://invalid.example.test", token)
			case "invalid token name":
				if err := os.Remove(token); err != nil {
					t.Fatal(err)
				}
				values["access-token-name"] = "bad name"
			case "missing username", "missing realm":
				data := "base_url: http://127.0.0.1:1\n"
				if mode == "missing username" {
					data += "realm: local\n"
				} else {
					data += "username: user\n"
				}
				writeTestFile(t, cfg, data)
				f, err := os.Open(os.DevNull)
				if err != nil {
					t.Fatal(err)
				}
				defer f.Close()
				useStdin(t, f)
			case "token directory":
				values["config"] = writeCLIConfig(t, "http://127.0.0.1:1", t.TempDir())
			}
			wr := &wrapper{}
			if err := wr.configure(commandContext(t, values)); err == nil {
				t.Fatal("invalid CLI configuration accepted")
			}
		})
	}
	t.Run("home unavailable", func(t *testing.T) {
		t.Setenv("HOME", "")
		t.Setenv("USERPROFILE", "")
		if got := getConfigPath("config.yaml"); got != filepath.Join(".config", "authdbctl", "config.yaml") {
			t.Fatal("missing-home fallback changed")
		}
	})
}

func writeTestFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0600); err != nil {
		t.Fatal(err)
	}
}

func TestAuthenticateSaveFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"authenticated":true,"access_token":"new-access"}`))
	}))
	defer server.Close()
	cfg, token := cachedCommandConfig(t, server.URL)
	wr := &wrapper{}
	if err := wr.configure(commandContext(t, map[string]string{"config": cfg, "token-path": token})); err != nil {
		t.Fatal(err)
	}
	original := wr.credentials
	store, err := authclient.NewFileTokenStore(t.TempDir()) // Rename over a directory must fail.
	if err != nil {
		t.Fatal(err)
	}
	wr.tokenStore = store
	if err := wr.authenticate(t.Context()); err == nil {
		t.Fatal("credential persistence failure was hidden")
	}
	if wr.credentials != original {
		t.Fatal("failed save published new in-memory credentials")
	}
	previous, err := authclient.NewFileTokenStore(token)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := previous.Load()
	if err != nil || *saved != original {
		t.Fatal("failed save changed previous credentials")
	}
}

func TestRequestFailures(t *testing.T) {
	for _, mode := range []string{"first authentication", "re-authentication", "request URL", "authorization", "transport", "response read", "operation failure", "null response", "array response", "invalid status", "zero retries", "negative retries"} {
		t.Run(mode, func(t *testing.T) {
			var calls, logins atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/login" {
					logins.Add(1)
					w.WriteHeader(401)
					return
				}
				calls.Add(1)
				switch mode {
				case "re-authentication":
					w.WriteHeader(401)
					_, _ = w.Write([]byte(`{"message":"Access denied"}`))
				case "response read":
					w.Header().Set("Content-Length", "100")
					_, _ = w.Write([]byte(`{}`))
				case "null response":
					_, _ = w.Write([]byte(`null`))
				case "array response":
					_, _ = w.Write([]byte(`[]`))
				case "invalid status":
					_, _ = w.Write([]byte(`{"status":true}`))
				case "operation failure":
					_, _ = w.Write([]byte(`{"status":"failure","error":"synthetic-private-response"}`))
				default:
					w.WriteHeader(503)
				}
			}))
			defer server.Close()
			cfg, token := cachedCommandConfig(t, server.URL)
			values := map[string]string{"config": cfg, "token-path": token, "retries": "3"}
			if mode == "zero retries" {
				values["retries"] = "0"
			}
			if mode == "negative retries" {
				values["retries"] = "-1"
			}
			c := commandContext(t, values)
			wr := &wrapper{}
			if err := wr.configure(c); err != nil {
				t.Fatal(err)
			}
			url := server.URL + "/api/server/user"
			switch mode {
			case "first authentication":
				wr.credentials = authclient.Credentials{}
			case "request URL":
				url = "://invalid"
			case "authorization":
				wr.credentials.AccessToken = "invalid\nheader"
			case "transport":
				server.Close()
			}
			_, err := wr.doRequestWithRetry(c, http.MethodPost, url, nil, []byte(`{}`))
			if err == nil {
				t.Fatal("failed request reported success")
			}
			if strings.Contains(err.Error(), "synthetic-private-response") {
				t.Fatal("error leaked response body")
			}
			wantCalls, wantLogins := int32(0), int32(0)
			switch mode {
			case "first authentication":
				wantLogins = 1
			case "re-authentication":
				wantCalls, wantLogins = 1, 1
			case "response read":
				wantCalls = 3
			case "operation failure", "null response", "array response", "invalid status", "zero retries", "negative retries":
				wantCalls = 1
			}
			if calls.Load() != wantCalls || logins.Load() != wantLogins {
				t.Fatalf("unexpected requests %d or logins %d", calls.Load(), logins.Load())
			}
		})
	}
}

func TestCancelDuringRetryDelay(t *testing.T) {
	received := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503)
		received <- struct{}{}
	}))
	defer server.Close()
	cfg, token := cachedCommandConfig(t, server.URL)
	c := commandContext(t, map[string]string{"config": cfg, "token-path": token, "retries": "3", "retry-interval": "1h"})
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	c.Context = ctx
	wr := &wrapper{}
	if err := wr.configure(c); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := wr.doRequestWithRetry(c, http.MethodGet, server.URL, nil, nil); done <- err }()
	<-received
	// Allow the completed response to enter its retry delay.
	time.AfterFunc(25*time.Millisecond, cancel)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("got %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("retry delay ignored cancellation")
	}
}
