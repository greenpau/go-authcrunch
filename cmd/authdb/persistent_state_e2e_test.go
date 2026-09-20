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

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/authclient"
	stateparser "github.com/greenpau/go-authcrunch/pkg/state/parser"
	cfgutil "github.com/greenpau/go-authcrunch/pkg/util/cfg"
)

func testAuthdbPersistentProcessRestart(t *testing.T, binary string) {
	cfg, client := executableConfig(t, "/auth", false)
	var err error
	cfg.Security.State, err = stateparser.NewStateConfigFromDirectives([]string{cfgutil.EncodeArgs([]string{"directory", filepath.Join(t.TempDir(), "state")})})
	if err != nil {
		t.Fatal(err)
	}
	process := startAuthdb(t, binary, cfg)
	cfg.HTTP.ListenAddress = process.address
	base := "https://" + process.address + "/auth"
	auth, err := authclient.NewClient(&authclient.Config{BaseURL: base, Realm: "local", Username: "admin", Password: tests.TestPwd1}, authclient.Options{HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	credentials, err := auth.Authenticate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	authorization, err := credentials.Authorization()
	if err != nil {
		t.Fatal(err)
	}
	headers := http.Header{"Authorization": {authorization}}
	client.Jar, _ = cookiejar.New(nil)
	browserHeaders := http.Header{"Origin": {"https://" + process.address}, "Content-Type": {"application/x-www-form-urlencoded"}}
	start, _ := serverRequest(t, client, "POST", base+"/login", url.Values{"realm": {"local"}, "username": {"admin"}}.Encode(), browserHeaders)
	if start.StatusCode != 303 {
		t.Fatal("browser login did not enter checkpoint")
	}
	checkpoint := start.Header.Get("Location")
	endpoint, err := url.Parse(base + "/login")
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint = endpoint.ResolveReference(target).String()
	password, _ := serverRequest(t, client, "POST", checkpoint, url.Values{"secret": {tests.TestPwd1}}.Encode(), browserHeaders)
	if password.StatusCode != 303 {
		t.Fatal("browser checkpoint failed")
	}
	completed, _ := serverRequest(t, client, "GET", checkpoint, "", nil)
	if completed.StatusCode != 303 {
		t.Fatal("browser login did not complete")
	}
	live, _ := serverRequest(t, client, "GET", base+"/portal", "", nil)
	if live.StatusCode != 200 {
		t.Fatal("browser session not established before restart")
	}

	before, keyBefore := serverRequest(t, client, "GET", base+"/.well-known/jwks.json", "", nil)
	if before.StatusCode != 200 {
		t.Fatal("key discovery failed")
	}
	// SIGKILL/TerminateProcess bypasses all library and host shutdown hooks.
	if err = process.cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-process.done:
		process.stopped = true
	case <-time.After(10 * time.Second):
		t.Fatal("killed server was not reaped")
	}
	client.CloseIdleConnections()
	replacement := startAuthdb(t, binary, cfg)
	after, keyAfter := serverRequest(t, client, "GET", base+"/.well-known/jwks.json", "", nil)
	var first, second any
	if json.Unmarshal(keyBefore, &first) != nil || json.Unmarshal(keyAfter, &second) != nil {
		t.Fatal("malformed JWKS")
	}
	keyBefore, _ = json.Marshal(first)
	keyAfter, _ = json.Marshal(second)
	if after.StatusCode != 200 || !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("generated signing keys changed across process death")
	}
	response, body := serverRequest(t, client, "GET", base+"/whoami?format=json", "", headers)
	if response.StatusCode != 200 || !bytes.Contains(body, []byte("admin")) {
		t.Fatal("old access credential lost after process restart")
	}
	response, _ = serverRequest(t, client, "GET", base+"/portal", "", nil)
	if response.StatusCode != 200 {
		t.Fatal("authenticated user cache lost after process restart")
	}
	replacement.stop(t)
}
