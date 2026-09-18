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

package authn_test

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

func TestE2EPasswordAttemptsSpanFreshSandboxesAndTransports(t *testing.T) {
	f, _, _ := newLoginIdentityE2E(t, false, false, false, "")
	const source = "203.0.113.10"

	for range 2 {
		oidcE2EStatus(t, passwordAttemptHTML(t, f, source, "wrong-password"), http.StatusUnauthorized)
	}
	for range 2 {
		oidcE2EStatus(t, passwordAttemptJSON(t, f, source, "wrong-password"), http.StatusUnauthorized)
	}
	oidcE2EStatus(t, passwordAttemptBasic(t, f, source, "wrong-password"), http.StatusUnauthorized)

	// One exact source exhausted its attempts, so every password transport in
	// its public /24 is denied before it can issue a credential.
	const neighbor = "203.0.113.200"
	blockedHTML := passwordAttemptHTML(t, f, neighbor, tests.TestPwd1)
	oidcE2EStatus(t, blockedHTML, http.StatusTooManyRequests)
	assertNoPasswordCredential(t, blockedHTML)
	blockedJSON := passwordAttemptJSON(t, f, neighbor, tests.TestPwd1)
	oidcE2EStatus(t, blockedJSON, http.StatusTooManyRequests)
	assertNoPasswordCredential(t, blockedJSON)
	blockedBasic := passwordAttemptBasic(t, f, neighbor, tests.TestPwd1)
	oidcE2EStatus(t, blockedBasic, http.StatusTooManyRequests)
	assertNoPasswordCredential(t, blockedBasic)

	allowed := passwordAttemptJSON(t, f, "203.0.114.10", tests.TestPwd1)
	oidcE2EStatus(t, allowed, http.StatusOK)
	var response apiauth.AuthResponse
	if err := json.Unmarshal(allowed.body, &response); err != nil || !response.Authenticated || response.AccessToken == "" {
		t.Fatal("unrelated public subnet could not complete real password login")
	}
}

func passwordAttemptHTML(t *testing.T, f *oidcE2EFixture, source, password string) oidcE2EResponse {
	t.Helper()
	headers := http.Header{"Origin": {f.server.URL}, "X-Real-IP": {source}}
	start := f.request(t, http.MethodPost, "/login", url.Values{"username": {"alice"}, "realm": {"local"}}, headers)
	oidcE2EStatus(t, start, http.StatusSeeOther)
	return f.request(t, http.MethodPost, start.header.Get("Location"), url.Values{"secret": {password}}, headers)
}

func passwordAttemptJSON(t *testing.T, f *oidcE2EFixture, source, password string) oidcE2EResponse {
	t.Helper()
	headers := http.Header{"Origin": {f.server.URL}, "X-Real-IP": {source}}
	request := apiauth.AuthRequest{Username: "alice", Realm: "local"}
	start := f.jsonRequest(t, "/login", request, "", headers)
	oidcE2EStatus(t, start, http.StatusOK)
	var challenge apiauth.AuthResponse
	if err := json.Unmarshal(start.body, &challenge); err != nil {
		t.Fatal("malformed JSON sandbox response")
	}
	request.SandboxID = challenge.SandboxID
	request.SandboxSecret = challenge.SandboxSecret
	request.ChallengeKind = challenge.NextChallenge
	request.ChallengeResponse = password
	return f.jsonRequest(t, "/login", request, "", headers)
}

func passwordAttemptBasic(t *testing.T, f *oidcE2EFixture, source, password string) oidcE2EResponse {
	t.Helper()
	secret := base64.StdEncoding.EncodeToString([]byte("alice:" + password))
	return f.request(t, http.MethodGet, "/basic/login/local", nil, http.Header{
		"Authorization": {"Basic " + secret},
		"X-Real-IP":     {source},
	})
}

func assertNoPasswordCredential(t *testing.T, response oidcE2EResponse) {
	t.Helper()
	if response.header.Get("Authorization") != "" || len(response.header.Values("Set-Cookie")) != 0 {
		t.Fatal("blocked password attempt returned a credential header")
	}
	body := string(response.body)
	if strings.Contains(body, "access_token") || strings.Contains(body, "refresh_token") {
		t.Fatal("blocked password attempt returned a credential body")
	}
}
