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
	"net/http"
	"net/url"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/apiauth"
)

func TestE2ETOTPReplayRejectedAcrossSandboxes(t *testing.T) {
	for _, winner := range []string{"html", "json"} {
		t.Run(winner+" first", func(t *testing.T) {
			f, _, _ := newLoginIdentityE2E(t, false, false, true, "")
			origin := http.Header{"Origin": {f.server.URL}}

			htmlStart := f.request(t, http.MethodPost, "/login", url.Values{
				"username": {"alice"}, "realm": {"local"},
			}, origin)
			oidcE2EStatus(t, htmlStart, http.StatusSeeOther)
			htmlSandbox := htmlStart.header.Get("Location")
			oidcE2EStatus(t, f.request(t, http.MethodPost, htmlSandbox, url.Values{
				"secret": {tests.TestPwd1},
			}, origin), http.StatusSeeOther)

			jsonRequest := apiauth.AuthRequest{Username: "alice", Realm: "local"}
			jsonStart := loginIdentityResponse(t, f.jsonRequest(t, "/login", jsonRequest, "", origin))
			jsonRequest.SandboxID, jsonRequest.SandboxSecret = jsonStart.SandboxID, jsonStart.SandboxSecret
			jsonRequest.ChallengeKind, jsonRequest.ChallengeResponse = jsonStart.NextChallenge, tests.TestPwd1
			jsonFactor := loginIdentityResponse(t, f.jsonRequest(t, "/login", jsonRequest, "", origin))
			jsonRequest.SandboxID, jsonRequest.SandboxSecret = jsonFactor.SandboxID, jsonFactor.SandboxSecret
			jsonRequest.ChallengeKind = jsonFactor.NextChallenge

			code := loginIdentityTOTP()
			if winner == "html" {
				oidcE2EStatus(t, f.request(t, http.MethodPost, htmlSandbox, url.Values{
					"passcode": {code},
				}, origin), http.StatusSeeOther)
				jsonRequest.ChallengeResponse = code
				denied := f.jsonRequest(t, "/login", jsonRequest, "", origin)
				oidcE2EStatus(t, denied, http.StatusUnauthorized)
				return
			}

			jsonRequest.ChallengeResponse = code
			accepted := loginIdentityResponse(t, f.jsonRequest(t, "/login", jsonRequest, "", origin))
			if !accepted.Authenticated {
				t.Fatal("JSON sandbox did not accept the first TOTP use")
			}
			denied := f.request(t, http.MethodPost, htmlSandbox, url.Values{"passcode": {code}}, origin)
			if denied.status == http.StatusSeeOther || denied.header.Get("Authorization") != "" {
				t.Fatal("HTML sandbox accepted a TOTP step consumed by JSON login")
			}
		})
	}
}
