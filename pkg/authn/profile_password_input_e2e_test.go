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
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
)

func TestE2EProfileRejectsPasswordHashImports(t *testing.T) {
	f, _, _ := newLoginIdentityE2E(t, true, false, false, "")
	webAuthnEnrollmentLogin(t, f, "alice", tests.TestPwd1)
	origin := http.Header{"Origin": {f.server.URL}, "Sec-Fetch-Site": {"same-origin"}}
	passwordClient := replacementClientWithoutJar(f)

	for _, candidate := range []string{
		tests.TestPwd2Hash(t),
		"bcrypt:malformed",
		"argon2:$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
		" \targon2:malformed\n",
	} {
		response := f.jsonRequest(t, "/api/profile", map[string]any{
			"kind": "update_user_password", "old_password": tests.TestPwd1, "new_password": candidate,
		}, "", origin)
		oidcE2EStatus(t, response, http.StatusBadRequest)
	}

	oidcE2EStatus(t, passwordAttemptBasic(t, passwordClient, "192.0.2.10", tests.TestPwd1), http.StatusSeeOther)
	oidcE2EStatus(t, passwordAttemptBasic(t, passwordClient, "192.0.2.10", tests.TestPwd2), http.StatusUnauthorized)
	refreshHeaders := http.Header{
		"Origin": {f.server.URL}, "Sec-Fetch-Site": {"same-origin"}, "X-Authcrunch-Refresh": {"1"},
	}
	oidcE2EStatus(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", refreshHeaders), http.StatusOK)

	changed := f.jsonRequest(t, "/api/profile", map[string]any{
		"kind": "update_user_password", "old_password": tests.TestPwd1, "new_password": tests.TestPwd2,
	}, "", origin)
	oidcE2EStatus(t, changed, http.StatusOK)
	oidcE2EStatus(t, passwordAttemptBasic(t, passwordClient, "192.0.2.11", tests.TestPwd1), http.StatusUnauthorized)
	oidcE2EStatus(t, passwordAttemptBasic(t, passwordClient, "192.0.2.11", tests.TestPwd2), http.StatusSeeOther)
	oidcE2EStatus(t, f.jsonRequest(t, "/api/refresh_token", map[string]any{}, "", refreshHeaders), http.StatusUnauthorized)
}
