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

package authcrunch_test

import (
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/greenpau/go-authcrunch"
	"github.com/greenpau/go-authcrunch/internal/tests"
)

func TestE2EGatekeeperMalformedBasicAuthRemainsAvailable(t *testing.T) {
	fixture := newServerCompositionFixture(t, false, func(config *authcrunch.Config) {
		config.AuthorizationPolicies[0].AuthProxyRawConfig = []string{"basic auth realm local portal portal"}
	})
	target := fixture.origin + "/protected"
	headers := http.Header{
		"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("alice"))},
		"X-Auth-Realm":  {"local"},
		"X-Real-IP":     {"198.51.100.20"},
	}
	malformed := fixture.request(t, http.MethodGet, target, "", headers)
	compositionStatus(t, malformed, http.StatusUnauthorized)
	if strings.Contains(string(malformed.body), "alice") || malformed.header.Get("Authorization") != "" {
		t.Fatal("malformed Basic auth response disclosed credential input")
	}

	headers.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte("alice:"+tests.TestPwd1)))
	healthy := fixture.request(t, http.MethodGet, target, "", headers)
	compositionStatus(t, healthy, http.StatusNoContent)
}
