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
	"testing"

	"github.com/greenpau/go-authcrunch"
)

func TestE2ERemoteGatekeeperMalformedBasicAuthRemainsAvailable(t *testing.T) {
	fixture := newServerCompositionFixture(t, false, func(config *authcrunch.Config) {
		policy := config.AuthorizationPolicies[0]
		policy.AuthProxyRawConfig = []string{"basic auth realm remote portal https://127.0.0.1:1/auth"}
		policy.RawCryptoKeyStoreConfig = append(policy.RawCryptoKeyStoreConfig,
			"crypto key internal system 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	})
	headers := http.Header{
		"Authorization": {"Basic " + base64.StdEncoding.EncodeToString([]byte("alice"))},
		"X-Auth-Realm":  {"remote"},
	}
	response := fixture.request(t, http.MethodGet, fixture.origin+"/protected", "", headers)
	compositionStatus(t, response, http.StatusUnauthorized)

	// A malformed request must not panic the TLS handler or damage the
	// gatekeeper; an independent valid credential remains usable.
	fixture.native(t, "alice")
}
