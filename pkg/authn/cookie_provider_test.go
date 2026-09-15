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

package authn

import (
	"testing"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
	"github.com/greenpau/go-authcrunch/pkg/idp"
)

func TestCookieProviderNameValidation(t *testing.T) {
	for _, tc := range []struct {
		name              string
		insecure, invalid bool
	}{
		{"", false, false}, {"invalid name", false, true}, {"invalid;name", false, true},
		{"PROVIDER_ID", false, false}, {"PROVIDER_ID", true, false},
		{"__Secure-PROVIDER_ID", false, false}, {"__sEcUrE-PROVIDER_ID", true, true},
		{"__Host-PROVIDER_ID", false, true}, {"__hOsT-PROVIDER_ID", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			provider := &mockIdentityProvider{name: "provider", realm: "upstream", kind: "oauth", identityTokenCookieName: tc.name}
			for _, prefix := range []string{"FIRST", "SECOND"} {
				factory, err := cookie.NewFactory(&cookie.Config{CookieNamePrefix: prefix, Insecure: tc.insecure})
				if err != nil {
					t.Fatal(err)
				}
				p := &Portal{config: &PortalConfig{IdentityProviders: []string{"provider"}}, cookie: factory, identityProviders: []idp.IdentityProvider{provider}, logger: zap.NewNop(), loginOptions: make(map[string]any)}
				err = p.configureIdentityProviderLogin()
				if (err != nil) != tc.invalid {
					t.Fatalf("provider compatibility: %v", err)
				}
				if provider.GetIdentityTokenCookieName() != tc.name {
					t.Fatal("portal prefix rewrote shared provider")
				}
			}
		})
	}
}
