// Copyright 2026 Paul Greenberg greenpau@outlook.com
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/authproxy"
	"github.com/greenpau/go-authcrunch/pkg/authz"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/ids"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"go.uber.org/zap"
)

// Repeated requests deliberately use the same method, address, realm and
// credential: these are all the credential-cache key inputs. Mutations happen
// only after successful requests, with no sleeps or cache manipulation.
func TestPortalCredentialAuthenticationFreshness(t *testing.T) {
	for _, method := range []string{"basic", "api_key"} {
		t.Run(method, func(t *testing.T) {
			f := newRefreshPortal(t, false, false)
			const signingKey = "synthetic-portal-credential-freshness-signing-key-0123456789"
			portal, err := NewPortal(PortalParameters{
				Config: &PortalConfig{Name: "credential-freshness", IdentityStores: []string{"localdb"},
					RawCryptoKeyStoreConfig: []string{"crypto key sign-verify " + signingKey}},
				IdentityStores: []ids.IdentityStore{f.store}, Logger: zap.NewNop(),
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(portal.Close)
			gate, err := authz.NewGatekeeper(&authz.PolicyConfig{
				Name: "credential-freshness", AuthRedirectDisabled: true,
				RawCryptoKeyStoreConfig: []string{"crypto key verify " + signingKey},
				AuthProxyRawConfig:      []string{"basic auth realm local portal credential-freshness", "api key auth realm local portal credential-freshness"},
				AccessListRules:         []*acl.RuleConfiguration{{Conditions: []string{"match roles original"}, Action: "allow stop"}},
			}, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(gate.Close)
			if err := gate.AddAuthenticators([]authproxy.Authenticator{portal}); err != nil {
				t.Fatal(err)
			}
			if err := gate.HasAuthProxies(); err != nil {
				t.Fatal(err)
			}
			const apiKey = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyzAB"
			key := &requests.Request{User: requests.User{Username: tests.TestUser1, Email: tests.TestEmail1}, Key: requests.Key{Payload: apiKey, Usage: "api", Comment: "fresh credential regression"}}
			if method == "api_key" {
				if err := f.store.Request(operator.AddAPIKey, key); err != nil {
					t.Fatal(err)
				}
				if err := f.store.Request(operator.GetAPIKeys, key); err != nil {
					t.Fatal(err)
				}
				key.Key.ID = key.Response.Payload.(*identity.APIKeyBundle).Get()[0].ID
			}
			authorize := func(step string, want bool) {
				t.Helper()
				r := httptest.NewRequest(http.MethodGet, "https://resource.example.test/private", nil)
				r.RemoteAddr = "192.0.2.10:12345"
				r.Header.Set("X-Auth-Realm", "local")
				if method == "basic" {
					r.SetBasicAuth(tests.TestUser1, tests.TestPwd1)
				} else {
					r.Header.Set("X-API-Key", apiKey)
				}
				ar := requests.NewAuthorizationRequest()
				err := gate.Authenticate(httptest.NewRecorder(), r, ar)
				if got := err == nil && ar.Response.Authorized; got != want {
					t.Fatalf("%s: authorized=%t, want %t", step, got, want)
				}
			}
			authorize("initial credential", true)
			authorize("repeated credential", true)
			if _, err := f.store.OverwriteUserRoles(tests.TestUser1, tests.TestEmail1, []string{"authp/user"}); err != nil {
				t.Fatal(err)
			}
			authorize("current roles no longer permit resource", false)
			if _, err := f.store.OverwriteUserRoles(tests.TestUser1, tests.TestEmail1, []string{"authp/user", "original"}); err != nil {
				t.Fatal(err)
			}
			authorize("restored current roles", true)
			if method == "basic" {
				if err := f.store.Request(operator.AddMfaToken, &requests.Request{User: key.User, MfaToken: requests.MfaToken{
					Type: "totp", Comment: "new required factor", Secret: refreshTestSecret,
					Algorithm: "sha1", Period: 30, Digits: 6, SkipVerification: true,
				}}); err != nil {
					t.Fatal(err)
				}
				if _, err := f.store.OverwriteUserAuthChallengeRules(tests.TestUser1, tests.TestEmail1, []string{"totp"}); err != nil {
					t.Fatal(err)
				}
				authorize("current MFA policy cannot be satisfied by Basic", false)
				if _, err := f.store.OverwriteUserAuthChallengeRules(tests.TestUser1, tests.TestEmail1, []string{"password"}); err != nil {
					t.Fatal(err)
				}
				authorize("current password-only policy permits Basic", true)
				_, err = f.store.ResetUserPassword(tests.TestUser1, tests.TestEmail1)
			} else {
				err = f.store.Request(operator.DeleteAPIKey, key)
			}
			if err != nil {
				t.Fatal(err)
			}
			authorize("revoked credential after successful authentication", false)
		})
	}
}
