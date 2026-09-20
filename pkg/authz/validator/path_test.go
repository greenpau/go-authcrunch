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

package validator

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/internal/testutils"
	"github.com/greenpau/go-authcrunch/pkg/acl"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/errors"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func TestAuthorizeRequestPathInterpretations(t *testing.T) {
	for _, tc := range []struct {
		name                   string
		method, claim, address bool
	}{
		{"base", false, false, false}, {"address", false, false, true},
		{"method", true, false, false}, {"claim", false, true, false},
		{"method_address", true, false, true}, {"claim_address", false, true, true},
		{"method_claim", true, true, false}, {"all", true, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := testutils.NewTestCryptoKeyStore()
			if err != nil {
				t.Fatal(err)
			}
			v, err := NewTokenValidator(keys.GetConfig(), zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(v.Close)
			list := acl.NewAccessList()
			list.SetLogger(zap.NewNop())
			if err := list.AddRules(t.Context(), []*acl.RuleConfiguration{
				{Conditions: []string{"prefix match path /admin"}, Action: "deny stop"},
				{Conditions: []string{"match roles viewer"}, Action: "allow stop"},
			}); err != nil {
				t.Fatal(err)
			}
			opts := options.NewTokenValidatorOptions()
			opts.ValidateMethodPath, opts.ValidateAccessListPathClaim, opts.ValidateSourceAddress = tc.method, tc.claim, tc.address
			if err := v.Configure(t.Context(), list, opts); err != nil {
				t.Fatal(err)
			}
			usr, err := user.NewUser(`{
                "sub":"path-viewer", "roles":["viewer"], "addr":"192.0.2.1",
                "acl":{"paths":["/public/**", "/public/%zz", "/public/100%", "/public/a%2fb/../%2e%2e/admin", "/public/%2e%2e/admin"]}
            }`)
			if err != nil {
				t.Fatal(err)
			}
			for _, target := range []struct {
				path    string
				allowed bool
			}{
				{"/public/file", true}, {"/public/%2e/assets/file", true},
				{"/public/%25zz", true}, {"/public/100%25", true},
				{"/admin", false}, {"/admin/%2e%2e/public/file", false},
				{"/public/a%252fb/../%252e%252e/admin", false},
				{"/public/%25zz/%252e%252e/admin", false},
				{"/public/%25252525252e%25252525252e/admin", false},
				{"/public/%ff/file", false}, {"/public/%25ff/file", false},
			} {
				t.Run(target.path, func(t *testing.T) {
					req := httptest.NewRequest(http.MethodGet, target.path, nil)
					req.RemoteAddr = "192.0.2.1:1234"
					before := *req.URL
					uri := req.RequestURI
					err := v.AuthorizeUser(t.Context(), req, usr)
					wantAllowed := target.allowed || !(tc.method || tc.claim)
					if wantAllowed && err != nil {
						t.Fatalf("safe request rejected: %v", err)
					}
					if !wantAllowed {
						want := errors.ErrAccessNotAllowedByPathACL
						if tc.method {
							want = errors.ErrAccessNotAllowed
						}
						if err != want {
							t.Fatalf("got %v, want %v", err, want)
						}
					}
					if *req.URL != before || req.RequestURI != uri {
						t.Fatal("authorization rewrote request")
					}
				})
			}
			for _, invalid := range []*user.User{nil, {}} {
				if err := v.AuthorizeUser(t.Context(), httptest.NewRequest(http.MethodGet, "/", nil), invalid); err == nil {
					t.Fatal("missing authenticated identity accepted")
				}
			}
			if tc.method || tc.claim {
				for _, req := range []*http.Request{nil, {}, {URL: &url.URL{Path: "/public/%2e/%zz"}}} {
					if err := v.AuthorizeUser(t.Context(), req, usr); err == nil {
						t.Fatal("invalid request accepted")
					}
				}
			}
			v.Close()
			if err := v.AuthorizeUser(t.Context(), httptest.NewRequest(http.MethodGet, "/", nil), usr); err == nil {
				t.Fatal("closed identity authorizer accepted request")
			}
		})
	}
}
