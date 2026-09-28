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

package validator_test

import (
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"go.uber.org/zap"

	"github.com/greenpau/go-authcrunch/pkg/acl"
	aclparser "github.com/greenpau/go-authcrunch/pkg/acl/parser"
	"github.com/greenpau/go-authcrunch/pkg/authz/options"
	"github.com/greenpau/go-authcrunch/pkg/authz/validator"
	"github.com/greenpau/go-authcrunch/pkg/kms"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

// Exercise the public authenticated-identity API used by non-JWT consumers. The
// fixture selects already established identities; clients cannot supply claims.
func TestE2EACLFieldsAuthorizeUser(t *testing.T) {
	for flags := range 8 {
		t.Run(fmt.Sprint(flags), func(t *testing.T) {
			field, err := aclparser.NewACLFieldConfigFromDirectives("external", []string{"claim https://example.org/roles", "type string list"})
			if err != nil {
				t.Fatal(err)
			}
			list, err := acl.NewAccessListWithFields([]*acl.FieldConfig{field})
			if err != nil {
				t.Fatal(err)
			}
			conditions := []string{"match external admin"}
			if flags&1 != 0 {
				conditions = append(conditions, "match method GET", "prefix match path /private/")
			}
			if err := list.AddRule(t.Context(), &acl.RuleConfiguration{Conditions: conditions, Action: "allow stop"}); err != nil {
				t.Fatal(err)
			}
			keys, err := kms.NewCryptoKeyStoreConfig(nil)
			if err != nil {
				t.Fatal(err)
			}
			v, err := validator.NewTokenValidator(keys, zap.NewNop())
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(v.Close)
			opts := options.NewTokenValidatorOptions()
			opts.ValidateMethodPath, opts.ValidateSourceAddress, opts.ValidateAccessListPathClaim = flags&1 != 0, flags&2 != 0, flags&4 != 0
			opts.ValidateBearerHeader = true
			opts.AuthorizationHeaderNames = []string{"access_token"}
			if err := v.Configure(t.Context(), list, opts); err != nil {
				t.Fatal(err)
			}
			base := map[string]any{
				"sub": "authenticated", "https://example.org/roles": []string{"admin"},
				"exp": time.Now().Add(time.Minute).Unix(), "addr": "127.0.0.1",
				"acl": map[string]any{"paths": []any{"/private/**"}},
			}
			identities := make(map[string]*user.User)
			for name, value := range map[string]any{"allowed": []string{"admin"}, "denied": []string{"reader"}, "malformed": []any{"admin", 1}, "null": nil} {
				data := maps.Clone(base)
				data["https://example.org/roles"] = value
				usr, err := user.NewUser(data)
				if err != nil {
					t.Fatal(err)
				}
				identities[name] = usr
			}
			before := identities["allowed"].Clone()
			// The public cache API also preserves custom claims and forces the same
			// checks when JWT parsing is legitimately skipped for a cached identity.
			cached := identities["allowed"].Clone()
			cached.Token = "opaque-fixture-cache-key"
			if err := v.CacheUser(cached); err != nil {
				t.Fatal(err)
			}
			badCached := identities["malformed"].Clone()
			badCached.Token = "malformed-fixture-cache-key"
			if err := v.CacheUser(badCached); err != nil {
				t.Fatal(err)
			}
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var err error
				if r.Header.Get("X-Test-Identity") == "cached" {
					var usr *user.User
					usr, err = v.Authorize(r.Context(), r, requests.NewAuthorizationRequest())
					if err == nil && !usr.Cached {
						t.Error("request did not use cached identity")
					}
				} else {
					err = v.AuthorizeUser(r.Context(), r, identities[r.Header.Get("X-Test-Identity")])
				}
				if err != nil {
					http.Error(w, "denied", http.StatusForbidden)
					return
				}
				w.WriteHeader(http.StatusNoContent)
			}))
			defer srv.Close()
			client := srv.Client()
			client.Timeout = 5 * time.Second
			for _, tc := range []struct {
				identity, method, path, token string
				allowed                       bool
			}{
				{"allowed", "GET", "/private/doc", "", true},
				{"denied", "GET", "/private/doc", "", false},
				{"malformed", "GET", "/private/doc", "", false},
				{"null", "GET", "/private/doc", "", false},
				{"missing", "GET", "/private/doc", "", false},
				{"allowed", "POST", "/private/doc", "", flags&1 == 0},
				{"allowed", "GET", "/public/doc", "", flags&5 == 0},
				{"cached", "GET", "/private/doc", cached.Token, true},
				{"cached", "POST", "/private/doc", cached.Token, flags&1 == 0},
				{"cached", "GET", "/public/doc", cached.Token, flags&5 == 0},
				{"cached", "GET", "/private/doc", badCached.Token, false},
			} {
				req, err := http.NewRequestWithContext(t.Context(), tc.method, srv.URL+tc.path, nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Header.Set("X-Test-Identity", tc.identity)
				if tc.token != "" {
					req.Header.Set("Authorization", "Bearer "+tc.token)
				}
				resp, err := client.Do(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
				_ = resp.Body.Close()
				want := http.StatusForbidden
				if tc.allowed {
					want = http.StatusNoContent
				}
				if resp.StatusCode != want {
					t.Fatalf("%s %s %s: status %d, want %d", tc.identity, tc.method, tc.path, resp.StatusCode, want)
				}
			}
			if diff := cmp.Diff(before.AsMap(), identities["allowed"].AsMap()); diff != "" {
				t.Fatal("claims changed:", diff)
			}
			if diff := cmp.Diff(before.GetData(), identities["allowed"].GetData()); diff != "" {
				t.Fatal("ACL data changed:", diff)
			}
		})
	}
}
