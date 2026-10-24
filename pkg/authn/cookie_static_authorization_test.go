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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestStaticAssetAuthorizationCookieOwnership(t *testing.T) {
	p := newRefreshPortal(t, false, false).portal
	refused := privateKeysAdminToken(t, p, []string{"app/user"}, time.Hour)
	admitted := privateKeysAdminToken(t, p, []string{"authp/user"}, time.Hour)
	expired := privateKeysAdminToken(t, p, []string{"app/user"}, -time.Hour)
	parts := strings.Split(refused, ".")
	if parts[2][0] == 'A' {
		parts[2] = "B" + parts[2][1:]
	} else {
		parts[2] = "A" + parts[2][1:]
	}
	forged := strings.Join(parts, ".")
	for _, mount := range []string{"", "/tenant/auth"} {
		for _, asset := range []string{"/favicon.ico", "/assets/images/favicon.svg"} {
			for _, tc := range []struct {
				name, token string
				admitted    bool
				deleted     bool
			}{
				{name: "resource-only", token: refused},
				{name: "portal-admitted", token: admitted, admitted: true},
				{name: "malformed", token: strings.Repeat("invalid-token", 4), deleted: true},
				{name: "below-discovery-length", token: "invalid-token"},
				{name: "forged", token: forged, deleted: true},
				{name: "expired", token: expired, deleted: true},
				{name: "anonymous"},
			} {
				t.Run(mount+asset+"/"+tc.name, func(t *testing.T) {
					r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+mount+asset, nil)
					if tc.token != "" {
						r.AddCookie(&http.Cookie{Name: p.cookie.AccessTokenCookieName, Value: tc.token})
					}
					w, rr := httptest.NewRecorder(), requests.NewRequest()
					usr, err := p.authorizeRequest(t.Context(), w, r, rr)
					if err != nil || (usr != nil) != tc.admitted || rr.Response.Authenticated != tc.admitted {
						t.Fatal("asset authorization changed portal admission")
					}
					deleted := false
					for _, cookie := range w.Result().Cookies() {
						if cookie.Name != p.cookie.AccessTokenCookieName || cookie.MaxAge >= 0 {
							t.Fatal("asset authorization issued an unexpected cookie")
						}
						deleted = true
					}
					if deleted != tc.deleted {
						t.Fatalf("access cookie deletion = %t, want %t", deleted, tc.deleted)
					}
				})
			}
		}
	}
}

func TestStaticAssetRefusalDoesNotGrantRestrictedAccess(t *testing.T) {
	p := newRefreshPortal(t, false, false).portal
	token := privateKeysAdminToken(t, p, []string{"app/user"}, time.Hour)
	original := ui.StaticAssets
	isolated, err := ui.NewStaticAssetLibrary()
	if err != nil {
		t.Fatal(err)
	}
	ui.StaticAssets = isolated
	t.Cleanup(func() { ui.StaticAssets = original })
	asset, err := isolated.GetAsset("assets/images/favicon.svg")
	if err != nil {
		t.Fatal(err)
	}
	asset.Restricted = true
	for _, mount := range []string{"", "/tenant/auth"} {
		t.Run(mount, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, refreshTestOrigin+mount+"/assets/images/favicon.svg", nil)
			r.AddCookie(&http.Cookie{Name: p.cookie.AccessTokenCookieName, Value: token})
			w, rr := httptest.NewRecorder(), requests.NewRequest()
			if err := p.ServeHTTP(t.Context(), w, r, rr); err != nil {
				t.Fatal(err)
			}
			if w.Code != http.StatusUnauthorized || rr.Response.Authenticated {
				t.Fatal("resource-only identity gained restricted portal asset access")
			}
			for _, cookie := range w.Result().Cookies() {
				if cookie.Name == p.cookie.AccessTokenCookieName {
					t.Fatal("restricted asset refusal changed the resource access cookie")
				}
			}
		})
	}
}
