// Copyright 2022 Paul Greenberg greenpau@outlook.com
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
	"context"
	"net/http/httptest"
	"testing"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

func TestPortalAppRoutes(t *testing.T) {
	for _, mount := range []string{"", "/auth", "/xauth", "/tenant/security", "/documents-team", "/team-profile"} {
		for _, app := range []string{"profile", "operator", "documents"} {
			for _, child := range []string{"", "/", "/preferences", "/users/local/alice", "/api/server/user", "/provider/local", "/cross-device", "/connected-accounts/"} {
				pathname := mount + "/" + app + child
				name, index := portalAppRoute(pathname)
				if name != app || index != len(mount) {
					t.Fatalf("wrong app boundary for %s", pathname)
				}
				request := httptest.NewRequest("GET", "https://example.test"+pathname, nil)
				rr := requests.NewRequest()
				extractBasePath(context.Background(), request, rr)
				if rr.Upstream.BasePath != mount+"/" || portalAppName(request, rr) != app {
					t.Fatalf("wrong app mount for %s", pathname)
				}
				if crossDeviceRouteIndex(pathname) >= 0 || providerLoginRouteIndex(pathname) >= 0 || connectedAccountsRouteIndex(pathname) >= 0 {
					t.Fatalf("another namespace stole %s", pathname)
				}
			}
		}
	}
	for _, pathname := range []string{"/xauth/documents-neighbor/", "/api/documents/file/profile/fetch", "/auth/provider/operator/", "/auth/oauth2/documents", "/auth/assets/profile/logo.svg", "/favicon.svg/documents/", "/auth/connected-accounts/documents/"} {
		if name, _ := portalAppRoute(pathname); name != "" {
			t.Fatalf("app stole another namespace: %s", pathname)
		}
	}
}
