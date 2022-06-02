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
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/util"
	"net/http"
	"strings"
)

func (p *Portal) handleHTTPExternalLogout(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, authMethod string) error {
	p.disableClientCache(w)
	authRealm, err := getEndpoint(r.URL.Path, "/"+authMethod+"/")
	if err != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
	}
	authRealm = strings.Split(authRealm, "/")[0]
	provider := p.getIdentityProviderByRealm(authRealm)
	if provider == nil {
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}
	providerLogoutURL := provider.GetLogoutURL()
	if providerLogoutURL == "" {
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}

	switch provider.GetDriver() {
	case "cognito":
		// Add redirect_uri to the logout URL.
		providerLogoutURL += "&logout_uri=" + util.GetCurrentBaseURL(r) + "/logout"
	}

	return p.handleHTTPRedirectExternal(ctx, w, r, rr, providerLogoutURL)
}
