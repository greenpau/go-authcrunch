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
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/idp"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// Preserve earlier namespaces: an OAuth callback containing /provider/ remains
// OAuth, while a provider realm named cross-device/logout stays a provider route.
func providerLoginRouteIndex(path string) int {
	i := strings.Index(path, "/provider/")
	if i < 0 {
		return -1
	}
	prefix := path[:i] + "/"
	for _, namespace := range []string{"/api/", "/qrcode/", "/profile/", "/sandbox/", "/register/", "/apps/sso", "/apps/mobile-access", "/barcode/mfa/", "/saml/", "/oauth2/", "/basic/login", "/assets/", "/favicon", "/cross-device/"} {
		if strings.Contains(prefix, namespace) {
			return -1
		}
	}
	return i
}
func validProviderRealm(realm string) bool {
	if realm == "" || len(realm) > 64 {
		return false
	}
	for _, ch := range realm {
		if (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') && (ch < '0' || ch > '9') && ch != '-' && ch != '_' {
			return false
		}
	}
	return true
}
func (p *Portal) handleHTTPProviderLogin(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	p.disableClientCache(w)
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		return p.handleHTTPError(ctx, w, r, rr, http.StatusMethodNotAllowed)
	}
	i := providerLoginRouteIndex(r.URL.Path)
	if i < 0 {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
	}
	realm := r.URL.Path[i+len("/provider/"):]
	if !validProviderRealm(realm) {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
	}
	provider := p.getIdentityProviderByRealm(realm)
	login, ok := provider.(idp.HTTPLoginProvider)
	if !ok || p.getIdentityStoreByRealm(realm) != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
	}
	// Discard caller-retained verification state before crossing the provider boundary.
	rr.Response = requests.Response{}
	rr.User = requests.User{}
	rr.Authentication = requests.AuthenticationEvidence{}
	rr.Upstream.Method = "provider"
	rr.Upstream.Realm = realm
	rr.Flags.Enabled = true
	result, err := login.Login(ctx, r)
	if err != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
	}
	if result == nil || (result.Identity == nil) == (result.RedirectURL == "") {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadGateway)
	}
	if result.Identity != nil && result.Identity.Validate() != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadGateway)
	}
	if result.RedirectURL != "" {
		target, err := url.Parse(result.RedirectURL)
		if err != nil || len(result.RedirectURL) > 8192 || target.Scheme != "https" || target.Hostname() == "" || target.User != nil || strings.ContainsAny(result.RedirectURL, "\r\n\x00") {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusBadGateway)
		}
	}
	if c := result.Cookie; c != nil {
		if c.Valid() != nil || !c.Secure || !c.HttpOnly || c.Domain != "" || c.Path != r.URL.Path || (c.SameSite != http.SameSiteLaxMode && c.SameSite != http.SameSiteStrictMode) || c.Name != login.GetLoginCookieName() || p.cookie.ValidateProviderLoginCookieName(c.Name, c.Path) != nil {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusBadGateway)
		}
		http.SetCookie(w, c)
	}
	if result.RedirectURL != "" {
		http.Redirect(w, r, result.RedirectURL, http.StatusFound)
		return nil
	}
	identity := result.Identity
	rr.Response.Payload = map[string]any{"sub": identity.Subject, "email": identity.Email, "name": identity.Name, "roles": append([]string(nil), identity.Roles...), "origin": realm}
	if err := p.authorizeLoginRequest(ctx, w, r, rr); err != nil {
		code := rr.Response.Code
		if code < 400 || code > 599 {
			code = http.StatusInternalServerError
		}
		return p.handleHTTPError(ctx, w, r, rr, code)
	}
	w.WriteHeader(rr.Response.Code)
	return nil
}
