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
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/apiauth"
	"github.com/greenpau/go-authcrunch/pkg/authn/refresh"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

const refreshRequestHeader = "X-Authcrunch-Refresh"

func (p *Portal) refreshPath(operation string) string {
	return strings.TrimSuffix(p.config.RefreshTokens.BasePath, "/") + "/api/" + operation
}

func (p *Portal) validateRefreshOrigin(r *http.Request) error {
	c := p.config.RefreshTokens
	// The embedding server must normalize forwarded metadata, as for other portal
	// routes. These values are checked against an explicit configured public origin.
	secure := r.TLS != nil || r.URL.Scheme == "https"
	if forwarded := r.Header.Get("X-Forwarded-Proto"); forwarded != "" {
		secure = forwarded == "https"
	}
	if !secure || "https://"+addrutil.GetSourceHost(r) != c.PublicOrigin {
		return refresh.ErrDenied
	}
	mount := strings.TrimSuffix(c.BasePath, "/")
	if r.URL.RawPath != "" || (r.URL.Path != c.BasePath && !strings.HasPrefix(r.URL.Path, mount+"/")) {
		return refresh.ErrDenied
	}
	return nil
}

func (p *Portal) validateRefreshLogin(r *http.Request, transport string) error {
	if err := p.validateRefreshOrigin(r); err != nil {
		return err
	}
	switch transport {
	case refresh.CookieTransport:
		if values := r.Header.Values("Origin"); len(values) > 1 || (len(values) == 1 && values[0] != p.config.RefreshTokens.PublicOrigin) {
			return refresh.ErrDenied
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			return refresh.ErrDenied
		}
	case refresh.BodyTransport:
		if !p.config.RefreshTokens.BodyTransportEnabled || r.Header.Get("Cookie") != "" {
			return refresh.ErrDenied
		}
		for _, name := range []string{"Origin", "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest"} {
			if len(r.Header.Values(name)) != 0 {
				return refresh.ErrDenied
			}
		}
	default:
		return refresh.ErrDenied
	}
	return nil
}

// parseRefreshBody accepts one JSON object and at most one string credential.
// Streaming field parsing rejects duplicate keys, including escaped spellings.
func parseRefreshBody(w http.ResponseWriter, r *http.Request) (string, bool, error) {
	r.Body = http.MaxBytesReader(w, r.Body, 1024)
	d := json.NewDecoder(r.Body)
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return "", false, refresh.ErrInvalid
	}
	token, present := "", false
	for d.More() {
		key, err := d.Token()
		if err != nil || key != "refresh_token" || present {
			return "", false, refresh.ErrInvalid
		}
		present = true
		if err := d.Decode(&token); err != nil || token == "" {
			return "", false, refresh.ErrInvalid
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return "", false, refresh.ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return "", false, refresh.ErrInvalid
	}
	return token, present, nil
}

func (p *Portal) handleAPIRefreshToken(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	p.disableClientCache(w)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Content-Type", "application/json")
	if p.refresh == nil {
		return p.handleJSONError(ctx, w, http.StatusNotFound, "Refresh is unavailable")
	}
	logout := r.URL.Path == p.refreshPath("logout")
	if r.URL.RawPath != "" || (!logout && r.URL.Path != p.refreshPath("refresh_token")) {
		return p.handleJSONError(ctx, w, http.StatusNotFound, "Unknown refresh endpoint")
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		return p.handleJSONError(ctx, w, http.StatusMethodNotAllowed, "POST required")
	}
	if err := p.validateRefreshOrigin(r); err != nil {
		return p.handleJSONError(ctx, w, http.StatusForbidden, "Invalid request origin")
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		return p.handleJSONError(ctx, w, http.StatusBadRequest, "Query parameters are not accepted")
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "application/json" {
		return p.handleJSONError(ctx, w, http.StatusUnsupportedMediaType, "JSON required")
	}
	token, body, err := parseRefreshBody(w, r)
	if err != nil {
		return p.handleJSONError(ctx, w, http.StatusBadRequest, "Invalid refresh request")
	}
	cookies := r.CookiesNamed(p.config.RefreshTokens.CookieName)
	transport := refresh.CookieTransport
	if body {
		transport = refresh.BodyTransport
	}
	if len(cookies) > 1 || (body && len(cookies) != 0) {
		return p.handleJSONError(ctx, w, http.StatusBadRequest, "Ambiguous refresh credential")
	}
	if err := p.validateRefreshLogin(r, transport); err != nil {
		return p.handleJSONError(ctx, w, http.StatusForbidden, "Invalid refresh transport")
	}
	if transport == refresh.CookieTransport {
		if len(r.Header.Values("Origin")) != 1 || r.Header.Get("Origin") != p.config.RefreshTokens.PublicOrigin || len(r.Header.Values(refreshRequestHeader)) != 1 || r.Header.Get(refreshRequestHeader) != "1" {
			return p.handleJSONError(ctx, w, http.StatusForbidden, "Invalid browser refresh request")
		}
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" {
			return p.handleJSONError(ctx, w, http.StatusForbidden, "Invalid fetch context")
		}
		if mode := r.Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "cors" && mode != "same-origin" {
			return p.handleJSONError(ctx, w, http.StatusForbidden, "Invalid fetch mode")
		}
		if dest := r.Header.Get("Sec-Fetch-Dest"); dest != "" && dest != "empty" {
			return p.handleJSONError(ctx, w, http.StatusForbidden, "Invalid fetch destination")
		}
		if len(cookies) == 1 {
			token = cookies[0].Value
		}
	}
	if logout {
		if token != "" {
			if err := p.refresh.Logout(ctx, token, transport); err != nil {
				// Malformed credentials are not a successful server logout.
				return p.refreshError(ctx, w, err)
			}
		}
		if transport == refresh.CookieTransport {
			p.deleteRefreshCookies(w, r)
		}
		rr.Response.Code = http.StatusOK
		return json.NewEncoder(w).Encode(map[string]bool{"logged_out": true})
	}
	tokens, err := p.refresh.Refresh(context.WithValue(ctx, refreshRequestContextKey{}, r), token, transport)
	if err != nil {
		return p.refreshError(ctx, w, err)
	}
	if transport == refresh.CookieTransport {
		u, err := p.userFromRefresh(tokens)
		if err != nil {
			return p.refreshError(ctx, w, err)
		}
		if err := p.sessions.Add(u.Claims.ID, u); err != nil {
			return p.refreshError(ctx, w, err)
		}
		p.deliverRefreshCookies(w, r, tokens)
	}
	rr.Response.Code = http.StatusOK
	return json.NewEncoder(w).Encode(p.refreshResponse(tokens, transport))
}

func (p *Portal) refreshError(ctx context.Context, w http.ResponseWriter, err error) error {
	if errors.Is(err, refresh.ErrInvalid) || errors.Is(err, refresh.ErrDenied) {
		return p.handleJSONError(ctx, w, http.StatusUnauthorized, "Reauthentication required")
	}
	return p.handleJSONError(ctx, w, http.StatusServiceUnavailable, "Refresh temporarily unavailable")
}

func (p *Portal) refreshResponse(tokens *refresh.Result, transport string) *apiauth.AuthResponse {
	response := &apiauth.AuthResponse{Authenticated: true, SessionID: tokens.SessionID, AccessExpiresAt: tokens.AccessExpiresAt, RefreshExpiresAt: tokens.RefreshExpiresAt, SessionExpiresAt: tokens.AbsoluteExpiresAt}
	if transport == refresh.BodyTransport {
		response.AccessToken, response.AccessTokenName = tokens.AccessToken, p.cookie.AccessTokenCookieName
		response.RefreshToken, response.RefreshTokenName = tokens.RefreshToken, p.config.RefreshTokens.CookieName
	}
	return response
}

func (p *Portal) deliverRefreshCookies(w http.ResponseWriter, r *http.Request, tokens *refresh.Result) {
	// Retain the access cookie's configured domain/path, but bound its lifetime to
	// this signed JWT and enforce browser credential protection for refresh mode.
	access, err := http.ParseSetCookie(p.cookie.GetAccessTokenCookie(addrutil.GetSourceHost(r), tokens.AccessToken))
	if err == nil {
		access.Secure, access.HttpOnly = true, true
		access.Expires = time.Unix(tokens.AccessExpiresAt, 0).UTC()
		access.MaxAge = max(1, int(tokens.AccessExpiresAt-time.Now().Unix()))
		if access.SameSite == http.SameSiteDefaultMode || access.SameSite == 0 {
			access.SameSite = http.SameSiteLaxMode
		}
		// Browser login may have already prepared an access cookie in grantAccess.
		previous := w.Header().Values("Set-Cookie")
		w.Header().Del("Set-Cookie")
		for _, raw := range previous {
			c, err := http.ParseSetCookie(raw)
			if err != nil || (c.Name != access.Name && c.Name != p.config.RefreshTokens.CookieName) {
				w.Header().Add("Set-Cookie", raw)
			}
		}
		http.SetCookie(w, access)
	}
	c := p.config.RefreshTokens
	http.SetCookie(w, &http.Cookie{Name: c.CookieName, Value: tokens.RefreshToken, Path: c.BasePath, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: time.Unix(tokens.RefreshExpiresAt, 0).UTC(), MaxAge: max(1, int(tokens.RefreshExpiresAt-time.Now().Unix()))})
	w.Header().Add("Set-Cookie", p.cookie.GetDeleteRefreshTokenCookie(c.BasePath))
	w.Header().Del("Authorization")
	w.Header().Set("Cache-Control", "no-store")
}

func (p *Portal) deleteRefreshCookies(w http.ResponseWriter, r *http.Request) {
	c := p.config.RefreshTokens
	http.SetCookie(w, &http.Cookie{Name: c.CookieName, Path: c.BasePath, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: time.Unix(0, 0).UTC(), MaxAge: -1})
	h := addrutil.GetSourceHost(r)
	for _, raw := range []string{p.cookie.GetDeleteAccessTokenCookie(h), p.cookie.GetDeleteRefreshTokenCookie(c.BasePath), p.cookie.GetDeleteSessionIDCookie(h), p.cookie.GetDeleteSandboxIDCookie(c.BasePath), p.cookie.GetDeleteRefererCookie(c.BasePath), p.cookie.GetDeleteIdentityTokenCookie(p.cookie.IdentityTokenCookieName, c.BasePath)} {
		if cookie, err := http.ParseSetCookie(raw); err == nil {
			cookie.Secure, cookie.HttpOnly, cookie.MaxAge = true, true, -1
			http.SetCookie(w, cookie)
		}
	}
}

// A completed browser login replaces the previous browser session, including
// when the new realm is access-only. Otherwise an old refresh cookie could
// silently restore the previous identity after its replacement JWT expires.
func (p *Portal) revokeRefreshOnLogin(ctx context.Context, w http.ResponseWriter, r *http.Request) error {
	if p.refresh == nil {
		return nil
	}
	for _, c := range r.CookiesNamed(p.config.RefreshTokens.CookieName) {
		if err := p.refresh.Logout(ctx, c.Value, refresh.CookieTransport); err != nil && !errors.Is(err, refresh.ErrInvalid) {
			return err
		}
	}
	c := p.config.RefreshTokens
	http.SetCookie(w, &http.Cookie{Name: c.CookieName, Path: c.BasePath, Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode, Expires: time.Unix(0, 0).UTC(), MaxAge: -1})
	return nil
}
