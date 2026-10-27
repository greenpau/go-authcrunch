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
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/identity/attachment"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
)

type accountConnection struct {
	browser, destination [32]byte
	source               requests.ExternalIdentity
	csrf, store, base    string
	expires              time.Time
	startedAt            int64
	loginID              string
}

type accountConnectionStore struct {
	mu      sync.Mutex
	pending map[string]accountConnection
}

func connectedAccountsRouteIndex(path string) int {
	i := strings.Index(path+"/", "/connected-accounts/")
	if i < 0 {
		return -1
	}
	prefix := path[:i] + "/"
	for _, namespace := range []string{"/provider/", "/cross-device/", "/api/", "/qrcode/", "/profile/", "/operator/", "/documents/", "/sandbox/", "/register/", "/apps/", "/barcode/", "/saml/", "/oauth2/", "/basic/", "/assets/", "/favicon"} {
		if strings.Contains(prefix, namespace) {
			return -1
		}
	}
	return i
}

func (p *Portal) connectedAccountSession(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) *user.User {
	// This browser interaction requires one access cookie, independently of
	// the validator's optional header/query credential transports.
	accessCookies := r.CookiesNamed(p.cookie.AccessTokenCookieName)
	if len(accessCookies) != 1 || accessCookies[0].Value == "" {
		return nil
	}
	parsed, err := p.authorizeRequest(ctx, w, r, rr)
	if err != nil || parsed == nil || parsed.Claims == nil || parsed.TokenSource != "cookie" || parsed.Token != accessCookies[0].Value {
		return nil
	}
	cached, err := p.sessions.GetForToken(parsed.Claims.ID, parsed.Token)
	if err != nil {
		return nil
	}
	return cached
}

func (p *Portal) handleConnectedAccounts(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	p.disableClientCache(w)
	// Suppress ticket paths while preserving Origin on browser form POSTs.
	w.Header().Set("Referrer-Policy", "strict-origin")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; img-src 'self'; font-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		return p.handleHTTPError(ctx, w, r, rr, http.StatusMethodNotAllowed)
	}
	if r.Method == http.MethodPost {
		if !validCrossDeviceOrigin(r) {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusForbidden)
		}
		if status := parseCrossDeviceForm(w, r); status != 0 {
			return p.handleHTTPError(ctx, w, r, rr, status)
		}
		if len(r.PostForm) != 2 || len(r.PostForm["csrf"]) != 1 || len(r.PostForm["action"]) != 1 {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
		}
	}
	// Require an existing unambiguous browser cookie; never create a binding
	// from a connection URL or from bearer-token authentication.
	cookies := r.CookiesNamed(p.cookie.SessionIDCookieName)
	if len(cookies) != 1 || cookies[0].Value == "" {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
	}
	rr.Upstream.SessionID = cookies[0].Value
	browser := sha256.Sum256([]byte(cookies[0].Value))
	usr := p.connectedAccountSession(ctx, w, r, rr)
	if usr == nil {
		return p.handleHTTPRedirect(ctx, w, r, rr, "/login")
	}
	endpoint := strings.TrimPrefix(r.URL.Path, rr.Upstream.BasePath+"connected-accounts")
	if endpoint == "" || endpoint == "/" {
		if r.Method != http.MethodGet {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusMethodNotAllowed)
		}
		return p.connectedAccountsPage(ctx, w, r, rr, usr, browser)
	}
	ticket := strings.TrimPrefix(endpoint, "/")
	if strings.Contains(ticket, "/") || len(ticket) != 48 {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusNotFound)
	}
	p.accountConnections.mu.Lock()
	defer p.accountConnections.mu.Unlock()
	pending, ok := p.accountConnections.pending[ticket]
	if !ok || pending.browser != browser || pending.base != rr.Upstream.BasePath || !time.Now().Before(pending.expires) {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusGone)
	}
	if r.Method == http.MethodPost && subtle.ConstantTimeCompare([]byte(r.PostForm.Get("csrf")), []byte(pending.csrf)) != 1 {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusForbidden)
	}
	if pending.startedAt == 0 {
		if r.Method != http.MethodPost || r.PostForm.Get("action") != "start" || usr.ExternalIdentity != pending.source {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusForbidden)
		}
		pending.startedAt = time.Now().Unix()
		p.accountConnections.pending[ticket] = pending
		target := rr.Upstream.BaseURL + rr.Upstream.BasePath + "connected-accounts/" + ticket
		return p.handleHTTPRedirectSeeOther(ctx, w, r, rr, "/login?fresh=1&redirect_url="+url.QueryEscape(target))
	}
	if pending.destination == ([32]byte{}) || pending.destination != sha256.Sum256([]byte(usr.Token)) || usr.Authenticator.Method != "local" || usr.Authenticator.Name != pending.store || usr.LoginEvidence.AuthenticatedAt < pending.startedAt || usr.LoginEvidence.Method == "api_key" || len(usr.LoginMethods) == 0 {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusForbidden)
	}
	backend := p.getIdentityStoreByRealm(usr.Authenticator.Realm)
	store, ok := backend.(attachment.Store)
	if !ok || backend.GetName() != pending.store {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusForbidden)
	}
	if err := store.WithRefreshIdentity(ctx, usr.LoginEvidence, func(identity.RefreshIdentity) error { return nil }); err != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
	}
	if r.Method == http.MethodGet {
		return p.renderConnectedAccounts(ctx, w, r, rr, map[string]any{"view": "confirm", "provider": pending.source.Provider, "username": usr.LoginUsername, "csrf": pending.csrf, "ticket": ticket})
	}
	if r.PostForm.Get("action") == "cancel" {
		delete(p.accountConnections.pending, ticket)
		return p.handleHTTPRedirectSeeOther(ctx, w, r, rr, "/connected-accounts/")
	}
	if r.PostForm.Get("action") != "connect" {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusBadRequest)
	}
	// Consume before attempting the commit. Storage errors require starting a
	// fresh operation; no concurrent confirmation can repeat the mutation.
	delete(p.accountConnections.pending, ticket)
	if _, err := store.ConnectExternalAccount(ctx, attachment.ExternalAccount(pending.source), pending.source.Evidence, usr.LoginEvidence); err != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusConflict)
	}
	return p.renderConnectedAccounts(ctx, w, r, rr, map[string]any{"view": "connected", "provider": pending.source.Provider, "username": usr.LoginUsername})
}

// A timestamp alone cannot prove that a login began after this operation:
// completed logins in either browser may share its whole-second auth_time.
// Capture the actual fresh local sandbox, then bind its issued token on success.
func (p *Portal) connectionLoginTicket(r *http.Request, proof *user.User) string {
	if proof == nil || !proof.LoginFresh || !proof.LoginReturnURLBound || proof.Authenticator.Method != "local" || proof.Authenticator.TempSessionID == "" || proof.ExternalIdentity.Evidence.UserID != "" {
		return ""
	}
	target := p.trustedConnectionReturnURL(r, proof.LoginReturnURL)
	if target == "" {
		return ""
	}
	return target[len(target)-48:]
}

func (p *Portal) bindConnectedAccountLogin(r *http.Request, proof *user.User) {
	ticket := p.connectionLoginTicket(r, proof)
	if ticket == "" {
		return
	}
	p.accountConnections.mu.Lock()
	defer p.accountConnections.mu.Unlock()
	pending, ok := p.accountConnections.pending[ticket]
	if !ok || pending.store != proof.Authenticator.Name || !time.Now().Before(pending.expires) {
		return
	}
	pending.loginID = proof.Authenticator.TempSessionID
	pending.destination = [32]byte{}
	p.accountConnections.pending[ticket] = pending
}

func (p *Portal) completeConnectedAccountLogin(r *http.Request, proof, issued *user.User) {
	if issued == nil || issued.Token == "" {
		return
	}
	ticket := p.connectionLoginTicket(r, proof)
	if ticket == "" {
		return
	}
	p.accountConnections.mu.Lock()
	defer p.accountConnections.mu.Unlock()
	pending, ok := p.accountConnections.pending[ticket]
	if !ok || pending.store != proof.Authenticator.Name || pending.loginID != proof.Authenticator.TempSessionID || !time.Now().Before(pending.expires) {
		return
	}
	pending.destination = sha256.Sum256([]byte(issued.Token))
	p.accountConnections.pending[ticket] = pending
}

func (p *Portal) connectedAccountsPage(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User, browser [32]byte) error {
	if usr.ExternalIdentity.Evidence.UserID == "" {
		backend := p.getIdentityStoreByRealm(usr.Authenticator.Realm)
		store, ok := backend.(attachment.Store)
		if !ok || usr.Authenticator.Method != "local" {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusForbidden)
		}
		var accounts []identity.ExternalAccount
		err := store.WithRefreshIdentity(ctx, usr.LoginEvidence, func(current identity.RefreshIdentity) error { accounts = current.ExternalAccounts; return nil })
		if err != nil {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
		}
		return p.renderConnectedAccounts(ctx, w, r, rr, map[string]any{"view": "accounts", "username": usr.LoginUsername, "accounts": accounts})
	}
	a, _, err := p.externalIdentityAttachment(usr.ExternalIdentity)
	if err != nil || a.StoreName() == "" {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusForbidden)
	}
	store, err := a.Store()
	if err != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusServiceUnavailable)
	}
	var current identity.RefreshIdentity
	err = store.WithRefreshIdentity(ctx, usr.ExternalIdentity.Evidence, func(snapshot identity.RefreshIdentity) error { current = snapshot; return nil })
	if err != nil {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
	}
	if !current.ExternallyProvisioned {
		return p.renderConnectedAccounts(ctx, w, r, rr, map[string]any{"view": "accounts", "username": current.Username, "accounts": current.ExternalAccounts})
	}
	now := time.Now()
	if usr.ExternalIdentity.Evidence.AuthenticatedAt <= 0 || now.Unix()-usr.ExternalIdentity.Evidence.AuthenticatedAt > 300 {
		return p.renderConnectedAccounts(ctx, w, r, rr, map[string]any{"view": "reauthenticate"})
	}
	// Linking needs an enabled local login realm in this portal.
	var enabled bool
	for _, backend := range p.identityStores {
		if backend.GetKind() == "local" && backend.GetName() == a.StoreName() {
			enabled = true
		}
	}
	if !enabled {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusForbidden)
	}
	ticket, csrf := util.GetRandomString(48), util.GetRandomString(48)
	p.accountConnections.mu.Lock()
	if p.accountConnections.pending == nil {
		p.accountConnections.pending = make(map[string]accountConnection)
	}
	for key, pending := range p.accountConnections.pending {
		if !now.Before(pending.expires) {
			delete(p.accountConnections.pending, key)
		}
	}
	if len(p.accountConnections.pending) >= 4096 {
		p.accountConnections.mu.Unlock()
		return p.handleHTTPError(ctx, w, r, rr, http.StatusTooManyRequests)
	}
	p.accountConnections.pending[ticket] = accountConnection{browser: browser, source: usr.ExternalIdentity, csrf: csrf, store: a.StoreName(), base: rr.Upstream.BasePath, expires: now.Add(5 * time.Minute)}
	p.accountConnections.mu.Unlock()
	return p.renderConnectedAccounts(ctx, w, r, rr, map[string]any{"view": "start", "provider": usr.ExternalIdentity.Provider, "csrf": csrf, "ticket": ticket})
}

func (p *Portal) renderConnectedAccounts(ctx context.Context, w http.ResponseWriter, _ *http.Request, rr *requests.Request, data map[string]any) error {
	args := p.ui.GetArgs()
	args.BaseURL(rr.Upstream.BasePath)
	args.PageTitle = args.Translate("connected_accounts_title")
	maps.Copy(args.Data, data)
	body, err := p.ui.Render("connected_accounts", args)
	if err != nil {
		return fmt.Errorf("render connected accounts: %w", err)
	}
	return p.handleHTTPRenderHTML(ctx, w, http.StatusOK, body.Bytes())
}

// This exception admits only a server-created pending connection in the same
// browser and origin. Ordinary redirect_url values retain the operator allowlist.
func (p *Portal) trustedConnectionReturnURL(r *http.Request, raw string) string {
	target, err := url.Parse(raw)
	origin, originErr := getWebAuthnExpectedOrigin(r)
	if err != nil || originErr != nil || target.Scheme+"://"+target.Host != origin || target.RawQuery != "" || target.Fragment != "" || target.RawPath != "" || target.User != nil {
		return ""
	}
	i := connectedAccountsRouteIndex(target.Path)
	if i < 0 {
		return ""
	}
	ticket := strings.TrimPrefix(target.Path[i:], "/connected-accounts/")
	if len(ticket) != 48 || strings.Contains(ticket, "/") {
		return ""
	}
	cookies := r.CookiesNamed(p.cookie.SessionIDCookieName)
	if len(cookies) != 1 {
		return ""
	}
	browser := sha256.Sum256([]byte(cookies[0].Value))
	p.accountConnections.mu.Lock()
	defer p.accountConnections.mu.Unlock()
	pending, exists := p.accountConnections.pending[ticket]
	if !exists || pending.browser != browser || target.Path != pending.base+"connected-accounts/"+ticket || pending.startedAt == 0 || !time.Now().Before(pending.expires) {
		return ""
	}
	return raw
}

func (p *Portal) trustedLoginFlowReturnURL(r *http.Request, raw string) string {
	if target := p.trustedLoginReturnURL(raw); target != "" {
		return target
	}
	return p.trustedConnectionReturnURL(r, raw)
}

func (p *Portal) revokeConnectedAccounts(r *http.Request) {
	p.accountConnections.mu.Lock()
	defer p.accountConnections.mu.Unlock()
	for _, cookie := range r.CookiesNamed(p.cookie.SessionIDCookieName) {
		browser := sha256.Sum256([]byte(cookie.Value))
		for ticket, pending := range p.accountConnections.pending {
			if pending.browser == browser {
				delete(p.accountConnections.pending, ticket)
			}
		}
	}
}
