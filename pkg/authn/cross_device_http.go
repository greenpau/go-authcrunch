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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"maps"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/token_refresh"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
	"github.com/skip2/go-qrcode"
)

const maxCrossDeviceFormSize int64 = 4 << 10

// A cross-device segment is a route only outside an existing route namespace.
// For example, /oauth2/cross-device names a provider, while a later /oauth2/
// inside /cross-device/ is an invalid transfer endpoint, not a provider route.
func crossDeviceRouteIndex(path string) int {
	i := strings.Index(path+"/", "/cross-device/")
	if i < 0 {
		return -1
	}
	prefix := path[:i] + "/"
	for _, namespace := range []string{"/provider/", "/api/", "/qrcode/", "/profile/", "/sandbox/", "/register/", "/apps/sso", "/apps/mobile-access", "/barcode/mfa/", "/saml/", "/oauth2/", "/basic/login", "/assets/", "/favicon"} {
		if strings.Contains(prefix, namespace) {
			return -1
		}
	}
	return i
}

func validCrossDeviceOrigin(r *http.Request) bool {
	origin, err := getWebAuthnExpectedOrigin(r)
	return err == nil && strings.HasPrefix(origin, "https://") && len(r.Header.Values("Origin")) == 1 && r.Header.Get("Origin") == origin && validAPIRequestOrigin(r)
}

// parseCrossDeviceForm returns zero on success, otherwise an HTTP error status.
func parseCrossDeviceForm(w http.ResponseWriter, r *http.Request) int {
	if len(r.Header.Values("Content-Type")) != 1 {
		return http.StatusBadRequest
	}
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil {
		return http.StatusBadRequest
	}
	if mediaType != "application/x-www-form-urlencoded" {
		return http.StatusUnsupportedMediaType
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxCrossDeviceFormSize)
	if err := r.ParseForm(); err != nil {
		if _, oversized := errors.AsType[*http.MaxBytesError](err); oversized {
			return http.StatusRequestEntityTooLarge
		}
		return http.StatusBadRequest
	}
	for _, values := range r.PostForm {
		if len(values) != 1 {
			return http.StatusBadRequest
		}
	}
	return 0
}

func (p *Portal) crossDeviceBinding(r *http.Request) string {
	cookies := r.CookiesNamed(p.cookie.CrossDeviceSessionIDCookieName)
	if len(cookies) != 1 || len(cookies[0].Value) != 26 {
		return ""
	}
	return cookies[0].Value
}

func crossDeviceResponse(w http.ResponseWriter, status int, data map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func crossDeviceFailure(w http.ResponseWriter, status int) {
	crossDeviceResponse(w, status, map[string]any{"status": "unavailable"})
}

func (p *Portal) handleCrossDevice(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) error {
	p.disableClientCache(w)
	// Suppress activation paths/query strings while retaining the Origin header
	// on same-origin form POSTs. Chrome sends Origin:null under no-referrer.
	w.Header().Set("Referrer-Policy", "strict-origin")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
	w.Header().Set("X-Frame-Options", "DENY")
	if p.crossDevice == nil {
		http.NotFound(w, r)
		return nil
	}
	origin, err := getWebAuthnExpectedOrigin(r)
	if err != nil || !strings.HasPrefix(origin, "https://") {
		crossDeviceFailure(w, http.StatusForbidden)
		return nil
	}
	route := strings.TrimPrefix(r.URL.Path, rr.Upstream.BasePath+"cross-device")
	if r.URL.RawPath != "" || (route != "" && route != "/activate" && route != "/confirm" && route != "/start" && route != "/begin" && route != "/poll" && route != "/cancel") {
		http.NotFound(w, r)
		return nil
	}
	want := http.MethodPost
	if route == "" || route == "/activate" || (route == "/confirm" && r.Method == http.MethodGet) {
		want = http.MethodGet
	}
	if r.Method != want {
		allow := want
		if route == "/confirm" {
			allow = http.MethodGet + ", " + http.MethodPost
		}
		w.Header().Set("Allow", allow)
		crossDeviceFailure(w, http.StatusMethodNotAllowed)
		return nil
	}
	if r.Method == http.MethodPost {
		if !validCrossDeviceOrigin(r) {
			crossDeviceFailure(w, http.StatusForbidden)
			return nil
		}
		if status := parseCrossDeviceForm(w, r); status != 0 {
			crossDeviceFailure(w, status)
			return nil
		}
	}
	base := rr.Upstream.BasePath
	switch route {
	case "":
		return p.renderCrossDevice(ctx, w, r, rr, "request", nil)
	case "/start":
		entry, secret, err := p.crossDevice.start(origin, base, addrutil.GetSourceAddress(r))
		if err != nil {
			crossDeviceFailure(w, http.StatusTooManyRequests)
			return nil
		}
		link := origin + base + "cross-device/activate?code=" + entry.code
		png, err := qrcode.Encode(link, qrcode.Medium, 256)
		if err != nil {
			_, _ = p.crossDevice.poll(entry.code, secret, origin, base, true)
			crossDeviceFailure(w, http.StatusInternalServerError)
			return nil
		}
		crossDeviceResponse(w, http.StatusOK, map[string]any{"code": entry.code, "secret": secret, "verification_uri": link, "display_code": entry.display, "qr": "data:image/png;base64," + base64.StdEncoding.EncodeToString(png), "expires_in": int(crossDeviceLifetime.Seconds()), "interval": int(crossDevicePollInterval.Seconds())})
	case "/activate":
		codes := r.URL.Query()["code"]
		if len(codes) != 1 || len(codes[0]) != 26 {
			crossDeviceFailure(w, http.StatusBadRequest)
			return nil
		}
		entry, err := p.crossDevice.view(codes[0], origin, base)
		if err != nil {
			crossDeviceFailure(w, http.StatusGone)
			return nil
		}
		binding := rand.Text()
		w.Header().Add("Set-Cookie", p.cookie.GetCrossDeviceSessionIDCookie(base, binding))
		return p.renderCrossDevice(ctx, w, r, rr, "activate", map[string]any{"code": entry.code, "display": entry.display, "csrf": binding})
	case "/begin":
		binding := p.crossDeviceBinding(r)
		if binding == "" || r.PostForm.Get("csrf") != binding || p.crossDevice.bind(r.PostForm.Get("code"), binding, origin, base) != nil {
			crossDeviceFailure(w, http.StatusForbidden)
			return nil
		}
		// Initiate a new login on the approving browser. Existing JWTs are not
		// evidence of this interaction; completion hooks run after verification.
		p.deleteAuthCookies(w, r)
		http.Redirect(w, r, base+"login?fresh=1", http.StatusSeeOther)
	case "/confirm":
		binding := p.crossDeviceBinding(r)
		entry, err := p.crossDevice.confirmation(binding, origin, base)
		if err == nil {
			err = p.validateCrossDeviceSession(ctx, entry.proof)
		}
		if err != nil {
			crossDeviceFailure(w, crossDeviceSessionErrorStatus(err, http.StatusGone))
			return nil
		}
		if r.Method == http.MethodGet {
			return p.renderCrossDevice(ctx, w, r, rr, "confirm", map[string]any{"csrf": binding, "display": entry.display, "account": entry.proof.user.Claims.Email})
		}
		decision := r.PostForm.Get("decision")
		if binding == "" || r.PostForm.Get("csrf") != binding || (decision != "approve" && decision != "deny") {
			crossDeviceFailure(w, http.StatusForbidden)
			return nil
		}
		if p.crossDevice.decide(binding, origin, base, decision == "approve") != nil {
			crossDeviceFailure(w, http.StatusGone)
			return nil
		}
		w.Header().Add("Set-Cookie", p.cookie.GetDeleteCrossDeviceSessionIDCookie(base))
		return p.renderCrossDevice(ctx, w, r, rr, decision, nil)
	case "/poll", "/cancel":
		proof, err := p.crossDevice.poll(r.PostForm.Get("code"), r.PostForm.Get("secret"), origin, base, route == "/cancel")
		switch {
		case errors.Is(err, errCrossDevicePending):
			crossDeviceResponse(w, http.StatusOK, map[string]any{"status": "pending"})
		case errors.Is(err, errCrossDeviceLimited):
			w.Header().Set("Retry-After", "2")
			crossDeviceResponse(w, http.StatusTooManyRequests, map[string]any{"status": "slow_down"})
		case err != nil:
			crossDeviceFailure(w, http.StatusGone)
		case route == "/cancel":
			crossDeviceResponse(w, http.StatusOK, map[string]any{"status": "cancelled"})
		default:
			return p.redeemCrossDevice(ctx, w, r, rr, proof)
		}
	}
	return nil
}

func (p *Portal) renderCrossDevice(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, view string, data map[string]any) error {
	args := p.ui.GetArgs()
	args.BaseURL(rr.Upstream.BasePath)
	args.PageTitle = args.Translate("cross_device_title")
	args.Data["view"] = view
	maps.Copy(args.Data, data)
	content, err := p.ui.Render("cross_device", args)
	if err != nil {
		return p.handleHTTPRenderError(ctx, w, r, rr, err)
	}
	return p.handleHTTPRenderHTML(ctx, w, http.StatusOK, content.Bytes())
}

func (p *Portal) validateCrossDeviceSession(ctx context.Context, proof *crossDeviceProof) error {
	if proof == nil {
		return errCrossDeviceDenied
	}
	session, err := p.sessions.Get(proof.sessionID)
	if err != nil {
		return err
	}
	if session.Claims.ExpiresAt <= time.Now().Unix() || crossDeviceHash(session.Token) != proof.sessionToken {
		return errCrossDeviceDenied
	}
	if proof.refreshSessionID != "" {
		if p.refresh == nil {
			return errCrossDeviceDenied
		}
		return p.refresh.ValidateSession(ctx, proof.refreshSessionID, tokenrefresh.CookieTransport)
	}
	return nil
}

func crossDeviceSessionErrorStatus(err error, denied int) int {
	if errors.Is(err, tokenrefresh.ErrUnavailable) || errors.Is(err, state.ErrUnavailable) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return http.StatusServiceUnavailable
	}
	return denied
}

// Called only after the normal browser login has successfully issued and cached
// credentials. JSON/API-key/Basic authentication cannot complete this flow.
func (p *Portal) completeCrossDeviceLogin(w http.ResponseWriter, r *http.Request, rr *requests.Request, issued, proof *user.User, providerClaims []byte, tokens *tokenrefresh.Result) {
	if p.crossDevice == nil {
		return
	}
	binding := p.crossDeviceBinding(r)
	origin, err := getWebAuthnExpectedOrigin(r)
	if err != nil || binding == "" {
		return
	}
	// Only the local issuer's committed result establishes a family reference.
	// An access-only transform or provider SID is unrelated public metadata.
	var refreshSessionID string
	if tokens != nil {
		refreshSessionID = tokens.SessionID
	}
	if p.crossDevice.complete(binding, origin, rr.Upstream.BasePath, &crossDeviceProof{refreshSessionID: refreshSessionID, user: proof, sessionID: issued.Claims.ID, sessionToken: crossDeviceHash(issued.Token), expires: issued.Claims.ExpiresAt, providerClaims: providerClaims, providerMethod: rr.Upstream.Method}) {
		w.Header().Set("Location", rr.Upstream.BasePath+"cross-device/confirm")
	}
}

func (p *Portal) redeemCrossDevice(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, proof *crossDeviceProof) error {
	if err := p.validateCrossDeviceSession(ctx, proof); err != nil {
		crossDeviceFailure(w, crossDeviceSessionErrorStatus(err, http.StatusUnauthorized))
		return nil
	}
	// Never reuse a session ID supplied by either browser.
	rr.Upstream.SessionID = util.GetRandomStringFromRange(36, 46)
	rr.Upstream.Realm = proof.user.Authenticator.Realm
	rr.Upstream.Method = proof.user.Authenticator.Method
	var issued *user.User
	var tokens *tokenrefresh.Result
	var err error
	if len(proof.providerClaims) > 0 {
		rr.Upstream.Method = proof.providerMethod
		issued, err = p.issueCrossDeviceProvider(ctx, r, rr, proof)
	} else {
		proof.user.RefreshTransport = tokenrefresh.CookieTransport
		issued, tokens, err = p.issueSandboxTokens(ctx, r, rr, proof.user)
	}
	headers := w.Header().Clone()
	granted := false
	if err == nil {
		err = p.grantAccess(ctx, w, r, rr, issued)
		granted = err == nil
	}
	if err == nil && len(proof.providerClaims) == 0 {
		err = p.finishOIDCLogin(ctx, w, r, proof.user)
	}
	if err != nil {
		cleanupErr := p.discardUndeliveredRefresh(ctx, tokens, tokenrefresh.CookieTransport)
		if granted {
			cleanupErr = errors.Join(cleanupErr, p.sessions.Delete(issued.Claims.ID))
		}
		clear(w.Header())
		maps.Copy(w.Header(), headers)
		rr.Response.Authenticated = false
		status := http.StatusUnauthorized
		if errors.Is(err, state.ErrCapacity) || errors.Is(err, state.ErrUnavailable) || cleanupErr != nil {
			status = http.StatusServiceUnavailable
		}
		rr.Response.Code = status
		crossDeviceFailure(w, status)
		return nil
	}
	if tokens != nil {
		p.deliverRefreshCookies(w, r, tokens)
	}
	// Fetch must not follow grantAccess's redirect or receive bearer tokens in
	// JSON. The browser receives ordinary HttpOnly credentials and navigates.
	next := w.Header().Get("Location")
	w.Header().Del("Location")
	w.Header().Del("Authorization")
	rr.Response.Code = http.StatusOK
	crossDeviceResponse(w, http.StatusOK, map[string]any{"status": "approved", "next": next})
	return nil
}

func (p *Portal) issueCrossDeviceProvider(ctx context.Context, r *http.Request, rr *requests.Request, proof *crossDeviceProof) (*user.User, error) {
	provider := p.getIdentityProviderByRealm(proof.user.Authenticator.Realm)
	if provider == nil || provider.GetName() != proof.user.Authenticator.Name {
		return nil, errCrossDeviceDenied
	}
	m := make(map[string]any)
	decoder := json.NewDecoder(bytes.NewReader(proof.providerClaims))
	decoder.UseNumber()
	if decoder.Decode(&m) != nil {
		return nil, errCrossDeviceDenied
	}
	combineGroupRoles(m)
	now := time.Now().Unix()
	m["jti"], m["iat"], m["nbf"] = rr.Upstream.SessionID, now, now-60
	m["exp"] = min(proof.expires, now+int64(p.keystore.GetTokenLifetime(nil, nil)))
	if _, exists := m["origin"]; !exists {
		m["origin"] = rr.Upstream.Realm
	}
	m["iss"], m["addr"] = util.GetIssuerURL(r), addrutil.GetSourceAddress(r)
	if err := p.transformUser(ctx, rr, m); err != nil {
		return nil, err
	}
	// An upstream login cannot satisfy additional local factors at redemption.
	if err := p.checkDirectAuthenticationPolicy(rr, m, nil); err != nil {
		return nil, err
	}
	// Keep transfers bounded by the completed login's lifetime, even if a
	// transform tries to extend expiry or replace the new session identifier.
	m["exp"], m["jti"] = min(proof.expires, now+int64(p.keystore.GetTokenLifetime(nil, nil))), rr.Upstream.SessionID
	injectPortalRoles(m, p.config)
	issued, err := user.NewUser(m)
	if err != nil {
		return nil, err
	}
	issued.Authenticator = proof.user.Authenticator
	if links, ok := m["frontend_links"]; ok {
		if err := issued.AddFrontendLinks(links); err != nil {
			return nil, err
		}
	}
	if err := p.keystore.SignToken(nil, nil, issued); err != nil {
		return nil, err
	}
	return issued, nil
}

func (p *Portal) revokeCrossDeviceLogin(ctx context.Context, r *http.Request) {
	if p.crossDevice == nil {
		return
	}
	usr, err := p.validator.Authorize(ctx, r, requests.NewAuthorizationRequest())
	if err != nil || usr == nil || usr.Claims == nil {
		return
	}
	refreshSessionID, _ := usr.AsMap()["sid"].(string)
	p.crossDevice.revoke(usr.Claims.ID, refreshSessionID)
}
