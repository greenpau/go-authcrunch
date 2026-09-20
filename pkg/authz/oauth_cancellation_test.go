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

package authz

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/operator"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

type oauthCancellation struct {
	state, callback string
	browserHash     [32]byte
}

type oauthCancelingProvider struct {
	*oauthProviderStub
	mu            sync.Mutex
	sequence      int
	cancellations []oauthCancellation
	active        map[string]struct{}
	invalid       bool
}

func (p *oauthCancelingProvider) Request(_ operator.Type, r *requests.Request) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.active) >= 1 {
		return fmt.Errorf("synthetic provider state capacity reached")
	}
	p.sequence++
	state := fmt.Sprintf("state-%d", p.sequence)
	if p.active == nil {
		p.active = make(map[string]struct{})
	}
	p.active[state] = struct{}{}
	r.Response.Code = http.StatusFound
	scheme := "https"
	if p.invalid {
		scheme = "http"
	}
	r.Response.RedirectURL = fmt.Sprintf("%s://provider.test/authorize?state=%s", scheme, state)
	return nil
}

func (p *oauthCancelingProvider) CancelLogin(state string, browserHash [32]byte, callback string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cancellations = append(p.cancellations, oauthCancellation{state: state, browserHash: browserHash, callback: callback})
	delete(p.active, state)
	return true
}

func (p *oauthCancelingProvider) canceled(t *testing.T, index int, state string, browser *http.Cookie, callback string) {
	t.Helper()
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.cancellations) <= index {
		t.Fatalf("missing cancellation %d", index)
	}
	got := p.cancellations[index]
	if got.state != state || got.browserHash != sha256.Sum256([]byte(browser.Value)) || got.callback != callback {
		t.Fatalf("cancellation %d did not match its login owner: %#v", index, got)
	}
}

func oauthLoginCookie(t *testing.T, g *Gatekeeper, recorder *httptest.ResponseRecorder) *http.Cookie {
	t.Helper()
	for _, cookie := range recorder.Result().Cookies() {
		if cookie.Name == g.oauth.config.LoginCookieName && cookie.MaxAge > 0 {
			return cookie
		}
	}
	t.Fatal("login cookie not issued")
	return nil
}

func TestOAuthAuthorizationCancelsReplacedLogoutAndCloseLogins(t *testing.T) {
	provider := &oauthCancelingProvider{oauthProviderStub: &oauthProviderStub{}}
	g := newOAuthUnitGatekeeper(t, provider.oauthProviderStub)
	// Replace the selected provider and its narrow cancellation capability with
	// the capacity-limited test implementation.
	g.oauth.provider = provider
	g.oauth.canceler = provider

	request := oauthUnitRequest(http.MethodGet, "https://app.test/private", nil)
	response := httptest.NewRecorder()
	_ = g.Authenticate(response, request, requests.NewAuthorizationRequest())
	first := oauthLoginCookie(t, g, response)

	request = oauthUnitRequest(http.MethodGet, "https://app.test/private", nil)
	request.AddCookie(first)
	response = httptest.NewRecorder()
	_ = g.Authenticate(response, request, requests.NewAuthorizationRequest())
	second := oauthLoginCookie(t, g, response)
	callback := "https://app.test" + g.oauth.config.CallbackPath()
	provider.canceled(t, 0, "state-1", first, callback)

	request = oauthUnitRequest(http.MethodPost, "https://app.test"+g.oauth.config.LogoutPath(), nil)
	request.Header.Set("Origin", "https://app.test")
	request.AddCookie(second)
	response = httptest.NewRecorder()
	_ = g.Authenticate(response, request, requests.NewAuthorizationRequest())
	if response.Code != http.StatusNoContent {
		t.Fatalf("logout status %d", response.Code)
	}
	provider.canceled(t, 1, "state-2", second, callback)

	request = oauthUnitRequest(http.MethodGet, "https://app.test/private", nil)
	response = httptest.NewRecorder()
	_ = g.Authenticate(response, request, requests.NewAuthorizationRequest())
	third := oauthLoginCookie(t, g, response)
	g.Close()
	provider.canceled(t, 2, "state-3", third, callback)
}

func TestOAuthAuthorizationCancelsRejectedProviderRedirect(t *testing.T) {
	provider := &oauthCancelingProvider{oauthProviderStub: &oauthProviderStub{}, invalid: true}
	g := newOAuthUnitGatekeeper(t, provider.oauthProviderStub)
	g.oauth.provider = provider
	g.oauth.canceler = provider

	response := httptest.NewRecorder()
	_ = g.Authenticate(response, oauthUnitRequest(http.MethodGet, "https://app.test/private", nil), requests.NewAuthorizationRequest())
	if response.Code != http.StatusBadGateway {
		t.Fatalf("invalid redirect status %d", response.Code)
	}
	provider.mu.Lock()
	defer provider.mu.Unlock()
	if len(provider.cancellations) != 1 || provider.cancellations[0].state != "state-1" || provider.cancellations[0].callback != "https://app.test"+g.oauth.config.CallbackPath() {
		t.Fatalf("invalid redirect state not canceled: %#v", provider.cancellations)
	}
}

func TestOAuthAuthorizationCancelsExpiredLoginBeforeProviderAdmission(t *testing.T) {
	provider := &oauthCancelingProvider{oauthProviderStub: &oauthProviderStub{}}
	g := newOAuthUnitGatekeeper(t, provider.oauthProviderStub)
	g.oauth.provider = provider
	g.oauth.canceler = provider

	response := httptest.NewRecorder()
	_ = g.Authenticate(response, oauthUnitRequest(http.MethodGet, "https://app.test/private", nil), requests.NewAuthorizationRequest())
	first := oauthLoginCookie(t, g, response)
	key := sha256.Sum256([]byte(first.Value))
	g.oauth.mu.Lock()
	login := g.oauth.logins[key]
	login.expires = time.Now().Add(-time.Second)
	g.oauth.logins[key] = login
	g.oauth.mu.Unlock()

	response = httptest.NewRecorder()
	_ = g.Authenticate(response, oauthUnitRequest(http.MethodGet, "https://app.test/private", nil), requests.NewAuthorizationRequest())
	if response.Code != http.StatusFound {
		t.Fatalf("replacement after expiry status %d", response.Code)
	}
	provider.canceled(t, 0, "state-1", first, "https://app.test"+g.oauth.config.CallbackPath())
}
