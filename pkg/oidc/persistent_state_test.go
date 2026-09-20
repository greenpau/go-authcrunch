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

package oidc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/state"
)

func TestE2EOIDCPersistentCapacityRefusalPreservesAuthority(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	storage, err := state.Open(&state.Config{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	record, err := storage.OpenRecord("oidc", "binding")
	if err != nil {
		t.Fatal(err)
	}
	f := newProviderFixture(t)
	now := time.Now()
	sessionCredential, accessCredential, refreshCredential, codeCredential := oidcRandom(), oidcRandom(), oidcRandom(), oidcRandom()
	sessionHash := sha256.Sum256([]byte(sessionCredential))
	request := persistentOIDCAuthorization{ClientID: "client", RedirectURI: "https://client.example.test/callback", State: strings.Repeat("s", 12000), Scopes: []string{"openid", "profile", "offline_access"}, Created: now, Expires: now.Add(time.Minute), Session: sessionHash}
	snapshot := persistentOIDCState{Sessions: []persistentOIDCSession{{Hash: sessionHash, Proof: requests.AuthenticationEvidence{UserID: "immutable-user", BackendVersion: "v1", CredentialVersion: 1, AuthenticatedAt: now.Unix()}, Realm: "local", Backend: "localdb", Username: "alice", Subject: "subject", Expires: now.Add(time.Hour)}}}
	accessHash := sha256.Sum256([]byte(accessCredential))
	refreshHash := sha256.Sum256([]byte(refreshCredential))
	snapshot.Grants = append(snapshot.Grants, persistentOIDCGrant{Hash: sha256.Sum256([]byte("live")), Session: sessionHash, Request: request, CodeExpires: now.Add(time.Minute), Expires: now.Add(time.Hour), Redeemed: true, AccessHash: accessHash, AccessExpires: now.Add(time.Hour), RefreshCurrent: refreshHash, RefreshHashes: [][32]byte{refreshHash}, Revocation: 1})
	snapshot.Grants = append(snapshot.Grants, persistentOIDCGrant{Hash: sha256.Sum256([]byte(codeCredential)), Session: sessionHash, Request: request, CodeExpires: now.Add(time.Minute), Expires: now.Add(time.Hour), Revocation: 1})
	grantAt := func(index int) persistentOIDCGrant {
		return persistentOIDCGrant{Hash: sha256.Sum256(fmt.Appendf(nil, "filler-%d", index)), Session: sessionHash, Request: request, CodeExpires: now.Add(time.Minute), Expires: now.Add(time.Hour), Revocation: 1}
	}
	low, high := 0, f.config.MaxGrants-len(snapshot.Grants)
	for low < high {
		mid := low + (high-low+1)/2
		candidate := snapshot
		candidate.Grants = slices.Clone(snapshot.Grants)
		for i := range mid {
			candidate.Grants = append(candidate.Grants, grantAt(i))
		}
		if _, prepareErr := record.PrepareEncode(candidate); errors.Is(prepareErr, state.ErrCapacity) {
			high = mid - 1
		} else if prepareErr != nil {
			t.Fatal(prepareErr)
		} else {
			low = mid
		}
	}
	for i := range low {
		snapshot.Grants = append(snapshot.Grants, grantAt(i))
	}
	partial := grantAt(low)
	partial.Request.State = ""
	partialFits := true
	partialCandidate := snapshot
	partialCandidate.Grants = append(slices.Clone(snapshot.Grants), partial)
	if _, prepareErr := record.PrepareEncode(partialCandidate); errors.Is(prepareErr, state.ErrCapacity) {
		partialFits = false
	} else if prepareErr != nil {
		t.Fatal(prepareErr)
	}
	if partialFits {
		paddingLow, paddingHigh := 0, len(request.State)
		for paddingLow < paddingHigh {
			mid := paddingLow + (paddingHigh-paddingLow+1)/2
			partial.Request.State = strings.Repeat("p", mid)
			partialCandidate.Grants[len(partialCandidate.Grants)-1] = partial
			if _, prepareErr := record.PrepareEncode(partialCandidate); errors.Is(prepareErr, state.ErrCapacity) {
				paddingHigh = mid - 1
			} else if prepareErr != nil {
				t.Fatal(prepareErr)
			} else {
				paddingLow = mid
			}
		}
		partial.Request.State = strings.Repeat("p", paddingLow)
		snapshot.Grants = append(snapshot.Grants, partial)
	} else {
		last := len(snapshot.Grants) - 1
		base := snapshot.Grants[last].Request.State
		paddingLow, paddingHigh := 0, 4000
		candidate := snapshot
		candidate.Grants = slices.Clone(snapshot.Grants)
		for paddingLow < paddingHigh {
			mid := paddingLow + (paddingHigh-paddingLow+1)/2
			candidate.Grants[last].Request.State = base + strings.Repeat("p", mid)
			if _, prepareErr := record.PrepareEncode(candidate); errors.Is(prepareErr, state.ErrCapacity) {
				paddingHigh = mid - 1
			} else if prepareErr != nil {
				t.Fatal(prepareErr)
			} else {
				paddingLow = mid
			}
		}
		snapshot.Grants[last].Request.State = base + strings.Repeat("p", paddingLow)
	}
	if len(snapshot.Grants) >= f.config.MaxGrants {
		t.Fatal("fixture reached configured grant capacity before record capacity")
	}
	if err = record.Encode(snapshot); err != nil {
		t.Fatal(err)
	}
	if err = f.provider.ConfigurePersistentState(record); err != nil {
		t.Fatal(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/host/logout" {
			if err := f.provider.LogoutWithError(w, r); err != nil {
				http.Error(w, "unavailable", http.StatusServiceUnavailable)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		f.provider.ServeHTTP(w, r)
	})
	server := httptest.NewTLSServer(handler)
	defer server.Close()
	client := server.Client()
	client.Timeout = 60 * time.Second
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	do := func(method, path string, cookie *http.Cookie, authorization string) *http.Response {
		t.Helper()
		req, reqErr := http.NewRequestWithContext(t.Context(), method, server.URL+path, nil)
		if reqErr != nil {
			t.Fatal(reqErr)
		}
		req.Host = "auth.example.test"
		if cookie != nil {
			req.AddCookie(cookie)
		}
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		resp, doErr := client.Do(req)
		if doErr != nil {
			t.Fatal(doErr)
		}
		resp.Body.Close()
		return resp
	}
	sessionCookie := &http.Cookie{Name: f.provider.sessionCookie, Value: sessionCredential}
	params := url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}, "prompt": {"none"}, "state": {strings.Repeat("x", 16000)}}
	response := do(http.MethodGet, "/auth/oidc/authorize?"+params.Encode(), sessionCookie, "")
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil || response.StatusCode != http.StatusFound || location.Query().Get("error") != "temporarily_unavailable" || location.Query().Get("code") != "" {
		t.Fatal("OIDC capacity refusal did not fail closed")
	}
	if response = do(http.MethodGet, "/auth/oidc/userinfo", nil, "Bearer "+accessCredential); response.StatusCode != http.StatusOK {
		t.Fatal("capacity refusal revoked existing OIDC authority")
	}
	refreshForm := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {refreshCredential}, "scope": {"openid"}}
	codeForm := url.Values{"grant_type": {"authorization_code"}, "code": {codeCredential}, "redirect_uri": {request.RedirectURI}}
	codeRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/auth/oidc/token", strings.NewReader(codeForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	codeRequest.Host = "auth.example.test"
	codeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	codeRequest.SetBasicAuth("client", strings.Repeat("s", 32))
	codeResponse, err := client.Do(codeRequest)
	if err != nil {
		t.Fatal(err)
	}
	codeResponse.Body.Close()
	if codeResponse.StatusCode != http.StatusServiceUnavailable || f.provider.grants[sha256.Sum256([]byte(codeCredential))].redeemed {
		t.Fatal("refused code redemption was not rolled back")
	}
	refreshRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/auth/oidc/token", strings.NewReader(refreshForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	refreshRequest.Host = "auth.example.test"
	refreshRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	refreshRequest.SetBasicAuth("client", strings.Repeat("s", 32))
	refreshResponse, err := client.Do(refreshRequest)
	if err != nil {
		t.Fatal(err)
	}
	refreshResponse.Body.Close()
	if refreshResponse.StatusCode != http.StatusServiceUnavailable || !slices.Contains(f.provider.refresh[refreshHash].request.scopes, "profile") || f.provider.refresh[refreshHash].refreshCurrent != refreshHash {
		t.Fatal("refused refresh mutation was not rolled back")
	}
	f.provider.Close()
	if err = storage.Close(); err != nil {
		t.Fatal(err)
	}
	storage, err = state.Open(&state.Config{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	record, err = storage.OpenRecord("oidc", "binding")
	if err != nil {
		t.Fatal(err)
	}
	f.provider, err = NewProvider(f.config, f.verifier, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.provider.ConfigurePersistentState(record); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(f.provider.refresh[refreshHash].request.scopes, "profile") || f.provider.refresh[refreshHash].refreshCurrent != refreshHash {
		t.Fatal("refused refresh mutation changed durable authority")
	}
	if f.provider.grants[sha256.Sum256([]byte(codeCredential))].redeemed {
		t.Fatal("refused code redemption changed durable authority")
	}
	loginResponse := httptest.NewRecorder()
	loginRequest := httptest.NewRequest(http.MethodPost, oidcTestOrigin+"/auth/login", nil)
	loginRequest.Header.Set("Origin", oidcTestOrigin)
	loginProof := Authentication{Realm: "local", Backend: "localdb", Username: "alice", Methods: []string{"pwd"}, Evidence: requests.AuthenticationEvidence{UserID: "immutable-user", BackendVersion: "v1", CredentialVersion: 1, AuthenticatedAt: now.Unix(), Method: "password"}}
	err = f.provider.CompleteLogin(t.Context(), loginResponse, loginRequest, loginProof)
	positiveCookie := false
	for _, cookie := range loginResponse.Result().Cookies() {
		positiveCookie = positiveCookie || cookie.MaxAge > 0
	}
	if !errors.Is(err, state.ErrCapacity) || positiveCookie || len(f.provider.sessions) != 1 {
		t.Fatal("refused session admission published or replaced OIDC authority")
	}
	f.provider.clients["client"].SkipConsent = false
	submitConsent := func(label string) {
		t.Helper()
		pendingCredential := oidcRandom()
		pendingHash := sha256.Sum256([]byte(pendingCredential))
		csrf := label + "-csrf"
		f.provider.pending[pendingHash] = &oidcAuthorization{clientID: "client", redirectURI: "https://client.example.test/callback", state: label, scopes: []string{"openid"}, claims: make(oidcClaimsRequest), created: now, expires: now.Add(time.Minute), session: sessionHash, consent: csrf}
		consentForm := url.Values{"csrf": {csrf}, "decision": {"allow"}}
		consentRequest, requestErr := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/auth/oidc/continue", strings.NewReader(consentForm.Encode()))
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		consentRequest.Host = "auth.example.test"
		consentRequest.Header.Set("Origin", oidcTestOrigin)
		consentRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		consentRequest.AddCookie(&http.Cookie{Name: f.provider.requestCookie, Value: pendingCredential})
		consentRequest.AddCookie(sessionCookie)
		consentResponse, requestErr := client.Do(consentRequest)
		if requestErr != nil {
			t.Fatal(requestErr)
		}
		consentResponse.Body.Close()
		consentLocation, parseErr := url.Parse(consentResponse.Header.Get("Location"))
		if parseErr != nil || consentResponse.StatusCode != http.StatusFound || consentLocation.Query().Get("error") != "temporarily_unavailable" || len(f.provider.sessions[sessionHash].consents["client"]) != 0 {
			t.Fatalf("refused code admission retained partial consent: status=%d error=%q consents=%v", consentResponse.StatusCode, consentLocation.Query().Get("error"), f.provider.sessions[sessionHash].consents["client"])
		}
	}
	originalMaxGrants := f.provider.config.MaxGrants
	f.provider.config.MaxGrants = len(f.provider.grants)
	submitConsent("grant-count-consent")
	f.provider.config.MaxGrants = originalMaxGrants
	submitConsent("record-capacity-consent")
	if response = do(http.MethodGet, "/auth/oidc/userinfo", nil, "Bearer "+accessCredential); response.StatusCode != http.StatusOK {
		t.Fatal("existing OIDC authority was not restored after capacity refusal")
	}
	unrelated, err := storage.OpenRecord("unrelated", "binding")
	if err != nil {
		t.Fatal(err)
	}
	if err = unrelated.Encode(map[string]string{"healthy": "yes"}); err != nil {
		t.Fatal("capacity refusal poisoned shared storage", err)
	}
	revokeForm := url.Values{"token": {accessCredential}}
	revokeRequest, err := http.NewRequestWithContext(t.Context(), http.MethodPost, server.URL+"/auth/oidc/revoke", strings.NewReader(revokeForm.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	revokeRequest.Host = "auth.example.test"
	revokeRequest.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	revokeRequest.SetBasicAuth("client", strings.Repeat("s", 32))
	revokeResponse, err := client.Do(revokeRequest)
	if err != nil {
		t.Fatal(err)
	}
	revokeResponse.Body.Close()
	if revokeResponse.StatusCode != http.StatusOK || storage.Err() != nil {
		t.Fatal("fixed-width revocation failed at persistent capacity")
	}
	f.provider.Close()
	if err = storage.Close(); err != nil {
		t.Fatal(err)
	}
	storage, err = state.Open(&state.Config{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	record, err = storage.OpenRecord("oidc", "binding")
	if err != nil {
		t.Fatal(err)
	}
	f.provider, err = NewProvider(f.config, f.verifier, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err = f.provider.ConfigurePersistentState(record); err != nil {
		t.Fatal(err)
	}
	if !f.provider.grants[sha256.Sum256([]byte("live"))].revoked {
		t.Fatal("fixed-width revocation was not durable")
	}
	if response = do(http.MethodGet, "/auth/oidc/userinfo", nil, "Bearer "+accessCredential); response.StatusCode != http.StatusUnauthorized {
		t.Fatal("revoked access token survived restart")
	}
	if response = do(http.MethodPost, "/host/logout", sessionCookie, ""); response.StatusCode != http.StatusNoContent {
		t.Fatal("capacity refusal prevented durable logout")
	}
	f.provider.Close()
	if err = storage.Close(); err != nil {
		t.Fatal(err)
	}
	storage, err = state.Open(&state.Config{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	record, err = storage.OpenRecord("oidc", "binding")
	if err != nil {
		t.Fatal(err)
	}
	f.provider, err = NewProvider(f.config, f.verifier, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer f.provider.Close()
	if err = f.provider.ConfigurePersistentState(record); err != nil {
		t.Fatal(err)
	}
	if len(f.provider.sessions) != 0 || len(f.provider.grants) != 0 {
		t.Fatal("logout revocation was not durable after capacity refusal")
	}
}

func TestOIDCPersistentRefreshHistory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	storage, err := state.Open(&state.Config{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	record, err := storage.OpenRecord("oidc", "binding")
	if err != nil {
		t.Fatal(err)
	}
	f, tokens := oidcRefreshFixture(t, func(o *Provider) {
		if err := o.ConfigurePersistentState(record); err != nil {
			t.Fatal(err)
		}
	})
	old := tokens["refresh_token"].(string)
	response := oidcRefreshRequest(t, f, old, "client", "")
	if response.Code != 200 {
		t.Fatal("rotation failed")
	}
	next := oidcUnitJSON(t, response)["refresh_token"].(string)
	restart := func() {
		f.provider.Close()
		if err := storage.Close(); err != nil {
			t.Fatal(err)
		}
		var err error
		storage, err = state.Open(&state.Config{Directory: directory})
		if err != nil {
			t.Fatal(err)
		}
		record, err = storage.OpenRecord("oidc", "binding")
		if err != nil {
			t.Fatal(err)
		}
		config := f.provider.config
		f.provider, err = NewProvider(&config, f.verifier, Options{})
		if err != nil {
			t.Fatal(err)
		}
		if err = f.provider.ConfigurePersistentState(record); err != nil {
			t.Fatal(err)
		}
	}
	restart()
	response = oidcRefreshRequest(t, f, next, "client", "")
	if response.Code != 200 {
		t.Fatal("OIDC refresh family not restored")
	}
	descendant := oidcUnitJSON(t, response)["refresh_token"].(string)
	if oidcRefreshRequest(t, f, old, "client", "").Code != 400 {
		t.Fatal("spent history was lost")
	}
	restart()
	if oidcRefreshRequest(t, f, descendant, "client", "").Code != 400 {
		t.Fatal("OIDC replay revocation lost")
	}
	f.provider.Close()
	if err := storage.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestE2EOIDCPersistentRestoreIsAtomic(t *testing.T) {
	storage, err := state.Open(&state.Config{Directory: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	record, err := storage.OpenRecord("oidc", "binding")
	if err != nil {
		t.Fatal(err)
	}
	f := newProviderFixture(t)
	expires := time.Now().Add(time.Hour)
	credential := oidcRandom()
	snapshot := persistentOIDCState{Sessions: []persistentOIDCSession{
		{Hash: sha256.Sum256([]byte(credential)), Proof: requests.AuthenticationEvidence{UserID: "immutable-user", BackendVersion: "v1", CredentialVersion: 1, AuthenticatedAt: time.Now().Unix()}, Realm: "local", Backend: "localdb", Username: "alice", Subject: "subject", Expires: expires},
		{Hash: sha256.Sum256([]byte("invalid")), Proof: requests.AuthenticationEvidence{AuthenticatedAt: time.Now().Unix()}, Realm: f.config.Realms[0], Username: "alice", Subject: "subject", Expires: expires},
	}}
	if err = record.Encode(snapshot); err != nil {
		t.Fatal(err)
	}
	if err = f.provider.ConfigurePersistentState(record); err == nil {
		t.Fatal("invalid persistent state accepted")
	}
	if len(f.provider.sessions) != 0 || len(f.provider.grants) != 0 || len(f.provider.access) != 0 || len(f.provider.refresh) != 0 || f.provider.state != nil {
		t.Fatal("failed restore published partial OIDC authority")
	}
	server := httptest.NewTLSServer(f.provider)
	defer server.Close()
	client := server.Client()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	target := server.URL + "/auth/oidc/authorize?" + url.Values{"client_id": {"client"}, "redirect_uri": {"https://client.example.test/callback"}, "response_type": {"code"}, "scope": {"openid"}, "prompt": {"none"}}.Encode()
	request, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Host = "auth.example.test"
	request.AddCookie(&http.Cookie{Name: f.provider.sessionCookie, Value: credential})
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil || response.StatusCode != http.StatusFound || location.Query().Get("error") != "login_required" || location.Query().Get("code") != "" {
		t.Fatal("failed restore authorized a partially restored OIDC session")
	}
	if err = record.Encode(persistentOIDCState{Sessions: snapshot.Sessions[:1]}); err != nil {
		t.Fatal(err)
	}
	if err = f.provider.ConfigurePersistentState(record); err != nil {
		t.Fatalf("provider was not retryable after atomic restore failure: %v", err)
	}
}

func TestOIDCPersistentRevocationEncoding(t *testing.T) {
	storage, err := state.Open(&state.Config{Directory: filepath.Join(t.TempDir(), "state")})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	record, err := storage.OpenRecord("oidc", "binding")
	if err != nil {
		t.Fatal(err)
	}
	f := newProviderFixture(t)
	now := time.Now()
	sessionHash := sha256.Sum256([]byte("session"))
	snapshot := persistentOIDCState{
		Sessions: []persistentOIDCSession{{Hash: sessionHash, Proof: requests.AuthenticationEvidence{UserID: "immutable-user", BackendVersion: "v1", CredentialVersion: 1, AuthenticatedAt: now.Unix()}, Realm: "local", Backend: "localdb", Username: "alice", Subject: "subject", Expires: now.Add(time.Hour)}},
		Grants:   []persistentOIDCGrant{{Hash: sha256.Sum256([]byte("grant")), Session: sessionHash, Request: persistentOIDCAuthorization{ClientID: "client", RedirectURI: "https://client.example.test/callback", Session: sessionHash}, CodeExpires: now.Add(time.Minute), Expires: now.Add(time.Hour)}},
	}
	if err = record.Encode(snapshot); err != nil {
		t.Fatal(err)
	}
	if err = f.provider.ConfigurePersistentState(record); err == nil || len(f.provider.sessions) != 0 || len(f.provider.grants) != 0 {
		t.Fatal("unversioned revocation state was accepted or partially restored")
	}
	snapshot.Grants[0].Revocation = 1
	active, err := record.PrepareEncode(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	snapshot.Grants[0].Revocation = 2
	revoked, err := record.PrepareEncode(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if len(active) != len(revoked) {
		t.Fatal("revocation changed persistent snapshot size")
	}
	snapshot.Grants[0].Revocation = 1
	if err = record.Encode(snapshot); err != nil {
		t.Fatal(err)
	}
	if err = f.provider.ConfigurePersistentState(record); err != nil {
		t.Fatal(err)
	}
}
func TestOIDCPersistentCommitFailure(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "state")
	storage, err := state.Open(&state.Config{Directory: directory})
	if err != nil {
		t.Fatal(err)
	}
	defer storage.Close()
	record, err := storage.OpenRecord("oidc", "binding")
	if err != nil {
		t.Fatal(err)
	}
	f := newProviderFixture(t)
	if err = f.provider.ConfigurePersistentState(record); err != nil {
		t.Fatal(err)
	}
	cookie := responseCookie(t, f.login(t), f.provider.sessionCookie)
	hash := sha256.Sum256([]byte("oidc"))
	if err = os.Mkdir(filepath.Join(directory, fmt.Sprintf("%x.state.pending", hash)), 0700); err != nil {
		t.Fatal(err)
	}
	response := oidcUnitAuthorize(t, f, cookie)
	if response.Code != http.StatusServiceUnavailable || response.Header().Get("Location") != "" || response.Header().Get("Set-Cookie") != "" {
		t.Fatal("failed durable commit published authority")
	}
}

func TestOIDCPersistentSessionRevocation(t *testing.T) {
	for _, method := range []string{"logout", "clear"} {
		for _, fail := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/fail=%t", method, fail), func(t *testing.T) {
				directory := filepath.Join(t.TempDir(), "state")
				storage, err := state.Open(&state.Config{Directory: directory})
				if err != nil {
					t.Fatal(err)
				}
				defer func() { _ = storage.Close() }()
				record, err := storage.OpenRecord("oidc", "binding")
				if err != nil {
					t.Fatal(err)
				}
				f := newProviderFixture(t)
				if err = f.provider.ConfigurePersistentState(record); err != nil {
					t.Fatal(err)
				}
				cookie := responseCookie(t, f.login(t), f.provider.sessionCookie)
				_ = oidcUnitCode(t, oidcUnitAuthorize(t, f, cookie))
				if fail {
					_ = storage.Close()
				}
				r := httptest.NewRequest("POST", f.config.Issuer+"/logout", nil)
				r.AddCookie(cookie)
				w := httptest.NewRecorder()
				if method == "logout" {
					err = f.provider.LogoutWithError(w, r)
				} else {
					err = f.provider.ClearSessionWithError(w, r)
				}
				if fail {
					if err == nil || w.Header().Get("Set-Cookie") != "" {
						t.Fatal("failed revocation acknowledged success")
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				f.provider.Close()
				if err = storage.Close(); err != nil {
					t.Fatal(err)
				}
				storage, err = state.Open(&state.Config{Directory: directory})
				if err != nil {
					t.Fatal(err)
				}
				record, err = storage.OpenRecord("oidc", "binding")
				if err != nil {
					t.Fatal(err)
				}
				f.provider, err = NewProvider(f.config, f.verifier, Options{})
				if err != nil {
					t.Fatal(err)
				}
				defer f.provider.Close()
				if err = f.provider.ConfigurePersistentState(record); err != nil {
					t.Fatal(err)
				}
				if oidcUnitAuthorize(t, f, cookie).Code != 303 {
					t.Fatal("revoked browser session survived restart")
				}
			})
		}
	}
}
