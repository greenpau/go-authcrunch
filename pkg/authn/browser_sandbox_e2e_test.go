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

package authn_test

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/greenpau/go-authcrunch/internal/tests"
	"github.com/greenpau/go-authcrunch/pkg/identity"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// Both tabs submit their username before either completes its password. All
// requests use the same ordinary browser cookie jar; no cookie is restored,
// replaced or manually injected to recover an earlier tab's proof.
func TestE2EBrowserSandboxIndependentTabs(t *testing.T) {
	f := newLoginRedirectFixture(t)
	destinations := []string{f.server.URL + "/_test/allowed/first?view=one%26two", f.server.URL + "/_test/allowed/second"}
	sandboxes := make([]string, len(destinations))
	for i, destination := range destinations {
		login := f.server.URL + "/login?redirect_url=" + url.QueryEscape(destination)
		page := f.request(t, http.MethodGet, login, nil)
		if page.StatusCode != http.StatusOK {
			t.Fatalf("tab %d login page returned HTTP %d", i+1, page.StatusCode)
		}
		start := f.request(t, http.MethodPost, login, url.Values{"username": {"alice"}, "realm": {"local"}})
		location, err := start.Location()
		if start.StatusCode != http.StatusSeeOther || err != nil || location.Scheme+"://"+location.Host != f.server.URL || !strings.HasPrefix(location.Path, "/sandbox/") {
			t.Fatalf("tab %d did not enter its mounted checkpoint", i+1)
		}
		if start.TLS == nil || len(start.TLS.VerifiedChains) == 0 {
			t.Fatal("browser checkpoint was not reached through verified TLS")
		}
		sandboxes[i] = location.String()
	}
	if sandboxes[0] == sandboxes[1] {
		t.Fatal("two browser starts reused the same checkpoint")
	}
	for _, i := range []int{1, 0} {
		password := f.request(t, http.MethodPost, sandboxes[i], url.Values{"secret": {tests.TestPwd1}})
		if password.StatusCode != http.StatusSeeOther {
			t.Fatalf("tab %d password checkpoint returned HTTP %d after both starts", i+1, password.StatusCode)
		}
		completed := f.request(t, http.MethodGet, sandboxes[i], nil)
		if got := f.follow(t, completed); got != destinations[i] {
			t.Fatalf("tab %d did not retain its own login destination", i+1)
		}
	}
}

// A fresh page's submitted intent survives another tab authenticating while it
// was open. Reloading the fresh page would clear shared access and hide the bug.
func TestE2EBrowserSandboxFreshWaitingTab(t *testing.T) {
	f := newLoginRedirectFixture(t)
	destination := f.server.URL + "/_test/allowed/fresh"
	target := f.server.URL + "/login?fresh=1&redirect_url=" + url.QueryEscape(destination)
	if response := f.request(t, http.MethodGet, target, nil); response.StatusCode != http.StatusOK {
		t.Fatal("fresh page was not rendered")
	}
	// Tab B binds an explicitly empty destination, independently of A's
	// compatibility return cookie. Keep the real shared jar throughout.
	other := f.request(t, http.MethodPost, f.server.URL+"/login?redirect_url=", url.Values{"username": {"alice"}, "realm": {"local"}})
	otherLocation, err := other.Location()
	if other.StatusCode != http.StatusSeeOther || err != nil {
		t.Fatal("other tab did not start its checkpoint")
	}
	if response := f.request(t, http.MethodPost, otherLocation.String(), url.Values{"secret": {tests.TestPwd1}}); response.StatusCode != http.StatusSeeOther {
		t.Fatal("other tab did not pass its password")
	}
	otherFinal, err := url.Parse(f.follow(t, f.request(t, http.MethodGet, otherLocation.String(), nil)))
	if err != nil || otherFinal.Path != "/portal" {
		t.Fatal("other tab did not finish its explicitly bound login")
	}
	start := f.request(t, http.MethodPost, target, url.Values{"username": {"alice"}, "realm": {"local"}})
	location, err := start.Location()
	if start.StatusCode != http.StatusSeeOther || err != nil || !strings.HasPrefix(location.Path, "/sandbox/") {
		t.Fatalf("waiting fresh POST did not begin an interactive checkpoint: HTTP%d", start.StatusCode)
	}
	if response := f.request(t, http.MethodPost, location.String(), url.Values{"secret": {tests.TestPwd1}}); response.StatusCode != http.StatusSeeOther {
		t.Fatal("fresh password checkpoint did not complete")
	}
	if got := f.follow(t, f.request(t, http.MethodGet, location.String(), nil)); got != destination {
		t.Fatal("fresh flow lost its own destination")
	}
}

func TestE2EBrowserSandboxExactProofAndCleanup(t *testing.T) {
	f := newLoginRedirectFixture(t)
	const base = "AUTHP_SANDBOX_ID"
	start := func() (*url.URL, *http.Cookie) {
		t.Helper()
		response := f.request(t, http.MethodPost, f.server.URL+"/login", url.Values{"username": {"alice"}, "realm": {"local"}})
		location, err := response.Location()
		if response.StatusCode != http.StatusSeeOther || err != nil {
			t.Fatal("proof fixture start failed")
		}
		for _, c := range response.Cookies() {
			if strings.HasPrefix(c.Name, base+"_") {
				return location, c
			}
		}
		t.Fatal("independent browser proof missing")
		return nil, nil
	}
	a, proofA := start()
	b, proofB := start()
	rawRequest := func(target string, headers []string) *http.Response {
		t.Helper()
		client := *f.client
		client.Jar = nil
		r, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
		if err != nil {
			t.Fatal("construct proof request")
		}
		r.Header.Set("Accept", "text/html")
		for _, h := range headers {
			r.Header.Add("Cookie", h)
		}
		response, err := client.Do(r)
		if err != nil {
			t.Fatal("proof request failed")
		}
		defer response.Body.Close()
		if _, err := io.Copy(io.Discard, io.LimitReader(response.Body, 1<<20)); err != nil {
			t.Fatal("drain proof response")
		}
		return response
	}
	for _, tc := range []struct {
		name    string
		headers []string
	}{
		{"missing", nil},
		{"other flow only", []string{proofB.Name + "=" + proofB.Value}},
		{"wrong exact valid legacy", []string{proofA.Name + "=incorrect; " + base + "=" + proofA.Value}},
		{"empty exact valid legacy", []string{proofA.Name + "=; " + base + "=" + proofA.Value}},
		{"duplicate exact valid legacy", []string{proofA.Name + "=" + proofA.Value, proofA.Name + "=" + proofA.Value + "; " + base + "=" + proofA.Value}},
		{"malformed exact valid legacy", []string{proofA.Name + "=bad\\value; " + base + "=" + proofA.Value}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := rawRequest(a.String(), tc.headers)
			if response.StatusCode != http.StatusUnauthorized {
				t.Fatalf("invalid proof HTTP%d", response.StatusCode)
			}
			for _, c := range response.Cookies() {
				if c.Name == proofA.Name || c.Name == proofB.Name {
					t.Fatal("unauthenticated request changed a flow proof")
				}
			}
		})
	}
	// Legacy-only callers retain their prior protocol when exact is absent.
	if response := rawRequest(a.String(), []string{base + "=" + proofA.Value}); response.StatusCode != http.StatusOK {
		t.Fatal("absent exact proof disabled legacy transport")
	}
	terminated := f.request(t, http.MethodGet, a.String()+"/terminate", nil)
	if terminated.StatusCode != http.StatusSeeOther {
		t.Fatal("authenticated termination failed")
	}
	deleted := false
	for _, c := range terminated.Cookies() {
		if c.Name == proofA.Name && c.MaxAge < 0 {
			deleted = true
		}
		if c.Name == proofB.Name {
			t.Fatal("termination deleted competing flow")
		}
	}
	if !deleted {
		t.Fatal("termination left selected proof cookie")
	}
	if response := rawRequest(a.String(), []string{proofA.Name + "=" + proofA.Value}); response.StatusCode != http.StatusUnauthorized {
		t.Fatal("terminated original proof replayed")
	}
	if response := f.request(t, http.MethodPost, b.String(), url.Values{"secret": {tests.TestPwd1}}); response.StatusCode != http.StatusSeeOther {
		t.Fatal("termination destroyed competing password flow")
	}
	completed := f.request(t, http.MethodGet, b.String(), nil)
	if completed.StatusCode != http.StatusSeeOther && completed.StatusCode != http.StatusFound {
		t.Fatalf("completion HTTP%d", completed.StatusCode)
	}
	deleted = false
	for _, c := range completed.Cookies() {
		if c.Name == proofB.Name && c.MaxAge < 0 {
			deleted = true
		}
	}
	if !deleted {
		t.Fatal("completion left selected proof cookie")
	}
	if response := rawRequest(b.String(), []string{proofB.Name + "=" + proofB.Value}); response.StatusCode != http.StatusUnauthorized {
		t.Fatal("completed original proof replayed")
	}
}

func TestE2EBrowserSandboxIndependentMFA(t *testing.T) {
	secrets := []string{"first-factor-0123456789abcdef012345", "second-factor-0123456789abcdef01234"}
	f := newLoginRedirectFixture(t, func(db *identity.Database) {
		if err := db.AddUser(&requests.Request{User: requests.User{Username: "bob", Email: "bob@example.test", Password: tests.TestPwd1Hash(t), Roles: []string{"authp/user"}}}); err != nil {
			t.Fatal("seed second identity")
		}
		for i, name := range []string{"alice", "bob"} {
			if err := db.AddMfaToken(&requests.Request{User: requests.User{Username: name, Email: name + "@example.test"}, MfaToken: requests.MfaToken{Type: "totp", Comment: "independent browser factor", Secret: secrets[i], Algorithm: "sha1", Digits: 6, Period: 30, SkipVerification: true}}); err != nil {
				t.Fatal("seed independent factor")
			}
		}
	})
	destinations := []string{f.server.URL + "/_test/allowed/mfa-a", f.server.URL + "/_test/allowed/mfa-b"}
	checkpoints := make([]string, 2)
	for i, name := range []string{"alice", "bob"} {
		response := f.request(t, http.MethodPost, f.server.URL+"/login?redirect_url="+url.QueryEscape(destinations[i]), url.Values{"username": {name}, "realm": {"local"}})
		location, err := response.Location()
		if response.StatusCode != http.StatusSeeOther || err != nil {
			t.Fatal("MFA start failed")
		}
		checkpoints[i] = location.String()
		password := f.request(t, http.MethodPost, checkpoints[i], url.Values{"secret": {tests.TestPwd1}})
		if password.StatusCode != http.StatusSeeOther {
			t.Fatal("MFA password checkpoint failed")
		}
		factor := f.request(t, http.MethodGet, checkpoints[i], nil)
		if factor.StatusCode != http.StatusOK {
			t.Fatal("factor page missing")
		}
	}
	for _, i := range []int{1, 0} {
		mac := hmac.New(sha1.New, []byte(secrets[i]))
		var counter [8]byte
		binary.BigEndian.PutUint64(counter[:], uint64(time.Now().Unix()/30))
		_, _ = mac.Write(counter[:])
		digest := mac.Sum(nil)
		offset := digest[len(digest)-1] & 15
		passcode := fmt.Sprintf("%06d", (binary.BigEndian.Uint32(digest[offset:offset+4])&0x7fffffff)%1000000)
		response := f.request(t, http.MethodPost, checkpoints[i]+"/mfa-app-auth", url.Values{"passcode": {passcode}})
		if response.StatusCode != http.StatusSeeOther {
			t.Fatalf("independent factor%d HTTP%d", i+1, response.StatusCode)
		}
		if got := f.follow(t, f.request(t, http.MethodGet, checkpoints[i], nil)); got != destinations[i] {
			t.Fatal("MFA flow lost its own bound destination")
		}
	}
}
