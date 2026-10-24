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
	"errors"
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn/cache"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

const maxBrowserSandboxes = 16

var errBrowserSandboxCapacity = errors.New("browser sandbox capacity exhausted")

func sandboxAdmissionStatus(err error) int {
	switch {
	case errors.Is(err, errBrowserSandboxCapacity):
		return http.StatusTooManyRequests
	case errors.Is(err, cache.ErrSandboxCapacity):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

// addBrowserSandbox shares admission and issuance across local and connected
// logins. Visible cookies bound one browser's sequential starts; the cache owns
// the atomic server bound, including simultaneous starts and native clients.
func (p *Portal) addBrowserSandbox(w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User) error {
	names := make(map[string]bool)
	prefix := p.cookie.SandboxIDCookieName + "_"
	for _, c := range r.Cookies() {
		if !strings.HasPrefix(c.Name, prefix) {
			continue
		}
		if p.cookie.SandboxIDCookieNameForSession(strings.TrimPrefix(c.Name, prefix)) == c.Name {
			names[c.Name] = true
		}
	}
	if len(names) >= maxBrowserSandboxes {
		return errBrowserSandboxCapacity
	}
	proof := p.cookie.GetSandboxIDCookieForSession(rr.Upstream.BasePath, usr.Authenticator.TempSecret, usr.Authenticator.TempSessionID)
	if proof == "" {
		return errors.New("invalid browser sandbox id")
	}
	if err := p.sandboxes.Add(usr.Authenticator.TempSessionID, usr); err != nil {
		return err
	}
	// Keep the original transport for existing clients. Browsers select the exact
	// independent proof first, so replacing the base cookie does not replace A.
	w.Header().Add("Set-Cookie", p.cookie.GetSandboxIDCookie(rr.Upstream.BasePath, usr.Authenticator.TempSecret))
	w.Header().Add("Set-Cookie", proof)
	return nil
}

// exactSandboxCookie counts raw occurrences as well as parsed cookies. An
// invalid value that net/http omits must not hide a present exact-flow cookie
// and accidentally enable legacy fallback. Cookie values are never logged.
func exactSandboxCookie(r *http.Request, name string) (value string, present, valid bool) {
	count := 0
	for _, header := range r.Header.Values("Cookie") {
		for part := range strings.SplitSeq(header, ";") {
			key, _, _ := strings.Cut(strings.TrimSpace(part), "=")
			if strings.TrimSpace(key) == name {
				count++
			}
		}
	}
	if count == 0 {
		return "", false, false
	}
	cookies := r.CookiesNamed(name)
	if count != 1 || len(cookies) != 1 || cookies[0].Value == "" {
		return "", true, false
	}
	return cookies[0].Value, true, true
}

func (p *Portal) browserSandboxSecret(r *http.Request, id string) string {
	name := p.cookie.SandboxIDCookieNameForSession(id)
	if name == "" {
		return ""
	}
	if value, present, valid := exactSandboxCookie(r, name); present {
		if valid {
			return value
		}
		return ""
	}
	value, _, valid := exactSandboxCookie(r, p.cookie.SandboxIDCookieName)
	if !valid {
		return ""
	}
	return value
}

// Call only after the selected sandbox's proof was authenticated and its state
// consumed. Put this tombstone before token delivery's rollback snapshot so a
// later issuance failure still removes the already consumed browser proof.
func (p *Portal) deleteBrowserSandboxCookie(w http.ResponseWriter, basePath, id string) {
	if raw := p.cookie.GetDeleteSandboxIDCookieForSession(basePath, id); raw != "" {
		w.Header().Add("Set-Cookie", raw)
	}
}
