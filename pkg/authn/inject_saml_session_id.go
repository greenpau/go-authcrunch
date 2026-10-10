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
	"net/http"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/util"
)

// injectSAMLSessionID supplies a fresh secret for each initiation. The cookie
// carrying it is selected by RelayState, so concurrent tabs never replace each
// other's proof. An incoming cookie cannot choose a new transaction's secret.
func (p *Portal) injectSAMLSessionID(w http.ResponseWriter, r *http.Request, rr *requests.Request) {
	if r.Method != http.MethodPost {
		rr.Upstream.SessionID = util.GetRandomStringFromRange(36, 46)
		return
	}
	rr.Upstream.SessionID = ""
	if r.ContentLength < 500 || r.ContentLength > 30000 || r.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 30000)
	if r.ParseForm() != nil || len(r.PostForm["RelayState"]) != 1 {
		return
	}
	name := p.cookie.SAMLSessionIDCookieNameForState(r.PostForm.Get("RelayState"))
	if name == "" {
		return
	}
	cookies := r.CookiesNamed(name)
	if len(cookies) != 1 {
		rr.Upstream.SessionID = ""
		return
	}
	value := util.SanitizeSessionID(cookies[0].Value)
	if value == "" || value != cookies[0].Value {
		rr.Upstream.SessionID = ""
		return
	}
	rr.Upstream.SessionID = value
}
