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

// injectSAMLSessionID supplies the provider with a short-lived browser binding
// distinct from the ordinary portal session. Initiation always rotates it, so a
// parent-domain cookie cannot choose the value bound into new SAML state.
func (p *Portal) injectSAMLSessionID(w http.ResponseWriter, r *http.Request, rr *requests.Request) {
	if r.Method != http.MethodPost {
		rr.Upstream.SessionID = util.GetRandomStringFromRange(36, 46)
		w.Header().Add("Set-Cookie", p.cookie.GetSAMLSessionIDCookie(rr.Upstream.SessionID))
		return
	}
	cookies := r.CookiesNamed(p.cookie.SAMLSessionIDCookieName)
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
