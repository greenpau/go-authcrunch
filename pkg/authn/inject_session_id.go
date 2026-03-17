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
	"net/http"
	"net/url"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/util"
	addrutil "github.com/greenpau/go-authcrunch/pkg/util/addr"
)

func (p *Portal) injectSessionID(_ context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) {
	if cookie, err := r.Cookie(p.cookie.SessionID); err == nil {
		v, err := url.Parse(cookie.Value)
		if err == nil && v.String() != "" {
			rr.Upstream.SessionID = util.SanitizeSessionID(v.String())
			return
		}
	}
	rr.Upstream.SessionID = util.GetRandomStringFromRange(36, 46)
	w.Header().Add("Set-Cookie", p.cookie.GetSessionCookie(addrutil.GetSourceHost(r), rr.Upstream.SessionID))
}
