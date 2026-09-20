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
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/util"
)

// ServeHTTP is a gateway for the authentication portal.
func (p *Portal) ServeHTTP(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request) (err error) {
	if p.state != nil {
		response := &persistentResponseWriter{ResponseWriter: w, health: p.persistentStateErr}
		defer func() {
			response.finish()
			if response.failed {
				rr.Response.Authenticated = false
				rr.Response.Code = http.StatusServiceUnavailable
				err = nil // The storage failure has already produced its HTTP response.
			}
		}()
		w = response
	}
	if p.closed.Load() || p.persistentStateErr() != nil {
		rr.Response.Authenticated = false
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return nil
	}
	if p.oidc != nil && p.oidc.HandleHTTP(w, r) {
		return nil
	}
	// Browser OIDC login uses the existing portal checkpoints. Reject cross-site
	// credential submission before it can replace the provider's browser session.
	if p.oidc != nil && r.Method == http.MethodPost && (strings.Contains(r.URL.Path, "/login") || strings.Contains(r.URL.Path, "/sandbox/")) && !p.oidc.ValidateLoginRequest(w, r) {
		return nil
	}
	if rr.ID == "" {
		rr.ID = util.GetRequestID(r)
	}
	rr.Logger = p.logger
	rr.Upstream.Request = r
	rr.Upstream.ContentType = util.GetContentType(r)
	rr.Response.Authenticated = false
	if p.config.UI.Title != "" {
		rr.Response.Title = p.config.UI.Title
	}
	rr.Response.RedirectTokenName = p.cookie.RefererCookieName
	if strings.HasSuffix(r.URL.Path, jwksPath) {
		// Public discovery must precede session authorization, API routing,
		// and content negotiation, including at nested portal mounts.
		return p.handleHTTPJWKS(w, r)
	}
	extractBasePath(ctx, r, rr)
	if err := p.cookie.ValidatePortalPath(rr.Upstream.BasePath); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return nil
	}
	switch {
	case strings.Contains(r.URL.Path, "/api/"):
		return p.handleAPI(ctx, w, r, rr)
	case strings.Contains(r.URL.Path, "/qrcode/"):
		return p.handleQRCode(ctx, w, r, rr)
	case strings.Contains(r.URL.RawQuery, "format=json"):
		return p.handleJSON(ctx, w, r, rr)
	}

	switch rr.Upstream.ContentType {
	case "application/json":
		return p.handleJSON(ctx, w, r, rr)
	}

	return p.handleHTTP(ctx, w, r, rr)
}
