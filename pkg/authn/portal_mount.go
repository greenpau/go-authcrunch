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
	"net/http"
	"net/url"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/portalpath"
	"github.com/greenpau/go-authcrunch/pkg/requests"
)

type portalMountContextKey struct{}

func declaredPortalMount(r *http.Request) string {
	mount, _ := r.Context().Value(portalMountContextKey{}).(string)
	return mount
}

// ServeHTTPAt serves one explicitly declared portal mount. It requires a
// canonical mount accepted by portalpath.Validate, matching enabled portal
// refresh/OP/Documents bindings and cookie restrictions. Invalid declarations return 500;
// outside or encoded mount aliases return 404, before any protocol dispatch or
// cookie issuance. The original request and shared portal are never modified.
// ServeHTTP remains the legacy entry point with inferred mount semantics.
func (p *Portal) ServeHTTPAt(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, basePath string) error {
	reject := func(status int) error {
		rr.Response.Authenticated = false
		rr.Response.Code = status
		p.disableClientCache(w)
		http.Error(w, http.StatusText(status), status)
		return nil
	}
	if p.managedRefreshUnavailable() {
		return p.rejectManagedRefresh(w, rr)
	}
	if portalpath.Validate(basePath) != nil {
		return reject(http.StatusInternalServerError)
	}
	if !portalMountContains(basePath, r.URL) {
		return reject(http.StatusNotFound)
	}
	if !p.portalMountAgrees(basePath) {
		return reject(http.StatusInternalServerError)
	}
	r = r.WithContext(context.WithValue(r.Context(), portalMountContextKey{}, basePath))
	return p.serveHTTP(ctx, w, r, rr)
}

func (p *Portal) portalMountAgrees(basePath string) bool {
	if p.cookie.ValidatePortalPath(basePath) != nil {
		return false
	}
	if c := p.config.RefreshTokens; c != nil && c.Enabled && c.BasePath != basePath {
		return false
	}
	if p.config.API != nil && p.config.API.DocumentsEnabled {
		// Compare the private configuration that bound the opened store.
		if p.documentsConfig == nil || p.documentsConfig.BasePath != basePath {
			return false
		}
	}
	if c := p.config.OIDCProvider; c != nil && c.Enabled {
		issuer, err := url.Parse(c.Issuer)
		if err != nil {
			return false
		}
		mount := issuer.Path
		if mount == "" {
			mount = "/"
		}
		if mount != basePath {
			return false
		}
	}
	return true
}

func portalMountContains(mount string, u *url.URL) bool {
	if u.Opaque != "" {
		return false
	}
	if u.RawPath != "" {
		decoded, err := url.PathUnescape(u.RawPath)
		if err != nil || decoded != u.Path || u.EscapedPath() != u.RawPath {
			return false
		}
	}
	contains := func(base, target string) bool {
		return target == base || strings.HasPrefix(target, strings.TrimSuffix(base, "/")+"/")
	}
	if !contains(mount, u.Path) {
		return false
	}
	escapedMount := (&url.URL{Path: mount}).EscapedPath()
	return contains(escapedMount, u.EscapedPath())
}

func portalSigningJWKSRequest(r *http.Request) bool {
	mount := declaredPortalMount(r)
	if mount == "" {
		return strings.HasSuffix(r.URL.Path, jwksPath)
	}
	endpoint := strings.TrimSuffix(mount, "/") + jwksPath
	return r.URL.Path == endpoint && r.URL.EscapedPath() == (&url.URL{Path: endpoint}).EscapedPath()
}
