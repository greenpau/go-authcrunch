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
	"bytes"
	"context"
	"html/template"
	"io"
	"net/http"
	"path"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/role"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
)

func (p *Portal) handleHTTPApps(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User, appName string) error {
	p.disableClientCache(w)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if !p.portalAppEnabled(appName) {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusNotFound)
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		return p.handleHTTPError(ctx, w, r, rr, http.StatusMethodNotAllowed)
	}
	assetPath := strings.TrimPrefix(r.URL.Path, rr.Upstream.BasePath)
	appRoot := rr.Upstream.BasePath + appName
	if path.Clean(r.URL.Path) != strings.TrimSuffix(r.URL.Path, "/") ||
		(r.URL.EscapedPath() != appRoot && !strings.HasPrefix(r.URL.EscapedPath(), appRoot+"/")) {
		return p.handleHTTPError(ctx, w, r, rr, http.StatusNotFound)
	}
	// Only the exact manifest is public. No suffix or neighboring path exemption.
	public := assetPath == appName+"/manifest.json"
	if !public {
		if usr == nil {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
		}
		roles := []role.Kind{role.Admin, role.User}
		if appName == "operator" {
			roles = []role.Kind{role.Admin}
		}
		if err := p.authorizedRole(usr, roles, rr.Response.Authenticated); err != nil {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusForbidden)
		}
	}
	if assetPath == appName {
		location := *r.URL
		location.Path += "/"
		w.Header().Set("Location", location.String())
		w.WriteHeader(http.StatusPermanentRedirect)
		return nil
	}
	asset, err := ui.AppAssets.GetAsset(assetPath)
	if err != nil {
		child := strings.TrimPrefix(assetPath, appName+"/")
		// Browser routes may end in dotted account names. File fetches must
		// still fail rather than receiving the SPA as JavaScript or JSON.
		documentRequest := strings.Contains(r.Header.Get("Accept"), "text/html")
		if (path.Ext(child) != "" && !documentRequest) || strings.HasPrefix(child, "assets/") || strings.HasPrefix(child, "i18n/") {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusNotFound)
		}
		asset, err = ui.AppAssets.GetAsset(appName + "/")
		if err != nil {
			return p.handleHTTPError(ctx, w, r, rr, http.StatusNotFound)
		}
	}
	content := asset.Content
	if asset.ContentType == "text/html" {
		// All other assets are mount independent, including CSS font URLs and chunks.
		baseTemplate, err := template.New("application-base").Parse(`<base href="{{.}}" />`)
		if err != nil {
			return p.handleHTTPRenderError(ctx, w, r, rr, err)
		}
		var base bytes.Buffer
		if err := baseTemplate.Execute(&base, appRoot+"/"); err != nil {
			return p.handleHTTPRenderError(ctx, w, r, rr, err)
		}
		content = strings.Replace(content, ui.ApplicationBaseTag, base.String(), 1)
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
		w.Header().Set("X-Frame-Options", "DENY")
	} else {
		etag := `"` + asset.Checksum + `"`
		w.Header().Set("Etag", etag)
		for candidate := range strings.SplitSeq(r.Header.Get("If-None-Match"), ",") {
			candidate = strings.TrimSpace(candidate)
			if candidate == "*" || strings.TrimPrefix(candidate, "W/") == etag {
				w.WriteHeader(http.StatusNotModified)
				return nil
			}
		}
	}
	w.Header().Set("Content-Type", asset.ContentType)
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, content)
	}
	return nil
}
