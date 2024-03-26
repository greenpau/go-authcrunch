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
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/authn/enums/role"
	"github.com/greenpau/go-authcrunch/pkg/authn/ui"
	"github.com/greenpau/go-authcrunch/pkg/requests"
	"github.com/greenpau/go-authcrunch/pkg/user"
	"go.uber.org/zap"
)

func (p *Portal) handleHTTPApps(ctx context.Context, w http.ResponseWriter, r *http.Request, rr *requests.Request, usr *user.User, appName string) error {
	p.disableClientCache(w)
	p.injectRedirectURL(ctx, w, r, rr)
	if usr == nil && !strings.HasSuffix(r.URL.Path, appName+"/manifest.json") {
		p.logger.Debug("app asset download is unauthorized", zap.String("app_name", appName), zap.String("app_file_url_path", r.URL.Path))
		return p.handleHTTPError(ctx, w, r, rr, http.StatusUnauthorized)
	}

	if err := p.authorizedRole(usr, []role.Kind{role.Admin, role.User}, rr.Response.Authenticated); err != nil {
		if !strings.HasSuffix(r.URL.Path, appName+"/manifest.json") {
			p.logger.Debug("app asset download is forbidden", zap.String("app_name", appName), zap.String("app_file_url_path", r.URL.Path))
			return p.handleHTTPError(ctx, w, r, rr, http.StatusForbidden)
		}
	}

	var assetPath string
	switch {
	case appName == "profile":
		assetPath = strings.TrimPrefix(r.URL.Path, rr.Upstream.BasePath)
		if !strings.HasPrefix(assetPath, "profile/") {
			assetPath = appName + "/" + assetPath
		}
	default:
		p.logger.Debug("asset download for unsupported app", zap.String("app_name", appName), zap.String("app_file_url_path", r.URL.Path))
		return p.handleHTTPRenderError(ctx, w, r, rr, fmt.Errorf("file not found"))
	}

	p.logRequest(appName+" app assets", r, rr)
	asset, err := ui.AppAssets.GetAsset(assetPath)
	if err != nil {
		if strings.HasSuffix(assetPath, "/") || strings.Count(assetPath, "/") >= 3 || strings.HasSuffix(assetPath, "/new") {
			asset, err = ui.AppAssets.GetAsset(appName + "/")
			if err != nil {
				p.logger.Debug("app asset download not found", zap.String("app_name", appName), zap.String("app_file_url_path", r.URL.Path), zap.String("asset_path", assetPath))
				return p.handleHTTPError(ctx, w, r, rr, http.StatusNotFound)
			}
		} else {
			p.logger.Debug("app asset download not found", zap.String("app_name", appName), zap.String("app_file_url_path", r.URL.Path), zap.String("asset_path", assetPath))
			return p.handleHTTPError(ctx, w, r, rr, http.StatusNotFound)
		}
	}

	w.Header().Set("Content-Type", asset.ContentType)
	w.Header().Set("Etag", asset.Checksum)
	w.Header().Set("Cache-Control", "max-age=7200")
	if match := r.Header.Get("If-None-Match"); match != "" {
		if strings.Contains(match, asset.Checksum) {
			w.WriteHeader(http.StatusNotModified)
			return nil
		}
	}
	w.WriteHeader(http.StatusOK)
	io.WriteString(w, asset.Content)
	return nil
}
