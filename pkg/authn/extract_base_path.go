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

func extractBasePathPrefix(path string) string {
	if path == "" || path == "/" {
		return "/"
	}
	basePath := path
	if path[0] == '/' {
		basePath = path[1:]
	}
	i := strings.IndexByte(basePath, '/')
	if i == -1 {
		return "/" + basePath + "/"
	}
	return "/" + basePath[:i] + "/"
}

func extractBaseURLPath(_ context.Context, r *http.Request, rr *requests.Request, s string) {
	baseURL, basePath := util.GetBaseURL(r, s)
	rr.Upstream.BaseURL = baseURL
	if basePath == "/" {
		rr.Upstream.BasePath = basePath
		return
	}
	if strings.HasSuffix(basePath, "/") {
		rr.Upstream.BasePath = basePath
		return
	}

	rr.Upstream.BasePath = basePath + "/"
}

func extractBasePath(ctx context.Context, r *http.Request, rr *requests.Request) {
	switch {
	case r.URL.Path == "/":
		rr.Upstream.BaseURL = util.GetCurrentBaseURL(r)
		rr.Upstream.BasePath = "/"
	case r.URL.Path == "/auth":
		rr.Upstream.BaseURL = util.GetCurrentBaseURL(r)
		rr.Upstream.BasePath = "/auth/"
	case strings.Contains(r.URL.Path, "/profile/"):
		extractBaseURLPath(ctx, r, rr, "/profile")
	case strings.HasSuffix(r.URL.Path, "/portal"):
		extractBaseURLPath(ctx, r, rr, "/portal")
	case strings.Contains(r.URL.Path, "/sandbox/"):
		extractBaseURLPath(ctx, r, rr, "/sandbox/")
	case strings.HasSuffix(r.URL.Path, "/recover"), strings.HasSuffix(r.URL.Path, "/forgot"):
		extractBaseURLPath(ctx, r, rr, "/recover,/forgot")
	case strings.HasSuffix(r.URL.Path, "/register"):
		extractBaseURLPath(ctx, r, rr, "/register")
	case strings.HasSuffix(r.URL.Path, "/whoami"):
		extractBaseURLPath(ctx, r, rr, "/whoami")
	case strings.Contains(r.URL.Path, "/saml/"):
		extractBaseURLPath(ctx, r, rr, "/saml/")
	case strings.Contains(r.URL.Path, "/oauth2/"):
		extractBaseURLPath(ctx, r, rr, "/oauth2/")
	case strings.HasSuffix(r.URL.Path, "/basic/login"):
		extractBaseURLPath(ctx, r, rr, "/basic/login")
	case strings.HasSuffix(r.URL.Path, "/logout"):
		extractBaseURLPath(ctx, r, rr, "/logout")
	case strings.Contains(r.URL.Path, "/assets/") || strings.Contains(r.URL.Path, "/favicon"):
		extractBaseURLPath(ctx, r, rr, "/assets/")
	case strings.HasSuffix(r.URL.Path, "/login"):
		extractBaseURLPath(ctx, r, rr, "/login")
	case strings.HasPrefix(r.URL.Path, "/auth/"):
		rr.Upstream.BaseURL = util.GetCurrentBaseURL(r)
		rr.Upstream.BasePath = "/auth/"
	default:
		rr.Upstream.BaseURL = util.GetCurrentBaseURL(r)
		rr.Upstream.BasePath = extractBasePathPrefix(r.URL.Path)
	}
}
