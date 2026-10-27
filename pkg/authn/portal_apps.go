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
	"net/http"
	"strings"

	"github.com/greenpau/go-authcrunch/pkg/requests"
)

// portalAppRoute finds an app only before another namespace has claimed the path.
// Realm names and API resource IDs never become browser application routes.
func portalAppRoute(path string) (string, int) {
	index := 0
	for segment := range strings.SplitSeq(strings.TrimPrefix(path, "/"), "/") {
		if strings.HasPrefix(segment, "favicon") {
			return "", -1
		}
		switch segment {
		case "profile", "operator", "documents":
			return segment, index
		case "connected-accounts", ".well-known", "api", "apps", "assets", "barcode", "basic", "beacon", "cross-device", "favicon", "forgot", "login", "logout", "oauth2", "oidc", "portal", "provider", "qrcode", "recover", "register", "saml", "sandbox", "whoami":
			return "", -1
		}
		index += len(segment) + 1
	}
	return "", -1
}

func portalAppName(r *http.Request, rr *requests.Request) string {
	relative, ok := strings.CutPrefix(r.URL.Path, rr.Upstream.BasePath)
	if !ok {
		return ""
	}
	name, _, _ := strings.Cut(relative, "/")
	switch name {
	case "profile", "operator", "documents":
		return name
	}
	return ""
}

func (p *Portal) portalAppEnabled(name string) bool {
	switch name {
	case "profile":
		return true // The profile shell retains its independently gated API.
	case "operator":
		return p.config.API != nil && p.config.API.AdminEnabled
	case "documents":
		return p.config.API != nil && p.config.API.DocumentsEnabled && p.documents != nil
	}
	return false
}
