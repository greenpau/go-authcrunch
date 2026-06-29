// Copyright 2024 Paul Greenberg greenpau@outlook.com
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

package redirects

import (
	"net/url"
	"strings"
)

// Match matches HTTP URL to the redirect URI match configuration.
func Match(u *url.URL, cfgs []*RedirectURIMatchConfig) bool {
	for _, cfg := range cfgs {
		if cfg == nil {
			continue
		}
		if matchRedirectURIPath(u.Path, cfg) && matchRedirectURIDomain(u.Host, cfg) {
			return true
		}
	}
	return false
}

func matchRedirectURIPath(requestPath string, cfg *RedirectURIMatchConfig) bool {
	switch cfg.pathMatch {
	case matchExact:
		return cfg.Path == requestPath
	case matchPartial:
		return strings.Contains(requestPath, cfg.Path)
	case matchPrefix:
		return strings.HasPrefix(requestPath, cfg.Path)
	case matchSuffix:
		return strings.HasSuffix(requestPath, cfg.Path)
	case matchRegex:
		return cfg.pathRegex.MatchString(requestPath)
	}
	return false
}

func matchRedirectURIDomain(requestHost string, cfg *RedirectURIMatchConfig) bool {
	switch cfg.domainMatch {
	case matchExact:
		return cfg.Domain == requestHost
	case matchPartial:
		return strings.Contains(requestHost, cfg.Domain)
	case matchPrefix:
		return strings.HasPrefix(requestHost, cfg.Domain)
	case matchSuffix:
		return strings.HasSuffix(requestHost, cfg.Domain)
	case matchRegex:
		return cfg.domainRegex.MatchString(requestHost)
	}
	return false
}
