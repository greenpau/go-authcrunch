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

// Match matches HTTP URL to the bypass configuration.
func Match(u *url.URL, cfgs []*RedirectURIMatchConfig) bool {
	pathMatched := false
	domainMatched := false

	for _, cfg := range cfgs {
		switch cfg.pathMatch {
		case matchExact:
			if cfg.Path == u.Path {
				pathMatched = true
			}
		case matchPartial:
			if strings.Contains(u.Path, cfg.Path) {
				pathMatched = true
			}
		case matchPrefix:
			if strings.HasPrefix(u.Path, cfg.Path) {
				pathMatched = true
			}
		case matchSuffix:
			if strings.HasSuffix(u.Path, cfg.Path) {
				pathMatched = true
			}
		case matchRegex:
			if cfg.pathRegex.MatchString(u.Path) {
				pathMatched = true
			}
		}
		if pathMatched {
			break
		}
	}
	if !pathMatched {
		return false
	}
	for _, cfg := range cfgs {
		switch cfg.domainMatch {
		case matchExact:
			if cfg.Domain == u.Host {
				domainMatched = true
			}
		case matchPartial:
			if strings.Contains(u.Host, cfg.Domain) {
				domainMatched = true
			}
		case matchPrefix:
			if strings.HasPrefix(u.Host, cfg.Domain) {
				domainMatched = true
			}
		case matchSuffix:
			if strings.HasSuffix(u.Host, cfg.Domain) {
				domainMatched = true
			}
		case matchRegex:
			if cfg.domainRegex.MatchString(u.Host) {
				domainMatched = true
			}
		}
		if domainMatched {
			break
		}
	}
	return domainMatched
}
