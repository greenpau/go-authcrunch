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
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

type matchStrategy int

const (
	matchUnknown matchStrategy = 0
	matchExact   matchStrategy = 1
	matchPartial matchStrategy = 2
	matchPrefix  matchStrategy = 3
	matchSuffix  matchStrategy = 4
	matchRegex   matchStrategy = 5
)

// RedirectURIMatchConfig holds the configuration for a redirect URI.
type RedirectURIMatchConfig struct {
	PathMatchType   string `json:"path_match_type,omitempty" xml:"path_match_type,omitempty" yaml:"path_match_type,omitempty"`
	Path            string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	DomainMatchType string `json:"domain_match_type,omitempty" xml:"domain_match_type,omitempty" yaml:"domain_match_type,omitempty"`
	Domain          string `json:"domain,omitempty" xml:"domain,omitempty" yaml:"domain,omitempty"`

	pathMatch   matchStrategy
	pathRegex   *regexp.Regexp
	domainMatch matchStrategy
	domainRegex *regexp.Regexp
}

// Validate validates RedirectURIMatchConfig.
func (c *RedirectURIMatchConfig) Validate() error {
	switch c.PathMatchType {
	case "exact":
		c.pathMatch = matchExact
	case "partial":
		c.pathMatch = matchPartial
	case "prefix":
		c.pathMatch = matchPrefix
	case "suffix":
		c.pathMatch = matchSuffix
	case "regex":
		c.pathMatch = matchRegex
	case "":
		return fmt.Errorf("undefined path match type")
	default:
		return fmt.Errorf("invalid %q path match type", c.PathMatchType)
	}

	switch c.DomainMatchType {
	case "exact":
		c.domainMatch = matchExact
	case "partial":
		c.domainMatch = matchPartial
	case "prefix":
		c.domainMatch = matchPrefix
	case "suffix":
		c.domainMatch = matchSuffix
	case "regex":
		c.domainMatch = matchRegex
	case "":
		return fmt.Errorf("undefined domain name match type")
	default:
		return fmt.Errorf("invalid %q domain name match type", c.DomainMatchType)
	}

	c.Path = strings.TrimSpace(c.Path)
	c.Domain = strings.TrimSpace(c.Domain)

	if c.Path == "" {
		return fmt.Errorf("undefined path")
	}

	if c.Domain == "" {
		return fmt.Errorf("undefined domain")
	}

	if c.pathRegex == nil {
		r, err := regexp.Compile(c.Path)
		if err != nil {
			return err
		}
		c.pathRegex = r
	}

	if c.domainRegex == nil {
		r, err := regexp.Compile(c.Domain)
		if err != nil {
			return err
		}
		c.domainRegex = r
	}

	return nil
}

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
	if !domainMatched {
		return false
	}

	return false
}
