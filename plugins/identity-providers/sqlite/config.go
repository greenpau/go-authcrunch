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

// Package sqlite authenticates single-use tickets issued by a trusted application.
package sqlite

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/greenpau/go-authcrunch/internal/sqlitedb"
	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
)

// Config binds a private ticket database to a canonical portal and trusted issuer.
type Config struct {
	Name         string `json:"name,omitempty" xml:"name,omitempty" yaml:"name,omitempty"`
	Realm        string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	Path         string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	Timeout      string `json:"timeout,omitempty" xml:"timeout,omitempty" yaml:"timeout,omitempty"`
	PublicOrigin string `json:"public_origin,omitempty" xml:"public_origin,omitempty" yaml:"public_origin,omitempty"`
	BasePath     string `json:"base_path,omitempty" xml:"base_path,omitempty" yaml:"base_path,omitempty"`
	CookieName   string `json:"cookie_name,omitempty" xml:"cookie_name,omitempty" yaml:"cookie_name,omitempty"`
	IssuerURL    string `json:"issuer_url,omitempty" xml:"issuer_url,omitempty" yaml:"issuer_url,omitempty"`
}

func matches(pattern, value string) bool {
	matched, _ := regexp.MatchString(pattern, value)
	return matched
}
func secureURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || !sqlitedb.ValidText(raw, 2048) || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || strings.ToLower(u.Host) != u.Host || strings.Contains(raw, "#") || raw != u.String() {
		return nil, ErrInvalid
	}
	return u, nil
}

// Validate applies defaults without opening files or contacting the issuer.
func (c *Config) Validate() error {
	if c == nil || !sqlitedb.ValidText(c.Name, 128) || !matches(`^[A-Za-z0-9_-]{1,64}$`, c.Realm) {
		return ErrInvalid
	}
	origin, err := secureURL(c.PublicOrigin)
	if err != nil || origin.Path != "" {
		return ErrInvalid
	}
	issuer, err := secureURL(c.IssuerURL)
	if err != nil || issuer.Path == "" || !matches(`^(/[A-Za-z0-9_-]+)+$`, issuer.Path) {
		return ErrInvalid
	}
	if c.BasePath == "" {
		c.BasePath = "/auth"
	}
	if len(c.BasePath) > 512 || (c.BasePath != "/" && !matches(`^(/[A-Za-z0-9_-]+)+$`, c.BasePath)) {
		return ErrInvalid
	}
	for segment := range strings.SplitSeq(c.BasePath, "/") {
		if strings.HasPrefix(segment, "favicon") {
			return ErrInvalid
		}
		switch segment {
		case "provider", "api", "profile", "sandbox", "register", "apps", "barcode", "saml", "oauth2", "basic", "assets", "favicon", "cross-device", "qrcode", "portal":
			return ErrInvalid
		}
	}
	if c.IssuerURL == c.PublicOrigin+strings.TrimSuffix(c.BasePath, "/")+"/provider/"+c.Realm {
		return ErrInvalid
	}
	if c.CookieName == "" {
		c.CookieName = "AUTHP_PROVIDER_SESSION_ID"
	}
	if len(c.CookieName) > 128 || (&http.Cookie{Name: c.CookieName}).Valid() != nil || cookie.ValidatePrefix(c.CookieName, "", strings.TrimSuffix(c.BasePath, "/")+"/provider/"+c.Realm, true) != nil {
		return ErrInvalid
	}
	return sqlitedb.Normalize(&c.Path, &c.Timeout)
}
