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

package cookie

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"golang.org/x/net/publicsuffix"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
)

// Factory holds configuration and associated finctions
// for the cookies issued by authn.Authenticator.
type Factory struct {
	config                  *Config
	domains                 []string
	CookieNamePrefix        string `json:"cookie_name_prefix,omitempty" xml:"cookie_name_prefix,omitempty" yaml:"cookie_name_prefix,omitempty"`
	RefererCookieName       string `json:"referer_cookie_name,omitempty" xml:"referer_cookie_name,omitempty" yaml:"referer_cookie_name,omitempty"`
	SessionIDCookieName     string `json:"session_id_cookie_name,omitempty" xml:"session_id_cookie_name,omitempty" yaml:"session_id_cookie_name,omitempty"`
	SandboxIDCookieName     string `json:"sandbox_id_cookie_name,omitempty" xml:"sandbox_id_cookie_name,omitempty" yaml:"sandbox_id_cookie_name,omitempty"`
	IdentityTokenCookieName string `json:"identity_token_cookie_name,omitempty" xml:"identity_token_cookie_name,omitempty" yaml:"identity_token_cookie_name,omitempty"`
	AccessTokenCookieName   string `json:"access_token_cookie_name,omitempty" xml:"access_token_cookie_name,omitempty" yaml:"access_token_cookie_name,omitempty"`
	RefreshTokenCookieName  string `json:"refresh_token_cookie_name,omitempty" xml:"refresh_token_cookie_name,omitempty" yaml:"refresh_token_cookie_name,omitempty"`
}

// NewFactory returns an instance of cookie factory.
func NewFactory(c *Config) (*Factory, error) {
	f := &Factory{}
	if c == nil {
		f.config = NewConfig()
	} else {
		f.config = c
	}
	if f.config.Domains != nil {
		domains := []string{}
		domainList := []*DomainConfig{}
		for _, v := range f.config.Domains {
			domainList = append(domainList, v)
		}
		sort.SliceStable(domainList, func(i, j int) bool {
			return domainList[i].Seq < domainList[j].Seq
		})
		for _, v := range domainList {
			domains = append(domains, v.Domain)
		}
		f.domains = domains
	}

	f.config.ApplyDefaults()

	f.CookieNamePrefix = f.config.CookieNamePrefix
	f.RefererCookieName = f.config.RefererCookieName
	f.SessionIDCookieName = f.config.SessionIDCookieName
	f.SandboxIDCookieName = f.config.SandboxIDCookieName
	f.IdentityTokenCookieName = f.config.IdentityTokenCookieName
	f.AccessTokenCookieName = f.config.AccessTokenCookieName
	f.RefreshTokenCookieName = f.config.RefreshTokenCookieName

	switch strings.ToLower(f.config.SameSite) {
	case "":
	case "lax", "strict", "none":
		caser := cases.Title(language.English)
		f.config.SameSite = caser.String(f.config.SameSite)
	default:
		return nil, fmt.Errorf("the SameSite cookie attribute %q is invalid", f.config.SameSite)
	}

	hasOverlaps, duplicate := f.HasCookieNameOverlaps()
	if hasOverlaps {
		return nil, fmt.Errorf("found duplicate cookie names: %v", duplicate)
	}

	return f, nil
}

// HasCookieNameOverlaps checks if any cookie names are identical.
func (f *Factory) HasCookieNameOverlaps() (bool, string) {
	checkMap := map[string]string{
		"RefererCookieName":       f.RefererCookieName,
		"SessionIDCookieName":     f.SessionIDCookieName,
		"SandboxIDCookieName":     f.SandboxIDCookieName,
		"IdentityTokenCookieName": f.IdentityTokenCookieName,
		"AccessTokenCookieName":   f.AccessTokenCookieName,
		"RefreshTokenCookieName":  f.RefreshTokenCookieName,
	}

	// seen stores: [cookie_value] -> field_name
	seen := make(map[string]string)

	for fieldName, cookieValue := range checkMap {
		if cookieValue == "" {
			continue
		}

		if existingField, exists := seen[cookieValue]; exists {
			// Found a mismatch/duplicate!
			return true, fmt.Sprintf(
				"duplicate cookie name %q found in both %q and %q",
				cookieValue,
				existingField,
				fieldName,
			)
		}
		seen[cookieValue] = fieldName
	}

	return false, ""
}

// GetCookie returns raw cookie string from key-value input.
func (f *Factory) GetCookie(h, k, v string) string {
	var sb strings.Builder
	sb.WriteString(k + "=" + v + ";")

	entry := f.evalHost(h)
	if entry != nil && entry.Domain != "" {
		sb.WriteString(fmt.Sprintf(" Domain=%s;", entry.Domain))
	}

	switch {
	case entry != nil && entry.Path != "":
		sb.WriteString(fmt.Sprintf(" Path=%s;", entry.Path))
	case f.config.Path != "":
		sb.WriteString(fmt.Sprintf(" Path=%s;", f.config.Path))
	default:
		sb.WriteString(" Path=/;")
	}

	switch {
	case entry != nil && entry.Lifetime != 0:
		sb.WriteString(fmt.Sprintf(" Max-Age=%d;", entry.Lifetime))
	case f.config.Lifetime != 0:
		sb.WriteString(fmt.Sprintf(" Max-Age=%d;", f.config.Lifetime))
	}

	switch {
	case entry != nil && entry.SameSite != "":
		sb.WriteString(fmt.Sprintf(" SameSite=%s;", entry.SameSite))
	case f.config.SameSite != "":
		sb.WriteString(fmt.Sprintf(" SameSite=%s;", f.config.SameSite))
	}

	switch {
	case entry != nil && !entry.Insecure:
		sb.WriteString(" Secure; HttpOnly;")
	case !f.config.Insecure:
		sb.WriteString(" Secure; HttpOnly;")
	}

	return sb.String()
}

// GetIdentityTokenCookie returns raw identity token cookie string from key-value input.
func (f *Factory) GetIdentityTokenCookie(baseURL, k, v string) string {
	var sb strings.Builder
	sb.WriteString(k + "=" + v + ";")
	sb.WriteString(" Path=" + baseURL + "whoami;")
	if f.config.Lifetime != 0 {
		sb.WriteString(fmt.Sprintf(" Max-Age=%d;", f.config.Lifetime))
	}
	if f.config.SameSite != "" {
		sb.WriteString(fmt.Sprintf(" SameSite=%s;", f.config.SameSite))
	}
	if !f.config.Insecure {
		sb.WriteString(" Secure; HttpOnly;")
	}
	return sb.String()
}

// GetRefreshTokenCookie returns raw refresh token cookie string from key-value input.
func (f *Factory) GetRefreshTokenCookie(baseURL, v string) string {
	var sb strings.Builder
	sb.WriteString(f.RefreshTokenCookieName + "=" + v + ";")
	sb.WriteString(" Path=" + baseURL + "api/refresh_token;")
	if f.config.Lifetime != 0 {
		sb.WriteString(fmt.Sprintf(" Max-Age=%d;", f.config.Lifetime))
	}
	if f.config.SameSite != "" {
		sb.WriteString(fmt.Sprintf(" SameSite=%s;", f.config.SameSite))
	}
	if !f.config.Insecure {
		sb.WriteString(" Secure; HttpOnly;")
	}
	return sb.String()
}

// GetSessionCookie return cookie holding session information
func (f *Factory) GetSessionCookie(h, s string) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s=%s;", f.SessionIDCookieName, s))
	entry := f.evalHost(h)
	if entry != nil && entry.Domain != "" {
		sb.WriteString(fmt.Sprintf(" Domain=%s;", entry.Domain))
	}

	sb.WriteString(" Path=/;")

	switch {
	case entry != nil && !entry.Insecure:
		sb.WriteString(" Secure; HttpOnly;")
	case !f.config.Insecure:
		sb.WriteString(" Secure; HttpOnly;")
	}

	return sb.String()
}

// GetDeleteCookie returns raw cookie with attributes for delete action.
func (f *Factory) GetDeleteCookie(h, s string) string {
	var sb strings.Builder
	sb.WriteString(s)
	sb.WriteString("=delete;")
	entry := f.evalHost(h)
	if entry != nil && entry.Domain != "" {
		sb.WriteString(fmt.Sprintf(" Domain=%s;", entry.Domain))
	}

	switch {
	case entry != nil && entry.Path != "":
		sb.WriteString(fmt.Sprintf(" Path=%s;", entry.Path))
	case f.config.Path != "":
		sb.WriteString(fmt.Sprintf(" Path=%s;", f.config.Path))
	default:
		sb.WriteString(" Path=/;")
	}

	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}

// GetDeleteSessionCookie returns raw cookie with attributes for delete action
// for session id cookie.
func (f *Factory) GetDeleteSessionCookie(h string) string {
	var sb strings.Builder
	sb.WriteString(f.SessionIDCookieName)
	sb.WriteString("=delete;")
	entry := f.evalHost(h)
	if entry != nil && entry.Domain != "" {
		sb.WriteString(fmt.Sprintf(" Domain=%s;", entry.Domain))
	}
	sb.WriteString(" Path=/;")
	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}

// GetDeleteIdentityTokenCookie returns raw identity token cookie with attributes for delete action.
func (f *Factory) GetDeleteIdentityTokenCookie(s string) string {
	var sb strings.Builder
	sb.WriteString(s)
	sb.WriteString("=delete;")
	sb.WriteString(" Path=/;")
	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}

// GetDeleteRefreshTokenCookie returns raw refresh token cookie with attributes for delete action.
func (f *Factory) GetDeleteRefreshTokenCookie() string {
	var sb strings.Builder
	sb.WriteString(f.RefreshTokenCookieName)
	sb.WriteString("=delete;")
	sb.WriteString(" Path=/;")
	sb.WriteString(" Expires=Thu, 01 Jan 1970 00:00:00 GMT;")
	return sb.String()
}

func (f *Factory) evalHost(h string) *DomainConfig {
	i := strings.IndexByte(h, ':')
	if i > 0 {
		if strings.Count(h, ":") > 1 {
			// IPv6 address found.
			return nil
		}
		// There is a host:port separator.
		h = h[:i]
	}
	if addr := net.ParseIP(h); addr != nil {
		// This is IP address.
		return nil
	}

	if strings.Count(h, ".") == 0 {
		// This is hostname without domain.
		return nil
	}

	if len(f.domains) > 0 {
		var candidate *DomainConfig
		for _, k := range f.domains {
			if h == k {
				return f.config.Domains[k]
			}
			if strings.HasSuffix(h, "."+k) {
				candidate = f.config.Domains[k]
			}
		}
		if candidate != nil {
			// Partial match between the provided hostname and the config domain.
			return candidate
		}
	}

	c := &DomainConfig{}

	if f.config.GuessDomainEnabled {
		if strings.Count(h, ".") == 1 {
			c.Domain = string(h)
		} else {
			i = strings.IndexByte(h, '.')
			c.Domain = string(h[i+1:])
		}

		// Validate extracted domain is not a public suffix.
		// Browsers reject cookies set to PSL entries (co.uk, fly.dev, etc.).
		// If invalid, omit domain attribute so the browser defaults to exact FQDN.
		if _, err := publicsuffix.EffectiveTLDPlusOne(c.Domain); err != nil {
			c.Domain = ""
		}
	}

	if f.config.StripDomainEnabled {
		c.Domain = ""
	}

	c.Path = f.config.Path
	c.Lifetime = f.config.Lifetime
	c.Insecure = f.config.Insecure
	c.SameSite = f.config.SameSite
	return c
}
