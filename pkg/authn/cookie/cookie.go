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
)

// Config represents a common set of configuration settings
// applicable to the cookies issued by authn.Authenticator.
type Config struct {
	Domains            map[string]*DomainConfig `json:"domains,omitempty" xml:"domains,omitempty" yaml:"domains,omitempty"`
	Path               string                   `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	Lifetime           int                      `json:"lifetime,omitempty" xml:"lifetime,omitempty" yaml:"lifetime,omitempty"`
	Insecure           bool                     `json:"insecure,omitempty" xml:"insecure,omitempty" yaml:"insecure,omitempty"`
	SameSite           string                   `json:"same_site,omitempty" xml:"same_site,omitempty" yaml:"same_site,omitempty"`
	StripDomainEnabled bool                     `json:"strip_domain_enabled,omitempty" xml:"strip_domain_enabled,omitempty" yaml:"strip_domain_enabled,omitempty"`
}

// DomainConfig represents a common set of configuration settings
// applicable to the cookies issued by authn.Authenticator.
type DomainConfig struct {
	Seq                int    `json:"seq,omitempty" xml:"seq,omitempty" yaml:"seq,omitempty"`
	Domain             string `json:"domain,omitempty" xml:"domain,omitempty" yaml:"domain,omitempty"`
	Path               string `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	Lifetime           int    `json:"lifetime,omitempty" xml:"lifetime,omitempty" yaml:"lifetime,omitempty"`
	Insecure           bool   `json:"insecure,omitempty" xml:"insecure,omitempty" yaml:"insecure,omitempty"`
	SameSite           string `json:"same_site,omitempty" xml:"same_site,omitempty" yaml:"same_site,omitempty"`
	StripDomainEnabled bool   `json:"strip_domain_enabled,omitempty" xml:"strip_domain_enabled,omitempty" yaml:"strip_domain_enabled,omitempty"`
}

// Factory holds configuration and associated finctions
// for the cookies issued by authn.Authenticator.
type Factory struct {
	config    *Config
	domains   []string
	Referer   string `json:"referer,omitempty" xml:"referer,omitempty" yaml:"referer,omitempty"`
	SessionID string `json:"session_id,omitempty" xml:"session_id,omitempty" yaml:"session_id,omitempty"`
	SandboxID string `json:"sandbox_id,omitempty" xml:"sandbox_id,omitempty" yaml:"sandbox_id,omitempty"`
}

// NewFactory returns an instance of cookie factory.
func NewFactory(c *Config) (*Factory, error) {
	f := &Factory{}
	if c == nil {
		f.config = &Config{}
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
	f.Referer = "AUTHP_REDIRECT_URL"
	f.SessionID = "AUTHP_SESSION_ID"
	f.SandboxID = "AUTHP_SANDBOX_ID"
	switch strings.ToLower(f.config.SameSite) {
	case "":
	case "lax", "strict", "none":
		f.config.SameSite = strings.Title(f.config.SameSite)
	default:
		return nil, fmt.Errorf("the SameSite cookie attribute %q is invalid", f.config.SameSite)
	}

	return f, nil
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
func (f *Factory) GetIdentityTokenCookie(k, v string) string {
	var sb strings.Builder
	sb.WriteString(k + "=" + v + ";")
	sb.WriteString(" Path=/;")
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
	sb.WriteString(fmt.Sprintf("%s=%s;", f.SessionID, s))
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
	sb.WriteString(f.SessionID)
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
			if strings.Contains(h, k) {
				candidate = f.config.Domains[k]
			}
		}
		if candidate != nil {
			// Partial match between the provided hostname and the config domain.
			return candidate
		}
	}

	c := &DomainConfig{}

	if strings.Count(h, ".") == 1 {
		c.Domain = string(h)
	} else {
		i = strings.IndexByte(h, '.')
		c.Domain = string(h[i+1:])
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
