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

import "fmt"

// DefaultCookieNamePrefix is the default prefix for cookie names.
const DefaultCookieNamePrefix string = "AUTHP"

// DefaultSessionIDCookieName is the default session id cookie name.
const DefaultSessionIDCookieName string = "SESSION_ID"

// DefaultRefererCookieName is the default redirect url cookie name.
const DefaultRefererCookieName string = "REDIRECT_URL"

// DefaultSandboxIDCookieName is the default sandbox id cookie name.
const DefaultSandboxIDCookieName string = "SANDBOX_ID"

// DefaultIdentityTokenCookieName is the default identity token cookie name.
const DefaultIdentityTokenCookieName string = "ID_TOKEN"

// DefaultAccessTokenCookieName is the default access token cookie name.
const DefaultAccessTokenCookieName string = "ACCESS_TOKEN"

// DefaultRefreshTokenCookieName is the default access token cookie name.
const DefaultRefreshTokenCookieName string = "REFRESH_TOKEN"

// Config represents a common set of configuration settings
// applicable to the cookies issued by authn.Authenticator.
type Config struct {
	Domains                 map[string]*DomainConfig `json:"domains,omitempty" xml:"domains,omitempty" yaml:"domains,omitempty"`
	Path                    string                   `json:"path,omitempty" xml:"path,omitempty" yaml:"path,omitempty"`
	Lifetime                int                      `json:"lifetime,omitempty" xml:"lifetime,omitempty" yaml:"lifetime,omitempty"`
	Insecure                bool                     `json:"insecure,omitempty" xml:"insecure,omitempty" yaml:"insecure,omitempty"`
	SameSite                string                   `json:"same_site,omitempty" xml:"same_site,omitempty" yaml:"same_site,omitempty"`
	StripDomainEnabled      bool                     `json:"strip_domain_enabled,omitempty" xml:"strip_domain_enabled,omitempty" yaml:"strip_domain_enabled,omitempty"`
	GuessDomainEnabled      bool                     `json:"guess_domain_enabled,omitempty" xml:"guess_domain_enabled,omitempty" yaml:"guess_domain_enabled,omitempty"`
	SessionIDCookieName     string                   `json:"session_id_cookie_name,omitempty" xml:"session_id_cookie_name,omitempty" yaml:"session_id_cookie_name,omitempty"`
	RefererCookieName       string                   `json:"referer_cookie_name,omitempty" xml:"referer_cookie_name,omitempty" yaml:"referer_cookie_name,omitempty"`
	SandboxIDCookieName     string                   `json:"sandbox_id_cookie_name,omitempty" xml:"sandbox_id_cookie_name,omitempty" yaml:"sandbox_id_cookie_name,omitempty"`
	IdentityTokenCookieName string                   `json:"identity_token_cookie_name,omitempty" xml:"identity_token_cookie_name,omitempty" yaml:"identity_token_cookie_name,omitempty"`
	AccessTokenCookieName   string                   `json:"access_token_cookie_name,omitempty" xml:"access_token_cookie_name,omitempty" yaml:"access_token_cookie_name,omitempty"`
	RefreshTokenCookieName  string                   `json:"refresh_token_cookie_name,omitempty" xml:"refresh_token_cookie_name,omitempty" yaml:"refresh_token_cookie_name,omitempty"`
	CookieNamePrefix        string                   `json:"cookie_name_prefix,omitempty" xml:"cookie_name_prefix,omitempty" yaml:"cookie_name_prefix,omitempty"`
}

// NewConfig returns an instance of Config.
func NewConfig() *Config {
	return &Config{
		CookieNamePrefix:        DefaultCookieNamePrefix,
		RefererCookieName:       fmt.Sprintf("%s_%s", DefaultCookieNamePrefix, DefaultRefererCookieName),
		SessionIDCookieName:     fmt.Sprintf("%s_%s", DefaultCookieNamePrefix, DefaultSessionIDCookieName),
		SandboxIDCookieName:     fmt.Sprintf("%s_%s", DefaultCookieNamePrefix, DefaultSandboxIDCookieName),
		IdentityTokenCookieName: fmt.Sprintf("%s_%s", DefaultCookieNamePrefix, DefaultIdentityTokenCookieName),
		AccessTokenCookieName:   fmt.Sprintf("%s_%s", DefaultCookieNamePrefix, DefaultAccessTokenCookieName),
		RefreshTokenCookieName:  fmt.Sprintf("%s_%s", DefaultCookieNamePrefix, DefaultRefreshTokenCookieName),
	}
}

// ApplyDefaults applies default values to the configuration.
func (c *Config) ApplyDefaults() {
	if c.CookieNamePrefix == "" {
		c.CookieNamePrefix = DefaultCookieNamePrefix
	}
	if c.RefererCookieName == "" {
		c.RefererCookieName = fmt.Sprintf("%s_%s", c.CookieNamePrefix, DefaultRefererCookieName)
	}
	if c.SessionIDCookieName == "" {
		c.SessionIDCookieName = fmt.Sprintf("%s_%s", c.CookieNamePrefix, DefaultSessionIDCookieName)
	}
	if c.SandboxIDCookieName == "" {
		c.SandboxIDCookieName = fmt.Sprintf("%s_%s", c.CookieNamePrefix, DefaultSandboxIDCookieName)
	}
	if c.IdentityTokenCookieName == "" {
		c.IdentityTokenCookieName = fmt.Sprintf("%s_%s", c.CookieNamePrefix, DefaultIdentityTokenCookieName)
	}
	if c.AccessTokenCookieName == "" {
		c.AccessTokenCookieName = fmt.Sprintf("%s_%s", c.CookieNamePrefix, DefaultAccessTokenCookieName)
	}
	if c.RefreshTokenCookieName == "" {
		c.RefreshTokenCookieName = fmt.Sprintf("%s_%s", c.CookieNamePrefix, DefaultRefreshTokenCookieName)
	}
}
