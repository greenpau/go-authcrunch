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

// DefaultCookieNamePrefix is the default prefix for cookie names.
const DefaultCookieNamePrefix string = "AUTHP"

// DefaultSessionIDCookieName is the session id suffix, combined with the prefix.
const DefaultSessionIDCookieName string = "SESSION_ID"

// DefaultRefererCookieName is the redirect url suffix, combined with the prefix.
const DefaultRefererCookieName string = "REDIRECT_URL"

// DefaultSandboxIDCookieName is the sandbox id suffix, combined with the prefix.
const DefaultSandboxIDCookieName string = "SANDBOX_ID"

// DefaultIdentityTokenCookieName is the identity token suffix, combined with the prefix.
const DefaultIdentityTokenCookieName string = "ID_TOKEN"

// DefaultAccessTokenCookieName is the access token suffix, combined with the prefix.
const DefaultAccessTokenCookieName string = "ACCESS_TOKEN"

// DefaultRefreshTokenCookieName is the refresh token suffix, combined with the prefix.
const DefaultRefreshTokenCookieName string = "REFRESH_TOKEN"

// DefaultOIDCSessionIDCookieName is the OIDC session suffix, combined with the prefix.
const DefaultOIDCSessionIDCookieName string = "OIDC_SESSION_ID"

// DefaultOIDCRequestIDCookieName is the OIDC request suffix, combined with the prefix.
const DefaultOIDCRequestIDCookieName string = "OIDC_REQUEST_ID"

// DefaultSAMLSessionIDCookieName is the SAML browser-binding suffix, combined with the prefix.
const DefaultSAMLSessionIDCookieName string = "SAML_SESSION_ID"

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
	OIDCSessionIDCookieName string                   `json:"oidc_session_id_cookie_name,omitempty" xml:"oidc_session_id_cookie_name,omitempty" yaml:"oidc_session_id_cookie_name,omitempty"`
	OIDCRequestIDCookieName string                   `json:"oidc_request_id_cookie_name,omitempty" xml:"oidc_request_id_cookie_name,omitempty" yaml:"oidc_request_id_cookie_name,omitempty"`
	SAMLSessionIDCookieName string                   `json:"saml_session_id_cookie_name,omitempty" xml:"saml_session_id_cookie_name,omitempty" yaml:"saml_session_id_cookie_name,omitempty"`
	CookieNamePrefix        string                   `json:"cookie_name_prefix,omitempty" xml:"cookie_name_prefix,omitempty" yaml:"cookie_name_prefix,omitempty"`
}

// NewConfig returns cookie configuration with the common AUTHP names.
// Use SetCookieNamePrefix to change the prefix after defaults are initialized.
func NewConfig() *Config {
	c := &Config{}
	c.ApplyDefaults()
	return c
}

// ApplyDefaults fills omitted names without replacing explicit names.
// Use SetCookieNamePrefix instead of assigning CookieNamePrefix after calling
// NewConfig or ApplyDefaults; initialized names are otherwise explicit values.
func (c *Config) ApplyDefaults() {
	if c.CookieNamePrefix == "" {
		c.CookieNamePrefix = DefaultCookieNamePrefix
	}
	for _, entry := range c.names() {
		if *entry.value == "" {
			*entry.value = c.CookieNamePrefix + "_" + entry.suffix
		}
	}
}
