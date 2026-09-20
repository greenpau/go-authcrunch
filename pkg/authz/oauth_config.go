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

package authz

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strings"
)

const (
	oauthCallbackSuffix = "/authorization-code-callback"
	oauthLogoutSuffix   = "/logout"
	oauthLoginLifetime  = 300
)

var oauthPolicyName = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

// OAuthAuthorizationConfig selects direct OAuth login for an authorization
// policy. Sessions are opaque, local to this gatekeeper, and lost on reload.
// No portal, identity database, or signing key is required. This mode accepts
// only its own session cookie, not upstream tokens or ordinary portal JWTs.
type OAuthAuthorizationConfig struct {
	IdentityProvider string `json:"identity_provider,omitempty" xml:"identity_provider,omitempty" yaml:"identity_provider,omitempty"`
	// PublicOrigin pins the external HTTPS origin. When omitted, the host must
	// route only trusted Host values and supply a TLS request. Forwarded headers
	// never select the origin. Set this explicitly behind TLS termination.
	PublicOrigin      string `json:"public_origin,omitempty" xml:"public_origin,omitempty" yaml:"public_origin,omitempty"`
	BasePath          string `json:"base_path,omitempty" xml:"base_path,omitempty" yaml:"base_path,omitempty"`
	SessionCookieName string `json:"session_cookie_name,omitempty" xml:"session_cookie_name,omitempty" yaml:"session_cookie_name,omitempty"`
	LoginCookieName   string `json:"login_cookie_name,omitempty" xml:"login_cookie_name,omitempty" yaml:"login_cookie_name,omitempty"`
	SessionLifetime   int    `json:"session_lifetime,omitempty" xml:"session_lifetime,omitempty" yaml:"session_lifetime,omitempty"`
	MaxSessions       int    `json:"max_sessions,omitempty" xml:"max_sessions,omitempty" yaml:"max_sessions,omitempty"`
	MaxPendingLogins  int    `json:"max_pending_logins,omitempty" xml:"max_pending_logins,omitempty" yaml:"max_pending_logins,omitempty"`
}

// Validate normalizes direct OAuth settings for a named policy without IO.
func (c *OAuthAuthorizationConfig) Validate(policyName string) error {
	if c == nil {
		return fmt.Errorf("OAuth authorization config is nil")
	}
	if !oauthPolicyName.MatchString(policyName) {
		return fmt.Errorf("OAuth policy name must contain 1-128 letters, digits, underscores or hyphens")
	}
	if strings.TrimSpace(c.IdentityProvider) == "" || strings.ContainsAny(c.IdentityProvider, "\r\n") {
		return fmt.Errorf("OAuth identity provider is required")
	}
	if c.PublicOrigin != "" {
		u, err := url.Parse(c.PublicOrigin)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || strings.ContainsAny(c.PublicOrigin, "\\\r\n\t ?#") {
			return fmt.Errorf("OAuth public origin must be an HTTPS origin without credentials, path, query or fragment")
		}
		c.PublicOrigin = "https://" + u.Host
	}
	if c.BasePath == "" {
		c.BasePath = "/_authcrunch/oauth2/" + policyName
	}
	if !strings.HasPrefix(c.BasePath, "/") || c.BasePath == "/" || path.Clean(c.BasePath) != c.BasePath || strings.ContainsAny(c.BasePath, "%?#\\\r\n\t ") || strings.HasPrefix(c.BasePath, "//") || (&url.URL{Path: c.BasePath}).EscapedPath() != c.BasePath {
		return fmt.Errorf("OAuth base path must be a canonical absolute URL path")
	}
	if c.SessionCookieName == "" {
		c.SessionCookieName = "AUTHZ_" + policyName + "_SESSION"
	}
	if c.LoginCookieName == "" {
		c.LoginCookieName = "AUTHZ_" + policyName + "_LOGIN"
	}
	for _, name := range []string{c.SessionCookieName, c.LoginCookieName} {
		if err := (&http.Cookie{Name: name, Value: "valid", Path: "/", Secure: true, HttpOnly: true}).Valid(); err != nil {
			return fmt.Errorf("invalid OAuth cookie name")
		}
	}
	if c.SessionCookieName == c.LoginCookieName {
		return fmt.Errorf("OAuth cookie names must be distinct")
	}
	if c.SessionLifetime == 0 {
		c.SessionLifetime = 900
	}
	if c.SessionLifetime < 1 || c.SessionLifetime > 86400 {
		return fmt.Errorf("OAuth session lifetime must be between 1 and 86400 seconds")
	}
	if c.MaxSessions == 0 {
		c.MaxSessions = 10000
	}
	if c.MaxPendingLogins == 0 {
		c.MaxPendingLogins = 1024
	}
	if c.MaxSessions < 1 || c.MaxSessions > 65536 || c.MaxPendingLogins < 1 || c.MaxPendingLogins > 65536 {
		return fmt.Errorf("OAuth capacities must be between 1 and 65536")
	}
	return nil
}

// CallbackPath is the exact GET authorization-code callback the host must route
// through this policy, even when the protected application has a path matcher.
func (c *OAuthAuthorizationConfig) CallbackPath() string { return c.BasePath + oauthCallbackSuffix }

// LogoutPath is a same-origin POST endpoint that revokes the local session.
func (c *OAuthAuthorizationConfig) LogoutPath() string { return c.BasePath + oauthLogoutSuffix }

// ConfigureOAuth snapshots validated direct OAuth settings without changing
// other policy settings. A nil config disables direct OAuth authentication.
func (cfg *PolicyConfig) ConfigureOAuth(c *OAuthAuthorizationConfig) error {
	if c == nil {
		cfg.OAuth = nil
		cfg.validated = false
		return nil
	}
	candidate := *c
	if err := candidate.Validate(cfg.Name); err != nil {
		return err
	}
	cfg.OAuth = &candidate
	cfg.validated = false
	return nil
}
