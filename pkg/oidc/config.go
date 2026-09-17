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

package oidc

import (
	"fmt"
	"net/url"
	"path"
	"slices"
	"strings"
)

const (
	oidcDefaultSessionLifetime = 28800
	oidcDefaultTokenLifetime   = 300
	oidcDefaultCapacity        = 10000
	oidcRequestLifetime        = 600
	oidcCodeLifetime           = 60
	oidcMaxRequestBytes        = 16384
)

// Config enables an OpenID Provider for explicitly selected identity realms.
// Issuer includes the provider mount, without a trailing slash. State is bounded
// and process-local; restarting the provider requires new authorization.
type Config struct {
	Enabled bool     `json:"enabled,omitempty" xml:"enabled,omitempty" yaml:"enabled,omitempty"`
	Issuer  string   `json:"issuer,omitempty" xml:"issuer,omitempty" yaml:"issuer,omitempty"`
	Realms  []string `json:"realms,omitempty" xml:"realms,omitempty" yaml:"realms,omitempty"`
	// SigningKeyFiles contains dedicated RSA private PEM files. The first signs;
	// all are published for verification during planned rotation. These keys
	// must not also be used to sign the embedding application's access tokens.
	SigningKeyFiles        []string                `json:"signing_key_files,omitempty" xml:"signing_key_files,omitempty" yaml:"signing_key_files,omitempty"`
	Clients                []*ClientConfig         `json:"clients,omitempty" xml:"clients,omitempty" yaml:"clients,omitempty"`
	SessionLifetimeSeconds int                     `json:"session_lifetime_seconds,omitempty" xml:"session_lifetime_seconds,omitempty" yaml:"session_lifetime_seconds,omitempty"`
	TokenLifetimeSeconds   int                     `json:"token_lifetime_seconds,omitempty" xml:"token_lifetime_seconds,omitempty" yaml:"token_lifetime_seconds,omitempty"`
	MaxSessions            int                     `json:"max_sessions,omitempty" xml:"max_sessions,omitempty" yaml:"max_sessions,omitempty"`
	MaxPendingRequests     int                     `json:"max_pending_requests,omitempty" xml:"max_pending_requests,omitempty" yaml:"max_pending_requests,omitempty"`
	RefreshLifetimeSeconds int                     `json:"refresh_lifetime_seconds,omitempty" xml:"refresh_lifetime_seconds,omitempty" yaml:"refresh_lifetime_seconds,omitempty"`
	MaxRefreshTokens       int                     `json:"max_refresh_tokens,omitempty" xml:"max_refresh_tokens,omitempty" yaml:"max_refresh_tokens,omitempty"`
	AuthenticationContexts []AuthenticationContext `json:"authentication_contexts,omitempty" xml:"authentication_contexts,omitempty" yaml:"authentication_contexts,omitempty"`
	MaxGrants              int                     `json:"max_grants,omitempty" xml:"max_grants,omitempty" yaml:"max_grants,omitempty"`
}

// ClientConfig registers a relying party. Public clients use "none" and
// must use S256 PKCE. Confidential clients default to client_secret_basic.
// Public HTTP callbacks at literal 127.0.0.1 or [::1] identify supported native
// loopback clients. Authorization may vary only their valid TCP port; every
// other URI byte must match. Code redemption requires the actual authorized URI.
// HTTPS and confidential-client redirects remain exact. Private-use schemes are
// not supported. SkipConsent preapproves registered scopes and permitted individual
// claims; an explicit prompt=consent (required for offline_access) still interacts.
type ClientConfig struct {
	ClientID                string             `json:"client_id,omitempty" xml:"client_id,omitempty" yaml:"client_id,omitempty"`
	ClientName              string             `json:"client_name,omitempty" xml:"client_name,omitempty" yaml:"client_name,omitempty"`
	ClientSecret            string             `json:"client_secret,omitempty" xml:"client_secret,omitempty" yaml:"client_secret,omitempty"`
	TokenEndpointAuthMethod string             `json:"token_endpoint_auth_method,omitempty" xml:"token_endpoint_auth_method,omitempty" yaml:"token_endpoint_auth_method,omitempty"`
	RedirectURIs            []string           `json:"redirect_uris,omitempty" xml:"redirect_uris,omitempty" yaml:"redirect_uris,omitempty"`
	Scopes                  []string           `json:"scopes,omitempty" xml:"scopes,omitempty" yaml:"scopes,omitempty"`
	RequestObjectSigningAlg string             `json:"request_object_signing_alg,omitempty" xml:"request_object_signing_alg,omitempty" yaml:"request_object_signing_alg,omitempty"`
	RequestObjectKeys       []RequestObjectKey `json:"request_object_keys,omitempty" xml:"request_object_keys,omitempty" yaml:"request_object_keys,omitempty"`
	RequirePKCE             bool               `json:"require_pkce,omitempty" xml:"require_pkce,omitempty" yaml:"require_pkce,omitempty"`
	SkipConsent             bool               `json:"skip_consent,omitempty" xml:"skip_consent,omitempty" yaml:"skip_consent,omitempty"`
}

// Validate normalizes OIDC configuration and rejects ambiguous trust boundaries.
func (c *Config) Validate() error {
	if c == nil || !c.Enabled {
		return nil
	}
	u, err := url.Parse(c.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.RawPath != "" || u.Host != strings.ToLower(u.Host) || strings.ContainsAny(c.Issuer, "\\%?#;\r\n\t ") || (u.Path != "" && (path.Clean(u.Path) != u.Path || strings.HasSuffix(u.Path, "/"))) {
		return fmt.Errorf("oidc issuer must be a canonical HTTPS URL without query, fragment, or trailing slash")
	}
	if len(c.Realms) == 0 || !oidcUniqueStrings(c.Realms) {
		return fmt.Errorf("oidc requires distinct realms")
	}
	if len(c.SigningKeyFiles) == 0 || !oidcUniqueStrings(c.SigningKeyFiles) {
		return fmt.Errorf("oidc requires dedicated RSA signing_key_files")
	}
	if len(c.Clients) == 0 {
		return fmt.Errorf("oidc requires registered clients")
	}
	seen := make(map[string]bool)
	for _, client := range c.Clients {
		if client == nil {
			return fmt.Errorf("oidc client is nil")
		}
		if err := client.Validate(); err != nil {
			return err
		}
		if seen[client.ClientID] {
			return fmt.Errorf("duplicate oidc client_id")
		}
		seen[client.ClientID] = true
	}
	for _, setting := range []struct {
		value             *int
		fallback, maximum int
	}{
		{&c.SessionLifetimeSeconds, oidcDefaultSessionLifetime, 86400},
		{&c.TokenLifetimeSeconds, oidcDefaultTokenLifetime, 3600},
		{&c.RefreshLifetimeSeconds, oidcDefaultSessionLifetime, 86400},
		{&c.MaxRefreshTokens, oidcDefaultCapacity, 1000000},
		{&c.MaxSessions, oidcDefaultCapacity, 1000000},
		{&c.MaxPendingRequests, 1024, 100000},
		{&c.MaxGrants, oidcDefaultCapacity, 1000000},
	} {
		if *setting.value == 0 {
			*setting.value = setting.fallback
		}
		if *setting.value < 1 || *setting.value > setting.maximum {
			return fmt.Errorf("oidc lifetime or capacity outside supported bounds")
		}
	}
	return validateAuthenticationContexts(c.AuthenticationContexts)
}

// Validate normalizes client registration and checks redirect and credential policy.
func (c *ClientConfig) Validate() error {
	if c == nil {
		return fmt.Errorf("oidc client is nil")
	}
	if c.ClientID == "" || len(c.ClientID) > 256 || strings.TrimSpace(c.ClientID) != c.ClientID || strings.ContainsAny(c.ClientID, "\r\n\t") {
		return fmt.Errorf("invalid oidc client_id")
	}
	if c.ClientName == "" {
		c.ClientName = c.ClientID
	}
	if len(c.ClientName) > 256 {
		return fmt.Errorf("oidc client_name is too long")
	}
	if c.TokenEndpointAuthMethod == "" {
		c.TokenEndpointAuthMethod = "client_secret_basic"
	}
	switch c.TokenEndpointAuthMethod {
	case "none":
		if c.ClientSecret != "" {
			return fmt.Errorf("public oidc clients cannot have a secret")
		}
		c.RequirePKCE = true
	case "client_secret_basic", "client_secret_post":
		if len(c.ClientSecret) < 32 || len(c.ClientSecret) > 1024 {
			return fmt.Errorf("oidc client secrets require 32 to 1024 bytes")
		}
	default:
		return fmt.Errorf("unsupported oidc token endpoint authentication method")
	}
	if len(c.RedirectURIs) == 0 || !oidcUniqueStrings(c.RedirectURIs) {
		return fmt.Errorf("oidc requires distinct redirect_uris")
	}
	for _, raw := range c.RedirectURIs {
		u, err := parseOIDCRedirectURI(raw)
		if err != nil {
			return err
		}
		loopback := c.TokenEndpointAuthMethod == "none" && loopbackRedirectHost(u) != ""
		if u.Scheme != "https" && !loopback {
			return fmt.Errorf("oidc redirect_uri requires HTTPS or a public client's literal loopback address")
		}
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "email"}
	}
	if !oidcUniqueStrings(c.Scopes) || !slices.Contains(c.Scopes, "openid") {
		return fmt.Errorf("oidc scopes must be distinct and include openid")
	}
	for _, scope := range c.Scopes {
		if !slices.Contains([]string{"openid", "profile", "email", "address", "phone", "offline_access"}, scope) {
			return fmt.Errorf("unsupported oidc scope")
		}
	}
	return c.validateRequestObjectKeys()
}

func oidcUniqueStrings(values []string) bool {
	seen := make(map[string]bool, len(values))
	for _, value := range values {
		if value == "" || strings.TrimSpace(value) != value || seen[value] {
			return false
		}
		seen[value] = true
	}
	return true
}
