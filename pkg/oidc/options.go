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
	"crypto"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/greenpau/go-authcrunch/pkg/authn/cookie"
)

// Options supplies application integration settings to NewProvider.
// Cookie names default to the portal cookie factory's AUTHP names. The host must
// keep them distinct from its other cookies, including at overlapping mounts.
type Options struct {
	SessionCookieName string `json:"-" xml:"-" yaml:"-"`
	RequestCookieName string `json:"-" xml:"-" yaml:"-"`
	// LoginURL defaults to <issuer>/login?fresh=1. A custom URL must be canonical,
	// on the issuer origin, and inside its mount so interaction cookies reach it.
	LoginURL string `json:"-" xml:"-" yaml:"-"`
	// ExcludedSigningKeys prevents ID-token signing keys from also being trusted
	// for other credentials, such as the embedding application's access tokens.
	ExcludedSigningKeys []crypto.PublicKey `json:"-" xml:"-" yaml:"-"`
}

// NewProvider validates and snapshots configuration, loads dedicated signing keys,
// and creates a provider. Config must be enabled and verifier must be non-nil.
// It does not register routes or start a login UI; mount the returned http.Handler
// and complete authentication at Options.LoginURL using CompleteLogin.
func NewProvider(config *Config, verifier IdentityVerifier, options Options) (*Provider, error) {
	if config == nil || !config.Enabled {
		return nil, fmt.Errorf("oidc provider requires enabled configuration")
	}
	if verifier == nil {
		return nil, fmt.Errorf("oidc provider requires an identity verifier")
	}
	encoded, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	o := &Provider{verifier: verifier, clients: make(map[string]*ClientConfig), sessions: make(map[[32]byte]*oidcSession), pending: make(map[[32]byte]*oidcAuthorization), grants: make(map[[32]byte]*oidcGrant), access: make(map[[32]byte]*oidcGrant), now: time.Now}
	if err := json.Unmarshal(encoded, &o.config); err != nil {
		return nil, err
	}
	if err := o.config.Validate(); err != nil {
		return nil, err
	}
	issuer, _ := url.Parse(o.config.Issuer)
	o.origin, o.mount = issuer.Scheme+"://"+issuer.Host, issuer.Path
	defaults := cookie.NewConfig()
	o.sessionCookie, o.requestCookie = options.SessionCookieName, options.RequestCookieName
	if o.sessionCookie == "" {
		o.sessionCookie = defaults.OIDCSessionIDCookieName
	}
	if o.requestCookie == "" {
		o.requestCookie = defaults.OIDCRequestIDCookieName
	}
	if o.sessionCookie == o.requestCookie {
		return nil, fmt.Errorf("oidc session and request cookies must have distinct names")
	}
	for _, name := range []string{o.sessionCookie, o.requestCookie} {
		if err := (&http.Cookie{Name: name}).Valid(); err != nil {
			return nil, fmt.Errorf("invalid oidc cookie name: %w", err)
		}
		if strings.HasPrefix(name, "__Host-") && o.mount != "" {
			return nil, fmt.Errorf("__Host- oidc cookies require a root issuer path")
		}
	}
	o.loginURL = options.LoginURL
	if o.loginURL == "" {
		o.loginURL = o.config.Issuer + "/login?fresh=1"
	}
	login, err := url.Parse(o.loginURL)
	if err != nil || login.Scheme+"://"+login.Host != o.origin || login.User != nil || login.Opaque != "" || login.Fragment != "" || login.RawPath != "" || path.Clean(login.Path) != login.Path || strings.ContainsAny(o.loginURL, "\\#\r\n\t ") || (login.Path != o.mount && !strings.HasPrefix(login.Path, o.mount+"/")) {
		return nil, fmt.Errorf("oidc login URL must be canonical and within the issuer origin and mount")
	}
	if _, err := url.ParseQuery(login.RawQuery); err != nil {
		return nil, fmt.Errorf("invalid oidc login URL query")
	}
	if o.keys, err = loadSigningKeys(o.config.SigningKeyFiles, options.ExcludedSigningKeys); err != nil {
		return nil, err
	}
	if o.consentTemplate, err = template.New("oidc-consent").Parse(oidcConsentTemplate); err != nil {
		return nil, err
	}
	if o.formPostTemplate, err = template.New("oidc-form-post").Parse(oidcFormPostTemplate); err != nil {
		return nil, err
	}
	for _, c := range o.config.Clients {
		o.clients[c.ClientID] = c
	}
	return o, nil
}

// SupportsRealm reports whether a realm participates in this provider.
func (o *Provider) SupportsRealm(realm string) bool {
	return slices.Contains(o.config.Realms, realm)
}
