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

package authclient

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// DefaultAccessTokenName is the fallback key in an AuthCrunch Authorization header.
const DefaultAccessTokenName = "authp_access_token"

// Config contains portal authentication settings, independent of any CLI or file
// layout. Password and TOTPSecret are optional when Options.Prompt supplies them.
// APIKey selects a separate access-only login and replaces Username, Password,
// and TOTPSecret. Realm is required for both authentication methods.
// This type contains secrets and must not be logged.
type Config struct {
	BaseURL          string `json:"base_url,omitempty" xml:"base_url,omitempty" yaml:"base_url,omitempty"`
	Username         string `json:"username,omitempty" xml:"username,omitempty" yaml:"username,omitempty"`
	Realm            string `json:"realm,omitempty" xml:"realm,omitempty" yaml:"realm,omitempty"`
	Password         string `json:"password,omitempty" xml:"password,omitempty" yaml:"password,omitempty"`
	APIKey           string `json:"api_key,omitempty" xml:"api_key,omitempty" yaml:"api_key,omitempty"`
	TOTPSecret       string `json:"totp_secret,omitempty" xml:"totp_secret,omitempty" yaml:"totp_secret,omitempty"`
	TOTPCodeLength   int    `json:"totp_code_length,omitempty" xml:"totp_code_length,omitempty" yaml:"totp_code_length,omitempty"`
	TOTPCodeLifetime int    `json:"totp_code_lifetime,omitempty" xml:"totp_code_lifetime,omitempty" yaml:"totp_code_lifetime,omitempty"`
	AccessTokenName  string `json:"access_token_name,omitempty" xml:"access_token_name,omitempty" yaml:"access_token_name,omitempty"`
}

// Validate normalizes defaults and checks settings without including secrets in
// errors. BaseURL is the portal root (optionally including a path such as /auth),
// without user information, a query, or a fragment. HTTP is supported for local
// deployments; applications should use HTTPS when sending credentials remotely.
func (cfg *Config) Validate() error {
	if cfg == nil {
		return fmt.Errorf("authentication configuration is required")
	}
	u, err := url.Parse(cfg.BaseURL)
	if err != nil || u.Hostname() == "" || (u.Scheme != "https" && u.Scheme != "http") ||
		u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(cfg.BaseURL, "#") {
		return fmt.Errorf("base_url must be an HTTP or HTTPS portal URL without user information, query, or fragment")
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.Realm = strings.TrimSpace(cfg.Realm)
	if cfg.Realm == "" || (cfg.Username == "" && cfg.APIKey == "") {
		return fmt.Errorf("realm and either username or api_key are required")
	}
	if cfg.APIKey != "" && (cfg.Username != "" || cfg.Password != "" || cfg.TOTPSecret != "") {
		return fmt.Errorf("api_key cannot be combined with username, password, or totp_secret")
	}
	if cfg.TOTPCodeLength == 0 {
		cfg.TOTPCodeLength = 6
	}
	if cfg.TOTPCodeLifetime == 0 {
		cfg.TOTPCodeLifetime = 30
	}
	if cfg.TOTPCodeLength < 4 || cfg.TOTPCodeLength > 8 {
		return fmt.Errorf("totp_code_length must be between 4 and 8")
	}
	if cfg.TOTPCodeLifetime < 1 {
		return fmt.Errorf("totp_code_lifetime must be positive")
	}
	if cfg.AccessTokenName == "" {
		cfg.AccessTokenName = DefaultAccessTokenName
	}
	return validateTokenName(cfg.AccessTokenName)
}

func validateTokenName(name string) error {
	if err := (&http.Cookie{Name: name}).Valid(); err != nil {
		return fmt.Errorf("invalid access token name")
	}
	return nil
}
